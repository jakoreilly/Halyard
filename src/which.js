// Turning an engine's configured `command` into something spawnable.
//
// This exists because of a failure mode that costs an afternoon the first time
// you meet it, and produces three different errors on the way:
//
//   spawn claude ENOENT     the command is a bare name and the only thing on
//                           PATH is a Windows .CMD shim, which cannot be
//                           spawned at all with shell:false
//   spawn ... UNKNOWN       the resolved .exe is not an executable - it is a
//                           placeholder left behind by a package whose
//                           postinstall never ran (npm --ignore-scripts)
//   nothing at all          the real native binary is present, but one level
//                           down in an optional platform dependency that is
//                           not on PATH and never will be
//
// The watcher spawns with shell:false on purpose (see the comment at its spawn
// site: a shell is one more layer that can re-parse a prompt argument), so
// "just set shell:true" is not the fix. Resolving to an absolute path to a real
// executable BEFORE spawning is, and it keeps the no-shell guarantee intact.
//
// Every function here is sync and pure-ish: given a filesystem, the same answer
// every time. That is what lets `doctor` report exactly what the watcher will
// do, rather than its own approximation of it.

const fs = require('fs');
const os = require('os');
const path = require('path');

const isWindows = process.platform === 'win32';

// A `which` that does not shell out, so it behaves the same everywhere and
// cannot be tricked by a shell alias.
//
// Unchanged in behaviour from the copy that used to live in bin/halyard.js -
// it is moved here so the watcher and doctor share one answer instead of two
// implementations that can drift.
function whichSync(cmd, env = process.env, platform = process.platform) {
  const name = String(cmd || '');
  if (!name) return null;
  if (name.includes(path.sep) || name.includes('/')) {
    return fs.existsSync(name) ? name : null;
  }
  const exts = platform === 'win32'
    ? (env.PATHEXT || '.EXE;.CMD;.BAT').split(';')
    : [''];
  for (const dir of (env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const full = path.join(dir, name + ext);
      try {
        if (fs.statSync(full).isFile()) return full;
      } catch (e) { /* next */ }
    }
  }
  return null;
}

// Is this file something the OS can actually execute?
//
// On Windows the question has a cheap and completely reliable answer: every
// real PE binary begins with the two bytes "MZ". A .exe that does not is a
// placeholder - and the one that motivated this file is a shell script that
// prints "claude native binary not installed" to stderr, which spawn reports
// as the wonderfully unhelpful `UNKNOWN`.
//
// On POSIX there is no magic number worth trusting (a script with a shebang is
// perfectly executable), so the mode bit is the honest test.
function isRealExecutable(file, platform = process.platform) {
  let st;
  try {
    st = fs.statSync(file);
  } catch (e) {
    return false;
  }
  if (!st.isFile()) return false;

  if (platform === 'win32') {
    if (!/\.exe$/i.test(file)) return false;
    let fd = null;
    try {
      fd = fs.openSync(file, 'r');
      const head = Buffer.alloc(2);
      // A 0- or 1-byte file is not a PE, and reading fewer bytes than asked is
      // not an error - so check the count, not just the buffer.
      if (fs.readSync(fd, head, 0, 2, 0) < 2) return false;
      return head[0] === 0x4d && head[1] === 0x5a; // 'MZ'
    } catch (e) {
      return false;
    } finally {
      if (fd !== null) { try { fs.closeSync(fd); } catch (e) { /* closing */ } }
    }
  }

  try {
    fs.accessSync(file, fs.constants.X_OK);
    return true;
  } catch (e) {
    return false;
  }
}

// The executable an npm-generated Windows .CMD shim actually calls.
//
// npm writes these in a fixed shape, and the only line that matters is the one
// invoking the target relative to %dp0% (the shim's own directory):
//
//   "%dp0%\node_modules\@anthropic-ai\claude-code\bin\claude.exe"   %*
//
// Parsed rather than executed: running the shim to find out what it runs would
// need the shell this whole module exists to avoid.
function shimTarget(shim) {
  if (!/\.(cmd|bat)$/i.test(shim)) return null;
  let text;
  try {
    text = fs.readFileSync(shim, 'utf8');
  } catch (e) {
    return null;
  }
  const dir = path.dirname(shim);
  // Quoted first: an unquoted match would stop at the first space and silently
  // truncate any path under "Program Files".
  const quoted = text.match(/"%~?dp0%\\?([^"]+)"/i);
  const raw = quoted || text.match(/%~?dp0%\\?(\S+)/i);
  if (!raw) return null;
  // The shim's own %dp0% ends in a separator, so a leading one here is a
  // doubled separator, not an absolute path. The shim's own text is always
  // Windows path syntax regardless of what OS is parsing it here - normalize
  // to forward slashes so path.resolve joins it correctly on POSIX too,
  // rather than treating a literal backslash as part of a filename.
  const rel = raw[1].replace(/^[\\/]+/, '').replace(/\\/g, '/');
  if (!rel) return null;
  return path.resolve(dir, rel);
}

// The platform-native binary that belongs to a wrapper package.
//
// This is not a guess about one vendor: it is the standard npm layout for
// shipping native binaries (esbuild, swc, rollup and claude-code all use it).
// A wrapper package declares per-platform optionalDependencies named
// `<pkg>-<platform>-<arch>`, npm installs only the matching one, and a
// postinstall copies its binary into the wrapper's bin/. When that postinstall
// does not run - `npm i --ignore-scripts`, or a locked-down CI - the wrapper's
// bin/ still holds the placeholder and the real binary sits unused one level
// down. This finds it.
//
//   node_modules/@scope/pkg/bin/claude.exe            <- the placeholder
//   node_modules/@scope/pkg/node_modules/
//       @scope/pkg-win32-x64/claude.exe               <- the real one
function nativeSibling(binary, platform = process.platform, arch = os.arch()) {
  const ext = platform === 'win32' ? '.exe' : '';
  const base = path.basename(binary, path.extname(binary));

  // Walk up out of bin/ to the package root, then look for its private
  // node_modules. Bounded to a few levels: this is a known shape, not a search.
  let pkgRoot = path.dirname(binary);
  for (let i = 0; i < 3; i += 1) {
    const nm = path.join(pkgRoot, 'node_modules');
    let manifest = null;
    try {
      manifest = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
    } catch (e) { manifest = null; }

    if (manifest && fs.existsSync(nm)) {
      const optional = Object.keys(manifest.optionalDependencies || {});
      // Prefer the dependency the manifest actually declares for this
      // platform/arch over anything merely sitting in node_modules, so a stale
      // cross-platform copy left by a lockfile cannot win.
      const wanted = optional.filter((n) => n.endsWith(`-${platform}-${arch}`));
      const names = wanted.length ? wanted : optional;
      for (const name of names) {
        const candidate = path.join(nm, ...name.split('/'), base + ext);
        if (isRealExecutable(candidate, platform)) return candidate;
      }
    }
    pkgRoot = path.dirname(pkgRoot);
  }
  return null;
}

// The one function the rest of Halyard calls.
//
// Returns the same shape whether it succeeded or not, because both callers need
// the diagnosis and not merely the answer: the watcher puts `problem` in the
// reply the phone shows, and doctor prints it next to the engine. `command` is
// null exactly when the engine cannot run.
//
//   { command, source, problem, hint }
//
function resolveCommand(cmd, opts = {}) {
  const {
    platform = process.platform,
    arch = os.arch(),
    env = process.env,
  } = opts;
  const name = String(cmd || '');
  const out = { command: null, source: null, problem: null, hint: null };

  if (!name) {
    out.problem = 'no command configured';
    return out;
  }

  const found = whichSync(name, env, platform);
  if (!found) {
    out.problem = `${name} is not on PATH`;
    out.hint = 'install the agent CLI, or set engines.<name>.command to its absolute path';
    return out;
  }

  // Straightforward case: PATH gave us a real binary.
  if (isRealExecutable(found, platform)) {
    out.command = found;
    out.source = 'path';
    return out;
  }

  // On POSIX, anything executable already returned above; a non-executable hit
  // is a permission problem and saying so beats guessing further.
  if (platform !== 'win32') {
    out.problem = `${found} is not executable`;
    out.hint = `chmod +x "${found}"`;
    return out;
  }

  // Windows: a .cmd/.bat shim cannot be spawned with shell:false at all, so
  // follow it to the executable it wraps.
  const target = shimTarget(found);
  if (!target && /\.(cmd|bat)$/i.test(found)) {
    // A wrapper we cannot see through - it launches an interpreter rather than
    // a binary (the Copilot CLI shim shells out to powershell, for instance).
    // Saying "not a real executable" here would be wrong and would send
    // someone off reinstalling a CLI that is installed perfectly well.
    out.problem = `${found} is a ${path.extname(found).slice(1).toLowerCase()} wrapper, which cannot be run without a shell`;
    out.hint = 'set engines.<name>.command to the real executable this wrapper launches';
    return out;
  }
  if (target) {
    if (isRealExecutable(target, platform)) {
      out.command = target;
      out.source = 'shim';
      return out;
    }
    // The shim points at a placeholder: the wrapper package is installed but
    // its postinstall never copied the native binary in. The real one is
    // usually right there in an optional dependency.
    const native = nativeSibling(target, platform, arch);
    if (native) {
      out.command = native;
      out.source = 'native';
      return out;
    }
    out.problem = `${target} is not a real executable (the package's postinstall did not run)`;
    out.hint = `reinstall the agent CLI without --ignore-scripts, or point engines.<name>.command at the platform binary under ${path.join(path.dirname(target), '..', 'node_modules')}`;
    return out;
  }

  // Someone configured an absolute path straight to a placeholder.
  const native = nativeSibling(found, platform, arch);
  if (native) {
    out.command = native;
    out.source = 'native';
    return out;
  }

  out.problem = `${found} is not a real executable`;
  out.hint = 'reinstall the agent CLI without --ignore-scripts';
  return out;
}

module.exports = {
  whichSync,
  isRealExecutable,
  shimTarget,
  nativeSibling,
  resolveCommand,
  isWindows,
};
