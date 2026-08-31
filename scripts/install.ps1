# Halyard quick install for Windows.
#
#   irm https://raw.githubusercontent.com/jakoreilly/Halyard/main/scripts/install.ps1 | iex
#
# Same scope as the shell installer: check node, clone or update, run setup,
# print the link. No scheduled task, no firewall rule, no edits to your agent's
# settings - those are separate, explicit commands.
$ErrorActionPreference = 'Stop'

$repo = if ($env:HALYARD_REPO) { $env:HALYARD_REPO } else { 'https://github.com/jakoreilly/Halyard.git' }
$dir  = if ($env:HALYARD_DIR)  { $env:HALYARD_DIR }  else { Join-Path $HOME '.halyard-src' }

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'Halyard needs Node 18.17 or newer. Install it from https://nodejs.org and re-run.'
}
$major = [int](node -p 'process.versions.node.split(".")[0]')
if ($major -lt 18) { throw "Halyard needs Node 18.17+; found $(node -v)." }

if (Test-Path (Join-Path $dir '.git')) {
    Write-Host "  updating $dir"
    git -C $dir pull --ff-only
} else {
    Write-Host "  cloning into $dir"
    git clone --depth 1 $repo $dir
}

Push-Location $dir
node bin/halyard.js setup
Pop-Location

Write-Host ""
Write-Host "  Next:"
Write-Host "    node $dir\bin\halyard.js start        run it"
Write-Host "    node $dir\bin\halyard.js doctor       check it"
Write-Host "    node $dir\bin\halyard.js hook-config  wire up the approve/deny relay"
Write-Host ""
Write-Host "  Start at logon:  node $dir\bin\halyard.js install-service"
Write-Host ""
