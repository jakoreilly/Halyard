const readline = require('readline');
const { askPhone, RELAYED_TOOLS } = require('./permission-relay');

const TOOL_NAME = 'approve';
const SERVER_NAME = 'halyard_relay';

function describe(toolName, input) {
  const i = input || {};
  if (typeof i.command === 'string' && i.command) return i.command;
  if (typeof i.file_path === 'string' && i.file_path) return `${toolName} ${i.file_path}`;
  if (typeof i.notebook_path === 'string' && i.notebook_path) return `${toolName} ${i.notebook_path}`;
  if (typeof i.url === 'string' && i.url) return `${toolName} ${i.url}`;
  if (typeof i.pattern === 'string' && i.pattern) return `${toolName} ${i.pattern}${i.path ? ` in ${i.path}` : ''}`;
  let json = '';
  try { json = JSON.stringify(i); } catch (e) { json = ''; }
  return `${toolName} ${json}`.slice(0, 2000);
}

function decision(allow, input, reason) {
  return allow
    ? { behavior: 'allow', updatedInput: input || {} }
    : { behavior: 'deny', message: reason };
}

async function decide(args, ask = askPhone) {
  const toolName = String((args && args.tool_name) || 'a tool');
  const input = (args && args.input && typeof args.input === 'object') ? args.input : {};
  const answer = await ask({
    question: `A headless run wants to use ${toolName}, which needs permission. Approve?`,
    command: describe(toolName, input),
    rule: 'permission',
    cwd: process.cwd(),
    missedLabel: RELAYED_TOOLS.has(toolName) ? `${toolName} command that needed permission` : null,
  });
  return decision(answer.allow, input, answer.reason);
}

const TOOLS = [{
  name: TOOL_NAME,
  description: 'Halyard permission prompt: asks the phone to approve or deny a tool call. Used by Claude Code itself; not for direct use.',
  inputSchema: {
    type: 'object',
    properties: {
      tool_name: { type: 'string' },
      input: { type: 'object' },
      tool_use_id: { type: 'string' },
    },
    required: ['tool_name', 'input'],
  },
}];

async function handle(msg, ask = askPhone) {
  if (!msg || typeof msg !== 'object') return null;
  const { id, method, params } = msg;
  const isRequest = id !== undefined && id !== null;
  const reply = (result) => ({ jsonrpc: '2.0', id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

  switch (method) {
    case 'initialize':
      return reply({
        protocolVersion: (params && params.protocolVersion) || '2025-06-18',
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: '1.0.0' },
      });
    case 'ping':
      return isRequest ? reply({}) : null;
    case 'tools/list':
      return reply({ tools: TOOLS });
    case 'tools/call': {
      if (!params || params.name !== TOOL_NAME) return fail(-32602, `unknown tool ${params && params.name}`);
      let out;
      try {
        out = await decide(params.arguments || {}, ask);
      } catch (e) {
        out = decision(false, null, 'relay error');
      }
      return reply({ content: [{ type: 'text', text: JSON.stringify(out) }] });
    }
    default:
      return isRequest ? fail(-32601, `method not found: ${method}`) : null;
  }
}

function main() {
  const rl = readline.createInterface({ input: process.stdin });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch (e) { return; }
    handle(msg).then((res) => {
      if (res) process.stdout.write(`${JSON.stringify(res)}\n`);
    }).catch(() => {});
  });
}

if (require.main === module) main();

module.exports = { handle, decide, describe, decision, TOOL_NAME, SERVER_NAME };
