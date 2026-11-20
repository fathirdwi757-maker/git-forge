// mcp.ts — the Model Context Protocol endpoint at POST /mcp (streamable HTTP,
// JSON-RPC). Two client eras are served: the 2026 stateless era opens with
// server/discover, the classic era with initialize; both then use tools/list
// and tools/call. The tools are the canonical github-mcp-server set the
// contest maps onto, backed by the same forge store as REST and GraphQL, so
// anything created here is visible there (and vice versa).

import {
  VIEWER_LOGIN,
  addIssue,
  addPull,
  allRepos,
  createRepo,
  findRepo,
  issueView,
  mergePull,
  pullView,
  repoView,
  type Repo,
} from './forge.ts';
import { asRecord, str, type Reply } from './web.ts';

const SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const SERVER_INFO = { name: 'git-forge', version: '1.0.0' };

interface ToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, { type: string; description: string }>;
    required: string[];
  };
}

const stringProp = (description: string): { type: string; description: string } => ({ type: 'string', description });
const numberProp = (description: string): { type: string; description: string } => ({ type: 'integer', description });

const TOOLS: ToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: stringProp('The name of the repository to create'),
        description: stringProp('A short description of the repository'),
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get details of a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: { owner: stringProp('The repository owner'), repo: stringProp('The repository name') },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'list_repos',
    description: 'List the repositories owned by the authenticated user.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'create_issue',
    description: 'Create a new issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: stringProp('The repository owner'),
        repo: stringProp('The repository name'),
        title: stringProp('The issue title'),
        body: stringProp('The issue body'),
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'get_issue',
    description: 'Get a single issue by its number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: stringProp('The repository owner'),
        repo: stringProp('The repository name'),
        issue_number: numberProp('The issue number'),
      },
      required: ['owner', 'repo', 'issue_number'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository, optionally filtered by state (open, closed or all).',
    inputSchema: {
      type: 'object',
      properties: {
        owner: stringProp('The repository owner'),
        repo: stringProp('The repository name'),
        state: stringProp('Filter by state: open, closed or all'),
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: stringProp('The repository owner'),
        repo: stringProp('The repository name'),
        title: stringProp('The pull request title'),
        body: stringProp('The pull request body'),
        head: stringProp('The head branch name'),
        base: stringProp('The base branch name'),
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: stringProp('The repository owner'),
        repo: stringProp('The repository name'),
        state: stringProp('Filter by state: open, closed or all'),
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request into its base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: stringProp('The repository owner'),
        repo: stringProp('The repository name'),
        pull_number: numberProp('The pull request number'),
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

/* ------------------------------------------------------------ tool results */

interface ToolResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

function okResult(value: Record<string, unknown>): ToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value };
}

function errorResult(message: string): ToolResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function requireRepo(args: Record<string, unknown>): Repo | ToolResult {
  const owner = str(args.owner);
  const name = str(args.repo);
  if (!owner || !name) return errorResult('owner and repo are required');
  const repo = findRepo(owner, name);
  if (!repo) return errorResult(`repository ${owner}/${name} not found`);
  return repo;
}

function isError(value: Repo | ToolResult): value is ToolResult {
  return (value as ToolResult).isError === true;
}

function callTool(name: string, args: Record<string, unknown>): ToolResult | null {
  switch (name) {
    case 'create_repo': {
      const repoName = str(args.name);
      if (!repoName) return errorResult('name is required');
      if (findRepo(VIEWER_LOGIN, repoName)) return errorResult(`repository ${repoName} already exists`);
      const repo = createRepo(repoName, {
        description: str(args.description) ?? '',
        private: args.private === true,
      });
      return okResult(repoView(repo));
    }
    case 'get_repo': {
      const repo = requireRepo(args);
      if (isError(repo)) return repo;
      return okResult(repoView(repo));
    }
    case 'list_repos': {
      const repos = allRepos().map(repoView);
      return okResult({ repositories: repos, count: repos.length });
    }
    case 'create_issue': {
      const repo = requireRepo(args);
      if (isError(repo)) return repo;
      const title = str(args.title);
      if (!title) return errorResult('title is required');
      const issue = addIssue(repo, title, str(args.body) ?? '', []);
      return okResult(issueView(repo, issue));
    }
    case 'get_issue': {
      const repo = requireRepo(args);
      if (isError(repo)) return repo;
      const number = typeof args.issue_number === 'number' ? args.issue_number : Number(args.issue_number);
      const issue = repo.issues.get(number);
      if (!issue) return errorResult(`issue ${number} not found`);
      return okResult(issueView(repo, issue));
    }
    case 'list_issues': {
      const repo = requireRepo(args);
      if (isError(repo)) return repo;
      const state = str(args.state) ?? 'open';
      let issues = [...repo.issues.values()];
      if (state === 'open' || state === 'closed') issues = issues.filter((issue) => issue.state === state);
      const views = issues.map((issue) => issueView(repo, issue));
      return okResult({ issues: views, count: views.length });
    }
    case 'create_pull_request': {
      const repo = requireRepo(args);
      if (isError(repo)) return repo;
      const title = str(args.title);
      const head = (str(args.head) ?? '').replace(/^refs\/heads\//, '');
      const base = (str(args.base) ?? '').replace(/^refs\/heads\//, '');
      if (!title || !head || !base) return errorResult('title, head and base are required');
      const headTip = repo.branchTip(head);
      const baseTip = repo.branchTip(base);
      if (!headTip) return errorResult(`head branch '${head}' does not exist`);
      if (!baseTip) return errorResult(`base branch '${base}' does not exist`);
      if (headTip === baseTip) return errorResult('no commits between base and head');
      const duplicate = [...repo.pulls.values()].some(
        (pull) => pull.state === 'open' && pull.headRef === head && pull.baseRef === base,
      );
      if (duplicate) return errorResult('a pull request already exists for this head and base');
      const pull = addPull(repo, title, str(args.body) ?? '', head, base);
      return okResult(pullView(repo, pull));
    }
    case 'list_pull_requests': {
      const repo = requireRepo(args);
      if (isError(repo)) return repo;
      const state = str(args.state) ?? 'open';
      let pulls = [...repo.pulls.values()];
      if (state === 'open' || state === 'closed') pulls = pulls.filter((pull) => pull.state === state);
      const views = pulls.map((pull) => pullView(repo, pull));
      return okResult({ pull_requests: views, count: views.length });
    }
    case 'merge_pull_request': {
      const repo = requireRepo(args);
      if (isError(repo)) return repo;
      const number = typeof args.pull_number === 'number' ? args.pull_number : Number(args.pull_number);
      const pull = repo.pulls.get(number);
      if (!pull) return errorResult(`pull request ${number} not found`);
      if (pull.merged) return errorResult('pull request has already been merged');
      const outcome = mergePull(repo, pull, 'squash');
      if (!outcome.ok) return errorResult(outcome.conflict ? 'merge conflict: the pull request cannot be merged' : outcome.message);
      return okResult({ merged: true, sha: outcome.sha, number: pull.number, message: 'Pull Request successfully merged' });
    }
    default:
      return null;
  }
}

/* -------------------------------------------------------------- JSON-RPC */

interface RpcOutcome {
  status: number;
  payload?: unknown;
}

function handleMessage(message: Record<string, unknown>): RpcOutcome | null {
  const method = str(message.method);
  const hasId = 'id' in message && message.id !== undefined;
  const id = hasId ? message.id : null;
  const params = asRecord(message.params);
  if (!method) {
    if (!hasId) return null;
    return { status: 200, payload: { jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid Request' } } };
  }
  if (!hasId) return null; // a notification: accepted, never answered

  const result = (value: unknown): RpcOutcome => ({ status: 200, payload: { jsonrpc: '2.0', id, result: value } });
  const failure = (code: number, text: string): RpcOutcome => ({
    status: 200,
    payload: { jsonrpc: '2.0', id, error: { code, message: text } },
  });

  switch (method) {
    case 'server/discover':
      return result({
        supportedVersions: SUPPORTED_VERSIONS,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      });
    case 'initialize': {
      const requested = str(params.protocolVersion);
      const protocolVersion = requested && SUPPORTED_VERSIONS.includes(requested) ? requested : '2025-11-25';
      return result({ protocolVersion, capabilities: { tools: {} }, serverInfo: SERVER_INFO });
    }
    case 'ping':
      return result({});
    case 'tools/list':
      return result({ tools: TOOLS });
    case 'tools/call': {
      const toolName = str(params.name);
      if (!toolName) return failure(-32602, 'tools/call requires a tool name');
      const tool = callTool(toolName, asRecord(params.arguments));
      if (tool === null) return failure(-32602, `Unknown tool: ${toolName}`);
      return result(tool);
    }
    default:
      return failure(-32601, `Method not found: ${method}`);
  }
}

export function handleMCP(rawBody: Buffer): Reply {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return {
      status: 400,
      json: { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
    };
  }
  if (Array.isArray(parsed)) {
    const payloads: unknown[] = [];
    for (const entry of parsed) {
      const outcome = handleMessage(asRecord(entry));
      if (outcome?.payload !== undefined) payloads.push(outcome.payload);
    }
    if (payloads.length === 0) return { status: 202 };
    return { status: 200, json: payloads };
  }
  const outcome = handleMessage(asRecord(parsed));
  if (!outcome || outcome.payload === undefined) return { status: 202 };
  return { status: outcome.status, json: outcome.payload };
}
