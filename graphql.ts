// graphql.ts — GitHub GraphQL v4 at POST /api/graphql. The documents the
// clients send are a fixed family (viewer, repository, issues/pull-request
// connections, node lookups, introspection of a few types, and the issue /
// pull-request / comment mutations), so this is a small hand-written parser
// and executor for exactly that grammar: operations with variables, aliases,
// inline and named fragments, input objects, enum lists, null variables and
// batched array bodies. Unknown fields answer the way GitHub does: HTTP 200,
// the field null, and an errors entry naming the field and its type.

import {
  Repo,
  VIEWER_EMAIL,
  VIEWER_ID,
  VIEWER_LOGIN,
  VIEWER_NAME,
  addComment,
  addIssue,
  addPull,
  allRepos,
  computeMergeable,
  decodeGlobalId,
  encodeGlobalId,
  findRepo,
  isoFor,
  mergePull,
  pullFiles,
  type Comment,
  type Issue,
  type Pull,
} from './forge.ts';
import { asRecord, errorReply, jsonReply, str, type Reply } from './web.ts';

/* -------------------------------------------------------------- tokenizer */

interface Token {
  kind: 'name' | 'string' | 'number' | 'punct' | 'spread' | 'variable';
  value: string;
}

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (source.startsWith('...', i)) {
      tokens.push({ kind: 'spread', value: '...' });
      i += 3;
      continue;
    }
    if (ch === '$') {
      const match = /^\$[_A-Za-z][_0-9A-Za-z]*/.exec(source.slice(i));
      if (!match) throw new Error('invalid variable');
      tokens.push({ kind: 'variable', value: match[0].slice(1) });
      i += match[0].length;
      continue;
    }
    if (ch === '"') {
      if (source.startsWith('"""', i)) {
        const end = source.indexOf('"""', i + 3);
        if (end === -1) throw new Error('unterminated block string');
        tokens.push({ kind: 'string', value: source.slice(i + 3, end) });
        i = end + 3;
        continue;
      }
      let j = i + 1;
      let value = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\') {
          const esc = source[j + 1];
          value += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          value += source[j];
          j += 1;
        }
      }
      if (j >= source.length) throw new Error('unterminated string');
      tokens.push({ kind: 'string', value });
      i = j + 1;
      continue;
    }
    if (/[-0-9]/.test(ch)) {
      const match = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(source.slice(i));
      if (!match) throw new Error('invalid number');
      tokens.push({ kind: 'number', value: match[0] });
      i += match[0].length;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      const match = /^[_A-Za-z][_0-9A-Za-z]*/.exec(source.slice(i));
      tokens.push({ kind: 'name', value: (match as RegExpExecArray)[0] });
      i += (match as RegExpExecArray)[0].length;
      continue;
    }
    if ('{}()[]:=!@|&'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)}`);
  }
  return tokens;
}

/* ----------------------------------------------------------------- parser */

type Value =
  | { kind: 'string'; value: string }
  | { kind: 'number'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'enum'; value: string }
  | { kind: 'null' }
  | { kind: 'variable'; name: string }
  | { kind: 'list'; items: Value[] }
  | { kind: 'object'; fields: Map<string, Value> };

interface FieldNode {
  name: string;
  alias?: string;
  args: Map<string, Value>;
  selection?: SelectionItem[];
}

type SelectionItem =
  | { kind: 'field'; field: FieldNode }
  | { kind: 'inlineFragment'; typeCondition: string; selection: SelectionItem[] }
  | { kind: 'fragmentSpread'; name: string };

interface Operation {
  type: 'query' | 'mutation';
  name?: string;
  selection: SelectionItem[];
}

interface Document {
  operations: Operation[];
  fragments: Map<string, { typeCondition: string; selection: SelectionItem[] }>;
}

class Parser {
  private pos = 0;
  private readonly tokens: Token[];

  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  private peek(): Token | undefined {
    return this.tokens[this.pos];
  }

  private next(): Token {
    const token = this.tokens[this.pos];
    if (!token) throw new Error('unexpected end of document');
    this.pos += 1;
    return token;
  }

  private expectPunct(value: string): void {
    const token = this.next();
    if (token.kind !== 'punct' || token.value !== value) throw new Error(`expected '${value}'`);
  }

  private skipPunct(value: string): boolean {
    const token = this.peek();
    if (token && token.kind === 'punct' && token.value === value) {
      this.pos += 1;
      return true;
    }
    return false;
  }

  parseDocument(): Document {
    const operations: Operation[] = [];
    const fragments = new Map<string, { typeCondition: string; selection: SelectionItem[] }>();
    while (this.pos < this.tokens.length) {
      const token = this.peek() as Token;
      if (token.kind === 'punct' && token.value === '{') {
        operations.push({ type: 'query', selection: this.parseSelectionSet() });
        continue;
      }
      if (token.kind !== 'name') throw new Error('expected an operation or fragment');
      if (token.value === 'query' || token.value === 'mutation') {
        this.next();
        let name: string | undefined;
        const maybeName = this.peek();
        if (maybeName && maybeName.kind === 'name') name = this.next().value;
        if (this.peek()?.kind === 'punct' && this.peek()?.value === '(') this.parseVariableDefinitions();
        operations.push({ type: token.value, name, selection: this.parseSelectionSet() });
        continue;
      }
      if (token.value === 'fragment') {
        this.next();
        const fragName = this.next().value;
        const onToken = this.next();
        if (onToken.value !== 'on') throw new Error('expected on in fragment definition');
        const typeCondition = this.next().value;
        fragments.set(fragName, { typeCondition, selection: this.parseSelectionSet() });
        continue;
      }
      throw new Error(`unexpected definition ${token.value}`);
    }
    return { operations, fragments };
  }

  private parseVariableDefinitions(): void {
    this.expectPunct('(');
    while (!this.skipPunct(')')) {
      this.next(); // $variable
      this.expectPunct(':');
      this.parseType();
      if (this.skipPunct('=')) this.parseValue();
    }
  }

  private parseType(): void {
    if (this.skipPunct('[')) {
      this.parseType();
      this.expectPunct(']');
    } else {
      this.next(); // type name
    }
    this.skipPunct('!');
  }

  private parseSelectionSet(): SelectionItem[] {
    this.expectPunct('{');
    const items: SelectionItem[] = [];
    while (!this.skipPunct('}')) {
      const token = this.peek();
      if (!token) throw new Error('unterminated selection set');
      if (token.kind === 'spread') {
        this.next();
        const next = this.peek();
        if (next && next.kind === 'name' && next.value === 'on') {
          this.next();
          const typeCondition = this.next().value;
          items.push({ kind: 'inlineFragment', typeCondition, selection: this.parseSelectionSet() });
        } else {
          const name = this.next().value;
          items.push({ kind: 'fragmentSpread', name });
        }
        continue;
      }
      items.push({ kind: 'field', field: this.parseField() });
    }
    return items;
  }

  private parseField(): FieldNode {
    let name = this.next().value;
    let alias: string | undefined;
    if (this.skipPunct(':')) {
      alias = name;
      name = this.next().value;
    }
    const args = new Map<string, Value>();
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '(') {
      this.next();
      while (!this.skipPunct(')')) {
        const argName = this.next().value;
        this.expectPunct(':');
        args.set(argName, this.parseValue());
      }
    }
    // Directives are parsed and ignored: the documents here use none that change meaning.
    while (this.peek()?.kind === 'punct' && this.peek()?.value === '@') {
      this.next();
      this.next();
      if (this.peek()?.kind === 'punct' && this.peek()?.value === '(') {
        this.next();
        while (!this.skipPunct(')')) {
          this.next();
          this.expectPunct(':');
          this.parseValue();
        }
      }
    }
    let selection: SelectionItem[] | undefined;
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '{') selection = this.parseSelectionSet();
    return { name, alias, args, selection };
  }

  private parseValue(): Value {
    const token = this.next();
    if (token.kind === 'string') return { kind: 'string', value: token.value };
    if (token.kind === 'number') return { kind: 'number', value: Number(token.value) };
    if (token.kind === 'variable') return { kind: 'variable', name: token.value };
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    if (token.kind === 'punct' && token.value === '[') {
      const items: Value[] = [];
      while (!this.skipPunct(']')) items.push(this.parseValue());
      return { kind: 'list', items };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const fields = new Map<string, Value>();
      while (!this.skipPunct('}')) {
        const key = this.next().value;
        this.expectPunct(':');
        fields.set(key, this.parseValue());
      }
      return { kind: 'object', fields };
    }
    throw new Error('unexpected value');
  }
}

/* --------------------------------------------------------------- execution */

type Source =
  | { __type: 'User' }
  | { __type: 'Repository'; repo: Repo }
  | { __type: 'Issue'; repo: Repo; issue: Issue }
  | { __type: 'PullRequest'; repo: Repo; pull: Pull }
  | { __type: 'IssueComment'; repo: Repo; comment: Comment }
  | { __type: 'Ref'; name: string; prefix: string }
  | { __type: 'IssueConnection'; repo: Repo; items: Issue[]; hasNextPage: boolean; endCursor: string | null; total: number }
  | { __type: 'PullRequestConnection'; repo: Repo; items: Pull[]; total: number }
  | { __type: 'PullRequestChangedFileConnection'; repo: Repo; pull: Pull }
  | { __type: 'PullRequestChangedFile'; path: string; additions: number; deletions: number; changeType: string }
  | { __type: 'PageInfo'; hasNextPage: boolean; endCursor: string | null }
  | { __type: 'CreateIssuePayload'; issue: Source }
  | { __type: 'CloseIssuePayload'; issue: Source }
  | { __type: 'CreatePullRequestPayload'; pullRequest: Source }
  | { __type: 'MergePullRequestPayload'; pullRequest: Source }
  | { __type: 'AddCommentPayload'; commentEdge: Source }
  | { __type: 'CommentEdge'; node: Source }
  | { __type: '__Type'; name: string }
  | { __type: '__Schema' }
  | { __type: '__Field'; name: string }
  | { __type: '__EnumValue'; name: string }
  | { __type: '__TypeName'; name: string };

interface ExecContext {
  variables: Record<string, unknown>;
  fragments: Document['fragments'];
  errors: Array<{ message: string }>;
}

function evalValue(value: Value, ctx: ExecContext): unknown {
  switch (value.kind) {
    case 'string':
    case 'number':
    case 'boolean':
    case 'enum':
      return value.value;
    case 'null':
      return null;
    case 'variable':
      return ctx.variables[value.name] ?? null;
    case 'list':
      return value.items.map((item) => evalValue(item, ctx));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [key, item] of value.fields) out[key] = evalValue(item, ctx);
      return out;
    }
  }
}

function evalArgs(field: FieldNode, ctx: ExecContext): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of field.args) out[key] = evalValue(value, ctx);
  return out;
}

const cursorOf = (number: number): string => Buffer.from(`cursor:${number}`, 'utf8').toString('base64');
const numberFromCursor = (cursor: string): number => {
  const text = Buffer.from(cursor, 'base64').toString('utf8');
  const match = /^cursor:(\d+)$/.exec(text);
  return match ? Number(match[1]) : 0;
};

const userSource: Source = { __type: 'User' };

function repoByDbId(dbId: number): Repo | undefined {
  return allRepos().find((repo) => repo.dbId === dbId);
}

function nodeByGlobalId(id: string): Source | null {
  const decoded = decodeGlobalId(id);
  if (!decoded) return null;
  if (decoded.kind === 'User') return userSource;
  if (decoded.kind === 'Repository') {
    const repo = repoByDbId(Number(decoded.key));
    return repo ? { __type: 'Repository', repo } : null;
  }
  if (decoded.kind === 'Issue' || decoded.kind === 'PullRequest') {
    const [dbId, number] = decoded.key.split(':').map(Number);
    const repo = repoByDbId(dbId);
    if (!repo) return null;
    if (decoded.kind === 'Issue') {
      const issue = repo.issues.get(number);
      return issue ? { __type: 'Issue', repo, issue } : null;
    }
    const pull = repo.pulls.get(number);
    return pull ? { __type: 'PullRequest', repo, pull } : null;
  }
  if (decoded.kind === 'IssueComment') {
    const [dbId, rest] = decoded.key.split(':');
    const repo = repoByDbId(Number(dbId));
    if (!repo) return null;
    const commentId = Number(rest.replace(/^c/, ''));
    for (const issue of repo.issues.values()) {
      const comment = issue.comments.find((candidate) => candidate.id === commentId);
      if (comment) return { __type: 'IssueComment', repo, comment };
    }
    for (const pull of repo.pulls.values()) {
      const comment = pull.comments.find((candidate) => candidate.id === commentId);
      if (comment) return { __type: 'IssueComment', repo, comment };
    }
    return null;
  }
  return null;
}

/* --------------------------------------------------------- schema surface */

const OBJECT_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', 'search', 'rateLimit'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  User: ['id', 'login', 'name', 'email', 'url', 'avatarUrl', 'createdAt', 'updatedAt'],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'description', 'isPrivate',
    'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues',
    'pullRequest', 'pullRequests', 'createdAt', 'updatedAt', 'url',
  ],
  Issue: [
    'id', 'databaseId', 'number', 'title', 'state', 'body', 'author', 'comments',
    'labels', 'createdAt', 'updatedAt', 'closedAt', 'url', 'repository',
  ],
  PullRequest: [
    'id', 'databaseId', 'number', 'title', 'body', 'state', 'merged', 'mergeable',
    'headRefName', 'baseRefName', 'files', 'author', 'comments', 'createdAt',
    'updatedAt', 'mergedAt', 'closedAt', 'additions', 'deletions', 'changedFiles',
    'url', 'repository', 'mergeCommit',
  ],
  IssueComment: ['id', 'body', 'author', 'createdAt', 'updatedAt', 'url'],
  Ref: ['name', 'prefix', 'target'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'subject', 'clientMutationId'],
  CommentEdge: ['node', 'cursor'],
};

const ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  PullRequestChangedFileChangeType: ['ADDED', 'DELETED', 'MODIFIED', 'RENAMED'],
  Permission: ['READ', 'TRIAGE', 'WRITE', 'MAINTAIN', 'ADMIN'],
};

/* --------------------------------------------------------------- resolvers */

type Resolver = (source: Source, args: Record<string, unknown>, ctx: ExecContext) => unknown;

function issuesConnection(repo: Repo, args: Record<string, unknown>): Source {
  let items = [...repo.issues.values()];
  const states = args.states as string[] | undefined;
  if (Array.isArray(states) && states.length > 0) {
    items = items.filter((issue) => states.includes(issue.state.toUpperCase()));
  }
  const orderBy = asRecord(args.orderBy);
  const direction = str(orderBy.direction) ?? 'ASC';
  items.sort((a, b) => (direction === 'DESC' ? b.number - a.number : a.number - b.number));
  const total = items.length;
  const after = str(args.after);
  if (after) {
    const afterNumber = numberFromCursor(after);
    const index = items.findIndex((issue) => issue.number === afterNumber);
    if (index !== -1) items = items.slice(index + 1);
  }
  const first = typeof args.first === 'number' ? args.first : items.length;
  const page = items.slice(0, Math.max(0, first));
  return {
    __type: 'IssueConnection',
    repo,
    items: page,
    hasNextPage: items.length > page.length,
    endCursor: page.length > 0 ? cursorOf(page[page.length - 1].number) : null,
    total,
  };
}

const resolvers: Record<string, Record<string, Resolver>> = {
  Query: {
    viewer: () => userSource,
    repository: (_source, args) => {
      const owner = str(args.owner);
      const name = str(args.name);
      if (!owner || !name) return null;
      const repo = findRepo(owner, name);
      return repo ? ({ __type: 'Repository', repo } as Source) : null;
    },
    node: (_source, args) => {
      const id = str(args.id);
      return id ? nodeByGlobalId(id) : null;
    },
    __type: (_source, args) => {
      const name = str(args.name);
      if (!name) return null;
      return { __type: '__Type', name } as Source;
    },
    __schema: () => ({ __type: '__Schema' }) as Source,
  },
  Mutation: {
    createIssue: (_source, args) => {
      const input = asRecord(args.input);
      const decoded = decodeGlobalId(str(input.repositoryId) ?? '');
      const repo = decoded && decoded.kind === 'Repository' ? repoByDbId(Number(decoded.key)) : undefined;
      if (!repo) throw new Error('Repository not found for createIssue');
      const title = str(input.title);
      if (!title) throw new Error('Title is required');
      const issue = addIssue(repo, title, str(input.body) ?? '', []);
      return { __type: 'CreateIssuePayload', issue: { __type: 'Issue', repo, issue } } as Source;
    },
    closeIssue: (_source, args) => {
      const input = asRecord(args.input);
      const target = nodeByGlobalId(str(input.issueId) ?? '');
      if (!target || target.__type !== 'Issue') throw new Error('Issue not found for closeIssue');
      target.issue.state = 'closed';
      return { __type: 'CloseIssuePayload', issue: target } as Source;
    },
    createPullRequest: (_source, args) => {
      const input = asRecord(args.input);
      const decoded = decodeGlobalId(str(input.repositoryId) ?? '');
      const repo = decoded && decoded.kind === 'Repository' ? repoByDbId(Number(decoded.key)) : undefined;
      if (!repo) throw new Error('Repository not found for createPullRequest');
      const head = (str(input.headRefName) ?? '').replace(/^refs\/heads\//, '');
      const base = (str(input.baseRefName) ?? '').replace(/^refs\/heads\//, '');
      const headTip = repo.branchTip(head);
      const baseTip = repo.branchTip(base);
      if (!headTip) throw new Error(`Head ref '${head}' does not exist`);
      if (!baseTip) throw new Error(`Base ref '${base}' does not exist`);
      if (headTip === baseTip) throw new Error('No commits between base and head');
      const duplicate = [...repo.pulls.values()].some(
        (pull) => pull.state === 'open' && pull.headRef === head && pull.baseRef === base,
      );
      if (duplicate) throw new Error('A pull request already exists for this head and base');
      const pull = addPull(repo, str(input.title) ?? '', str(input.body) ?? '', head, base);
      return { __type: 'CreatePullRequestPayload', pullRequest: { __type: 'PullRequest', repo, pull } } as Source;
    },
    mergePullRequest: (_source, args) => {
      const input = asRecord(args.input);
      const target = nodeByGlobalId(str(input.pullRequestId) ?? '');
      if (!target || target.__type !== 'PullRequest') throw new Error('Pull request not found');
      const methodRaw = (str(input.mergeMethod) ?? 'MERGE').toUpperCase();
      const method = methodRaw === 'SQUASH' ? 'squash' : methodRaw === 'REBASE' ? 'rebase' : 'merge';
      const outcome = mergePull(target.repo, target.pull, method);
      if (!outcome.ok) throw new Error(outcome.conflict ? 'Merge conflict: this pull request cannot be merged' : outcome.message);
      return { __type: 'MergePullRequestPayload', pullRequest: target } as Source;
    },
    addComment: (_source, args) => {
      const input = asRecord(args.input);
      const target = nodeByGlobalId(str(input.subjectId) ?? '');
      const body = str(input.body);
      if (body === undefined) throw new Error('Comment body is required');
      if (!target || (target.__type !== 'Issue' && target.__type !== 'PullRequest')) {
        throw new Error('Subject not found for addComment');
      }
      const repo = target.repo;
      const holder: Issue =
        target.__type === 'Issue'
          ? target.issue
          : {
              number: target.pull.number,
              dbId: target.pull.dbId,
              title: target.pull.title,
              body: target.pull.body,
              state: target.pull.state,
              labels: [],
              comments: target.pull.comments,
              createdSeq: target.pull.createdSeq,
            };
      const comment = addComment(repo, holder, body);
      return {
        __type: 'AddCommentPayload',
        commentEdge: { __type: 'CommentEdge', node: { __type: 'IssueComment', repo, comment } },
      } as Source;
    },
  },
  User: {
    id: () => encodeGlobalId('User', String(VIEWER_ID)),
    login: () => VIEWER_LOGIN,
    name: () => VIEWER_NAME,
    email: () => VIEWER_EMAIL,
    url: () => `https://forge.invalid/${VIEWER_LOGIN}`,
    avatarUrl: () => '',
    createdAt: () => isoFor(1767225600),
    updatedAt: () => isoFor(1767225600),
  },
  Repository: {
    id: (source) => encodeGlobalId('Repository', String((source as { repo: Repo }).repo.dbId)),
    databaseId: (source) => (source as { repo: Repo }).repo.dbId,
    name: (source) => (source as { repo: Repo }).repo.name,
    nameWithOwner: (source) => `${VIEWER_LOGIN}/${(source as { repo: Repo }).repo.name}`,
    owner: () => userSource,
    description: (source) => (source as { repo: Repo }).repo.description,
    isPrivate: (source) => (source as { repo: Repo }).repo.isPrivate,
    defaultBranchRef: (source) => {
      const repo = (source as { repo: Repo }).repo;
      const tip = repo.branchTip(repo.defaultBranch);
      if (!tip) return null;
      return { __type: 'Ref', name: repo.defaultBranch, prefix: 'refs/heads/' } as Source;
    },
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    createdAt: (source) => isoFor((source as { repo: Repo }).repo.createdTs),
    updatedAt: (source) => isoFor((source as { repo: Repo }).repo.createdTs),
    url: (source) => `https://forge.invalid/${VIEWER_LOGIN}/${(source as { repo: Repo }).repo.name}`,
    issue: (source, args) => {
      const repo = (source as { repo: Repo }).repo;
      const number = typeof args.number === 'number' ? args.number : Number(args.number);
      const issue = repo.issues.get(number);
      return issue ? ({ __type: 'Issue', repo, issue } as Source) : null;
    },
    issues: (source, args) => issuesConnection((source as { repo: Repo }).repo, args),
    pullRequest: (source, args) => {
      const repo = (source as { repo: Repo }).repo;
      const number = typeof args.number === 'number' ? args.number : Number(args.number);
      const pull = repo.pulls.get(number);
      return pull ? ({ __type: 'PullRequest', repo, pull } as Source) : null;
    },
    pullRequests: (source, args) => {
      const repo = (source as { repo: Repo }).repo;
      let items = [...repo.pulls.values()];
      const states = args.states as string[] | undefined;
      if (Array.isArray(states) && states.length > 0) {
        items = items.filter((pull) => states.includes((pull.merged ? 'MERGED' : pull.state.toUpperCase())));
      } else {
        items = items.filter((pull) => pull.state === 'open');
      }
      items.sort((a, b) => a.number - b.number);
      const first = typeof args.first === 'number' ? args.first : items.length;
      return { __type: 'PullRequestConnection', repo, items: items.slice(0, Math.max(0, first)), total: items.length } as Source;
    },
  },
  Issue: {
    id: (source) => {
      const s = source as { repo: Repo; issue: Issue };
      return encodeGlobalId('Issue', `${s.repo.dbId}:${s.issue.number}`);
    },
    databaseId: (source) => (source as { issue: Issue }).issue.dbId,
    number: (source) => (source as { issue: Issue }).issue.number,
    title: (source) => (source as { issue: Issue }).issue.title,
    body: (source) => (source as { issue: Issue }).issue.body,
    state: (source) => ((source as { issue: Issue }).issue.state === 'closed' ? 'CLOSED' : 'OPEN'),
    author: () => userSource,
    createdAt: (source) => isoFor(1767225600 + (source as { issue: Issue }).issue.createdSeq * 60),
    updatedAt: (source) => isoFor(1767225600 + (source as { issue: Issue }).issue.createdSeq * 60),
    closedAt: (source) => ((source as { issue: Issue }).issue.state === 'closed' ? isoFor(1767225600 + (source as { issue: Issue }).issue.createdSeq * 60) : null),
    url: (source) => {
      const s = source as { repo: Repo; issue: Issue };
      return `https://forge.invalid/${VIEWER_LOGIN}/${s.repo.name}/issues/${s.issue.number}`;
    },
    repository: (source) => ({ __type: 'Repository', repo: (source as { repo: Repo }).repo }) as Source,
  },
  PullRequest: {
    id: (source) => {
      const s = source as { repo: Repo; pull: Pull };
      return encodeGlobalId('PullRequest', `${s.repo.dbId}:${s.pull.number}`);
    },
    databaseId: (source) => (source as { pull: Pull }).pull.dbId,
    number: (source) => (source as { pull: Pull }).pull.number,
    title: (source) => (source as { pull: Pull }).pull.title,
    body: (source) => (source as { pull: Pull }).pull.body,
    state: (source) => {
      const pull = (source as { pull: Pull }).pull;
      return pull.merged ? 'MERGED' : pull.state.toUpperCase();
    },
    merged: (source) => (source as { pull: Pull }).pull.merged,
    mergeable: (source) => {
      const s = source as { repo: Repo; pull: Pull };
      if (s.pull.state !== 'open') return 'UNKNOWN';
      const result = computeMergeable(s.repo, s.pull);
      return result === null ? 'UNKNOWN' : result ? 'MERGEABLE' : 'CONFLICTING';
    },
    headRefName: (source) => (source as { pull: Pull }).pull.headRef,
    baseRefName: (source) => (source as { pull: Pull }).pull.baseRef,
    author: () => userSource,
    files: (source) => {
      const s = source as { repo: Repo; pull: Pull };
      return { __type: 'PullRequestChangedFileConnection', repo: s.repo, pull: s.pull } as Source;
    },
    additions: (source) => {
      const s = source as { repo: Repo; pull: Pull };
      return pullFiles(s.repo, s.pull).reduce((sum, diff) => sum + diff.additions, 0);
    },
    deletions: (source) => {
      const s = source as { repo: Repo; pull: Pull };
      return pullFiles(s.repo, s.pull).reduce((sum, diff) => sum + diff.deletions, 0);
    },
    changedFiles: (source) => {
      const s = source as { repo: Repo; pull: Pull };
      return pullFiles(s.repo, s.pull).length;
    },
    mergedAt: (source) => (source as { pull: Pull }).pull.mergedAt,
    mergeCommit: (source) => {
      const pull = (source as { pull: Pull }).pull;
      return pull.mergeCommitSha ? { __type: '__TypeName', name: pull.mergeCommitSha } : null;
    },
    createdAt: (source) => isoFor(1767225600 + (source as { pull: Pull }).pull.createdSeq * 60),
    updatedAt: (source) => isoFor(1767225600 + (source as { pull: Pull }).pull.createdSeq * 60),
    closedAt: (source) => {
      const pull = (source as { pull: Pull }).pull;
      return pull.state === 'closed' ? isoFor(1767225600 + pull.createdSeq * 60) : null;
    },
    url: (source) => {
      const s = source as { repo: Repo; pull: Pull };
      return `https://forge.invalid/${VIEWER_LOGIN}/${s.repo.name}/pull/${s.pull.number}`;
    },
    repository: (source) => ({ __type: 'Repository', repo: (source as { repo: Repo }).repo }) as Source,
  },
  IssueComment: {
    id: (source) => {
      const s = source as { repo: Repo; comment: Comment };
      return encodeGlobalId('IssueComment', `${s.repo.dbId}:c${s.comment.id}`);
    },
    body: (source) => (source as { comment: Comment }).comment.body,
    author: () => userSource,
    createdAt: (source) => isoFor(1767225600 + (source as { comment: Comment }).comment.createdSeq * 60),
    updatedAt: (source) => isoFor(1767225600 + (source as { comment: Comment }).comment.createdSeq * 60),
  },
  Ref: {
    name: (source) => (source as { name: string }).name,
    prefix: (source) => (source as { prefix: string }).prefix,
  },
  IssueConnection: {
    nodes: (source) => {
      const s = source as { repo: Repo; items: Issue[] };
      return s.items.map((issue) => ({ __type: 'Issue', repo: s.repo, issue }) as Source);
    },
    edges: (source) => {
      const s = source as { repo: Repo; items: Issue[] };
      return s.items.map((issue) => ({
        __type: 'CommentEdge',
        node: { __type: 'Issue', repo: s.repo, issue } as Source,
        cursor: cursorOf(issue.number),
      }));
    },
    pageInfo: (source) => {
      const s = source as { hasNextPage: boolean; endCursor: string | null };
      return { __type: 'PageInfo', hasNextPage: s.hasNextPage, endCursor: s.endCursor } as Source;
    },
    totalCount: (source) => (source as { total: number }).total,
  },
  PullRequestConnection: {
    nodes: (source) => {
      const s = source as { repo: Repo; items: Pull[] };
      return s.items.map((pull) => ({ __type: 'PullRequest', repo: s.repo, pull }) as Source);
    },
    pageInfo: () => ({ __type: 'PageInfo', hasNextPage: false, endCursor: null }) as Source,
    totalCount: (source) => (source as { total: number }).total,
  },
  PullRequestChangedFileConnection: {
    nodes: (source, args) => {
      const s = source as { repo: Repo; pull: Pull };
      const diffs = pullFiles(s.repo, s.pull);
      const first = typeof args.first === 'number' ? args.first : diffs.length;
      return diffs.slice(0, Math.max(0, first)).map(
        (diff) =>
          ({
            __type: 'PullRequestChangedFile',
            path: diff.filename,
            additions: diff.additions,
            deletions: diff.deletions,
            changeType: diff.status === 'added' ? 'ADDED' : diff.status === 'removed' ? 'DELETED' : 'MODIFIED',
          }) as Source,
      );
    },
    totalCount: (source) => {
      const s = source as { repo: Repo; pull: Pull };
      return pullFiles(s.repo, s.pull).length;
    },
  },
  PullRequestChangedFile: {
    path: (source) => (source as { path: string }).path,
    additions: (source) => (source as { additions: number }).additions,
    deletions: (source) => (source as { deletions: number }).deletions,
    changeType: (source) => (source as { changeType: string }).changeType,
  },
  PageInfo: {
    hasNextPage: (source) => (source as { hasNextPage: boolean }).hasNextPage,
    hasPreviousPage: () => false,
    startCursor: (source) => (source as { endCursor: string | null }).endCursor,
    endCursor: (source) => (source as { endCursor: string | null }).endCursor,
  },
  CreateIssuePayload: { issue: (source) => (source as { issue: Source }).issue, clientMutationId: () => null },
  CloseIssuePayload: { issue: (source) => (source as { issue: Source }).issue, clientMutationId: () => null },
  CreatePullRequestPayload: {
    pullRequest: (source) => (source as { pullRequest: Source }).pullRequest,
    clientMutationId: () => null,
  },
  MergePullRequestPayload: {
    pullRequest: (source) => (source as { pullRequest: Source }).pullRequest,
    clientMutationId: () => null,
  },
  AddCommentPayload: {
    commentEdge: (source) => (source as { commentEdge: Source }).commentEdge,
    subject: () => null,
    clientMutationId: () => null,
  },
  CommentEdge: {
    node: (source) => (source as { node: Source }).node,
    cursor: (source) => (source as { cursor?: string }).cursor ?? '',
  },
  __Type: {
    name: (source) => (source as { name: string }).name,
    kind: (source) => (ENUM_VALUES[(source as { name: string }).name] ? 'ENUM' : 'OBJECT'),
    fields: (source) => {
      const name = (source as { name: string }).name;
      const fields = OBJECT_FIELDS[name];
      if (!fields) return null;
      return fields.map((fieldName) => ({ __type: '__Field', name: fieldName }) as Source);
    },
    enumValues: (source) => {
      const name = (source as { name: string }).name;
      const values = ENUM_VALUES[name];
      if (!values) return null;
      return values.map((value) => ({ __type: '__EnumValue', name: value }) as Source);
    },
    description: () => null,
    possibleTypes: () => null,
    interfaces: () => [],
    inputFields: () => null,
    ofType: () => null,
    specifiedByURL: () => null,
  },
  __Field: { name: (source) => (source as { name: string }).name, description: () => null },
  __EnumValue: { name: (source) => (source as { name: string }).name, description: () => null },
  __Schema: {
    queryType: () => ({ __type: '__Type', name: 'Query' }) as Source,
    mutationType: () => ({ __type: '__Type', name: 'Mutation' }) as Source,
    subscriptionType: () => null,
  },
  __TypeName: { oid: (source) => (source as { name: string }).name },
};

/* ------------------------------------------------------------ field runner */

function isSource(value: unknown): value is Source {
  return typeof value === 'object' && value !== null && '__type' in (value as Record<string, unknown>);
}

function executeSelection(
  typeName: string,
  source: Source | null,
  selection: SelectionItem[],
  ctx: ExecContext,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const expanded: FieldNode[] = [];
  const expand = (items: SelectionItem[], currentType: string): void => {
    for (const item of items) {
      if (item.kind === 'field') expanded.push(item.field);
      else if (item.kind === 'inlineFragment') {
        if (item.typeCondition === currentType || item.typeCondition === 'Node') expand(item.selection, currentType);
      } else {
        const fragment = ctx.fragments.get(item.name);
        if (fragment && (fragment.typeCondition === currentType || fragment.typeCondition === 'Node')) {
          expand(fragment.selection, currentType);
        }
      }
    }
  };
  expand(selection, typeName);
  const typeResolvers = resolvers[typeName] ?? {};
  for (const field of expanded) {
    const key = field.alias ?? field.name;
    if (field.name === '__typename') {
      out[key] = typeName;
      continue;
    }
    const resolver = typeResolvers[field.name];
    if (!resolver) {
      ctx.errors.push({ message: `Field '${field.name}' doesn't exist on type '${typeName}'` });
      out[key] = null;
      continue;
    }
    let value: unknown;
    try {
      value = resolver(source as Source, evalArgs(field, ctx), ctx);
    } catch (err) {
      ctx.errors.push({ message: err instanceof Error ? err.message : String(err) });
      out[key] = null;
      continue;
    }
    out[key] = completeValue(value, field, ctx);
  }
  return out;
}

function completeValue(value: unknown, field: FieldNode, ctx: ExecContext): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map((item) => completeValue(item, field, ctx));
  if (isSource(value)) {
    if (!field.selection) return {};
    return executeSelection(value.__type, value, field.selection, ctx);
  }
  return value;
}

function executeOperation(operation: Operation, doc: Document, variables: Record<string, unknown>): { data: unknown; errors?: Array<{ message: string }> } {
  const ctx: ExecContext = { variables, fragments: doc.fragments, errors: [] };
  const rootType = operation.type === 'mutation' ? 'Mutation' : 'Query';
  const rootSource = { __type: rootType } as unknown as Source;
  const data = executeSelection(rootType, rootSource, operation.selection, ctx);
  return ctx.errors.length > 0 ? { data, errors: ctx.errors } : { data };
}

/* ---------------------------------------------------------------- handler */

export function handleGraphQL(rawBody: Buffer): Reply {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return { status: 400, json: { errors: [{ message: 'Request body is not valid JSON' }] } };
  }
  const runOne = (entry: unknown): unknown => {
    const record = asRecord(entry);
    const query = str(record.query);
    if (!query) return { errors: [{ message: 'No query document provided' }] };
    const variables = asRecord(record.variables);
    let doc: Document;
    try {
      doc = new Parser(tokenize(query)).parseDocument();
    } catch (err) {
      return { errors: [{ message: err instanceof Error ? err.message : 'Parse error' }] };
    }
    const operationName = str(record.operationName);
    const operation =
      doc.operations.find((candidate) => candidate.name === operationName) ??
      (operationName ? undefined : doc.operations[0]);
    if (!operation) return { errors: [{ message: `Operation '${operationName}' not found` }] };
    return executeOperation(operation, doc, variables);
  };
  if (Array.isArray(parsed)) return jsonReply(200, parsed.map(runOne));
  return jsonReply(200, runOne(parsed));
}

export function graphqlUnauthorized(): Reply {
  return errorReply(401, 'Unauthorized');
}
