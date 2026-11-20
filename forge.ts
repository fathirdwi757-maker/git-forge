// forge.ts — the forge's domain state: the viewer, repositories with their
// object stores and refs, labels, issues, pull requests and comments, plus the
// operations every surface shares (contents writes, three-way merges, global
// ids). Everything is in memory: a trial starts a fresh process, and the same
// store backs the git protocol, REST, GraphQL and MCP so a change made on one
// surface is visible on all the others.

import {
  ObjectStore,
  ZERO_OID,
  buildCommit,
  buildTreeFromFiles,
  collectReachable,
  diffFileMaps,
  flattenTree,
  isAncestor,
  listCommits,
  mergeBase,
  mergeFileMaps,
  parseCommit,
  parseIdent,
  parseTag,
  peelToCommit,
  type FileDiff,
  type FileEntry,
} from './git.ts';

export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_NAME = 'ada iversen';
export const VIEWER_EMAIL = 'adaiversen@example.invalid';
export const DEFAULT_BRANCH = 'main';

/** Deterministic logical clock: every timestamp the forge mints derives from a
 * counter, so two runs over the same operations produce identical objects. */
const EPOCH_BASE = 1767225600; // 2026-01-01T00:00:00Z
let clockSeq = 0;
export function nextTimestamp(): number {
  clockSeq += 1;
  return EPOCH_BASE + clockSeq * 60;
}
export function identFor(timestamp: number): string {
  return `${VIEWER_NAME} <${VIEWER_EMAIL}> ${timestamp} +0000`;
}
export function isoFor(timestamp: number): string {
  return new Date(timestamp * 1000).toISOString();
}

/* ------------------------------------------------------------------- ids */

let repoIdSeq = 700000;
let issueIdSeq = 900000;
let commentIdSeq = 950000;

export function encodeGlobalId(kind: string, key: string): string {
  return Buffer.from(`${kind}:${key}`, 'utf8').toString('base64');
}

export function decodeGlobalId(id: string): { kind: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const split = text.indexOf(':');
    if (split === -1) return null;
    return { kind: text.slice(0, split), key: text.slice(split + 1) };
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ model */

export interface Label {
  name: string;
  color: string;
  description: string | null;
}

export interface Comment {
  id: number;
  body: string;
  createdSeq: number;
}

export interface Issue {
  number: number;
  dbId: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: Comment[];
  createdSeq: number;
}

export interface Pull {
  number: number;
  dbId: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  comments: Comment[];
  createdSeq: number;
}

export class Repo {
  readonly store = new ObjectStore();
  readonly refs = new Map<string, string>();
  readonly labels = new Map<string, Label>();
  readonly issues = new Map<number, Issue>();
  readonly pulls = new Map<number, Pull>();
  readonly dbId: number;
  readonly createdTs: number;
  readonly name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  private numberSeq = 0;
  private seq = 0;

  constructor(name: string, description: string, isPrivate: boolean, defaultBranch: string) {
    this.name = name;
    this.description = description;
    this.isPrivate = isPrivate;
    this.defaultBranch = defaultBranch;
    repoIdSeq += 1;
    this.dbId = repoIdSeq;
    this.createdTs = nextTimestamp();
  }

  nextSeq(): number {
    this.seq += 1;
    return this.seq;
  }

  /** Issues and pull requests share one numbering sequence, as on GitHub. */
  nextNumber(): number {
    this.numberSeq += 1;
    return this.numberSeq;
  }

  headRef(): string {
    return `refs/heads/${this.defaultBranch}`;
  }

  branchTip(branch: string): string | undefined {
    return this.refs.get(`refs/heads/${branch}`);
  }

  resolveRef(ref: string): string | undefined {
    if (this.refs.has(ref)) return this.refs.get(ref);
    if (this.refs.has(`refs/heads/${ref}`)) return this.refs.get(`refs/heads/${ref}`);
    if (this.refs.has(`refs/tags/${ref}`)) return this.refs.get(`refs/tags/${ref}`);
    if (ref === 'HEAD') return this.refs.get(this.headRef());
    if (/^[0-9a-f]{40}$/.test(ref) && this.store.has(ref)) return ref;
    return undefined;
  }

  /** The commit a ref ultimately points at (tags peeled), or undefined. */
  resolveCommit(ref: string): string | undefined {
    const oid = this.resolveRef(ref);
    if (!oid) return undefined;
    return peelToCommit(this.store, oid) ?? undefined;
  }

  treeOfCommit(commitOid: string): string {
    const obj = this.store.get(commitOid);
    if (!obj || obj.type !== 'commit') return ZERO_OID;
    return parseCommit(obj.data).tree;
  }

  filesAt(ref: string): Map<string, FileEntry> | null {
    const commit = this.resolveCommit(ref);
    if (!commit) return null;
    return flattenTree(this.store, this.treeOfCommit(commit));
  }
}

const reposByKey = new Map<string, Repo>();

export function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

export function findRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER_LOGIN) return undefined;
  return reposByKey.get(repoKey(owner, name));
}

export function createRepo(name: string, opts: { description?: string; private?: boolean; defaultBranch?: string }): Repo {
  const repo = new Repo(name, opts.description ?? '', opts.private ?? false, opts.defaultBranch ?? DEFAULT_BRANCH);
  reposByKey.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}

export function deleteRepo(owner: string, name: string): boolean {
  return reposByKey.delete(repoKey(owner, name));
}

export function allRepos(): Repo[] {
  return [...reposByKey.values()].sort((a, b) => a.dbId - b.dbId);
}

/* -------------------------------------------------------------- REST views */

export function repoView(repo: Repo): Record<string, unknown> {
  return {
    id: repo.dbId,
    node_id: encodeGlobalId('Repository', String(repo.dbId)),
    name: repo.name,
    full_name: `${VIEWER_LOGIN}/${repo.name}`,
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    owner: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    html_url: `https://forge.invalid/${VIEWER_LOGIN}/${repo.name}`,
    created_at: isoFor(repo.createdTs),
    updated_at: isoFor(repo.createdTs),
    pushed_at: isoFor(repo.createdTs),
    size: repo.store.objects.size,
    stargazers_count: 0,
    forks_count: 0,
    open_issues_count: [...repo.issues.values()].filter((issue) => issue.state === 'open').length,
    has_issues: true,
    has_projects: false,
    has_wiki: false,
    archived: false,
    disabled: false,
    visibility: repo.isPrivate ? 'private' : 'public',
  };
}

export function viewerView(): Record<string, unknown> {
  return {
    login: VIEWER_LOGIN,
    id: VIEWER_ID,
    node_id: encodeGlobalId('User', String(VIEWER_ID)),
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
    type: 'User',
    site_admin: false,
  };
}

export function labelView(label: Label): Record<string, unknown> {
  return { name: label.name, color: label.color, description: label.description, default: false };
}

export function commentView(repo: Repo, comment: Comment): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: encodeGlobalId('IssueComment', `${repo.dbId}:c${comment.id}`),
    body: comment.body,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: isoFor(EPOCH_BASE + comment.createdSeq * 60),
    updated_at: isoFor(EPOCH_BASE + comment.createdSeq * 60),
  };
}

export function issueView(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.dbId,
    node_id: encodeGlobalId('Issue', `${repo.dbId}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return { name, color: label?.color ?? '000000', description: label?.description ?? null };
    }),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    comments: issue.comments.length,
    created_at: isoFor(EPOCH_BASE + issue.createdSeq * 60),
    updated_at: isoFor(EPOCH_BASE + issue.createdSeq * 60),
    closed_at: issue.state === 'closed' ? isoFor(EPOCH_BASE + issue.createdSeq * 60) : null,
    repository_url: `https://forge.invalid/api/v3/repos/${VIEWER_LOGIN}/${repo.name}`,
  };
}

export function pullView(repo: Repo, pull: Pull): Record<string, unknown> {
  const headSha = repo.branchTip(pull.headRef) ?? ZERO_OID;
  const baseSha = repo.branchTip(pull.baseRef) ?? ZERO_OID;
  return {
    id: pull.dbId,
    node_id: encodeGlobalId('PullRequest', `${repo.dbId}:${pull.number}`),
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: pull.state === 'open' ? computeMergeable(repo, pull) === true : null,
    head: {
      ref: pull.headRef,
      sha: headSha,
      label: `${VIEWER_LOGIN}:${pull.headRef}`,
      repo: repoView(repo),
      user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    },
    base: {
      ref: pull.baseRef,
      sha: baseSha,
      label: `${VIEWER_LOGIN}:${pull.baseRef}`,
      repo: repoView(repo),
      user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: isoFor(EPOCH_BASE + pull.createdSeq * 60),
    updated_at: isoFor(EPOCH_BASE + pull.createdSeq * 60),
    closed_at: pull.state === 'closed' ? isoFor(EPOCH_BASE + pull.createdSeq * 60) : null,
  };
}

export function commitView(repo: Repo, oid: string): Record<string, unknown> {
  const obj = repo.store.get(oid);
  const info = obj && obj.type === 'commit' ? parseCommit(obj.data) : null;
  const author = info ? parseIdent(info.author) : { name: '', email: '', date: isoFor(EPOCH_BASE) };
  const committer = info ? parseIdent(info.committer) : author;
  return {
    sha: oid,
    node_id: encodeGlobalId('Commit', oid),
    commit: {
      message: info?.message ?? '',
      tree: { sha: info?.tree ?? ZERO_OID },
      author: { name: author.name, email: author.email, date: author.date },
      committer: { name: committer.name, email: committer.email, date: committer.date },
      comment_count: 0,
    },
    author: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    committer: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    parents: (info?.parents ?? []).map((parent) => ({ sha: parent })),
  };
}

/* --------------------------------------------------------- issue / PR ops */

export function addIssue(repo: Repo, title: string, body: string, labelNames: string[]): Issue {
  issueIdSeq += 1;
  const issue: Issue = {
    number: repo.nextNumber(),
    dbId: issueIdSeq,
    title,
    body,
    state: 'open',
    labels: [...labelNames],
    comments: [],
    createdSeq: repo.nextSeq(),
  };
  repo.issues.set(issue.number, issue);
  return issue;
}

export function addComment(repo: Repo, issue: Issue, body: string): Comment {
  commentIdSeq += 1;
  const comment: Comment = { id: commentIdSeq, body, createdSeq: repo.nextSeq() };
  issue.comments.push(comment);
  return comment;
}

export function addPull(repo: Repo, title: string, body: string, headRef: string, baseRef: string): Pull {
  issueIdSeq += 1;
  const pull: Pull = {
    number: repo.nextNumber(),
    dbId: issueIdSeq,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    headRef,
    baseRef,
    comments: [],
    createdSeq: repo.nextSeq(),
  };
  repo.pulls.set(pull.number, pull);
  return pull;
}

/** The diff a pull request proposes: merge-base tree against head tree. */
export function pullFiles(repo: Repo, pull: Pull): FileDiff[] {
  const headCommit = repo.resolveCommit(`refs/heads/${pull.headRef}`);
  const baseCommit = repo.resolveCommit(`refs/heads/${pull.baseRef}`);
  if (!headCommit || !baseCommit) return [];
  const base = mergeBase(repo.store, baseCommit, headCommit) ?? baseCommit;
  const before = flattenTree(repo.store, repo.treeOfCommit(base));
  const after = flattenTree(repo.store, repo.treeOfCommit(headCommit));
  return diffFileMaps(repo.store, before, after);
}

/** True when the pull merges cleanly, false on conflict, null when unresolvable. */
export function computeMergeable(repo: Repo, pull: Pull): boolean | null {
  const headCommit = repo.resolveCommit(`refs/heads/${pull.headRef}`);
  const baseCommit = repo.resolveCommit(`refs/heads/${pull.baseRef}`);
  if (!headCommit || !baseCommit) return null;
  const base = mergeBase(repo.store, baseCommit, headCommit);
  if (!base) return null;
  const result = mergeFileMaps(
    flattenTree(repo.store, repo.treeOfCommit(base)),
    flattenTree(repo.store, repo.treeOfCommit(baseCommit)),
    flattenTree(repo.store, repo.treeOfCommit(headCommit)),
  );
  return 'files' in result;
}

export type MergeOutcome = { ok: true; sha: string } | { ok: false; conflict: boolean; message: string };

/** Merge a pull request into its base branch with a real three-way merge. */
export function mergePull(repo: Repo, pull: Pull, method: 'merge' | 'squash' | 'rebase'): MergeOutcome {
  const store = repo.store;
  const headCommit = repo.resolveCommit(`refs/heads/${pull.headRef}`);
  const baseCommit = repo.resolveCommit(`refs/heads/${pull.baseRef}`);
  if (!headCommit || !baseCommit) return { ok: false, conflict: false, message: 'Base or head branch does not exist' };
  const ancestor = mergeBase(store, baseCommit, headCommit);
  if (!ancestor) return { ok: false, conflict: true, message: 'No common ancestor between base and head' };
  const ts = nextTimestamp();
  const ident = identFor(ts);

  const mergeTreesAt = (oursCommit: string, theirsCommit: string, baseAnc: string) =>
    mergeFileMaps(
      flattenTree(store, repo.treeOfCommit(baseAnc)),
      flattenTree(store, repo.treeOfCommit(oursCommit)),
      flattenTree(store, repo.treeOfCommit(theirsCommit)),
    );

  let newTip: string;
  if (method === 'rebase') {
    // Replay each head-only commit, oldest first, onto the moving base tip.
    const headOnly = listCommits(store, headCommit).filter((oid) => !isAncestor(store, oid, baseCommit));
    let tip = baseCommit;
    for (const commitOid of headOnly.reverse()) {
      const info = parseCommit(store.get(commitOid)?.data ?? Buffer.alloc(0));
      const parent = info.parents[0];
      const result = mergeTreesAt(tip, commitOid, parent ?? ancestor);
      if ('conflict' in result) return { ok: false, conflict: true, message: `Conflict in ${result.conflict}` };
      const tree = buildTreeFromFiles(store, result.files);
      const replay = buildCommit({ tree, parents: [tip], author: info.author, committer: ident, message: info.message });
      tip = store.put('commit', replay);
    }
    newTip = tip;
  } else {
    const result = mergeTreesAt(baseCommit, headCommit, ancestor);
    if ('conflict' in result) return { ok: false, conflict: true, message: `Conflict in ${result.conflict}` };
    const tree = buildTreeFromFiles(store, result.files);
    if (method === 'squash') {
      const message = pull.body ? `${pull.title} (#${pull.number})\n\n${pull.body}` : `${pull.title} (#${pull.number})`;
      const data = buildCommit({ tree, parents: [baseCommit], author: ident, committer: ident, message });
      newTip = store.put('commit', data);
    } else {
      const data = buildCommit({
        tree,
        parents: [baseCommit, headCommit],
        author: ident,
        committer: ident,
        message: `Merge pull request #${pull.number} from ${VIEWER_LOGIN}/${pull.headRef}`,
      });
      newTip = store.put('commit', data);
    }
  }

  repo.refs.set(`refs/heads/${pull.baseRef}`, newTip);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = isoFor(ts);
  pull.mergeCommitSha = newTip;
  return { ok: true, sha: newTip };
}

/* ------------------------------------------------------------ contents ops */

export interface ContentWriteResult {
  commitSha: string;
  blobSha: string;
  created: boolean;
}

/**
 * Write one file on a branch (creating the branch from the default branch when
 * it is missing, and the branch's first commit when the repo is unborn),
 * returning the new commit. This is the contents API's write path, shared by
 * REST and the MCP fallback flows that prepare branches.
 */
export function writeFile(
  repo: Repo,
  branch: string,
  path: string,
  content: Buffer,
  message: string,
): ContentWriteResult {
  const store = repo.store;
  const branchRef = `refs/heads/${branch}`;
  let tip = repo.refs.get(branchRef);
  if (!tip) {
    const fallback = repo.refs.get(repo.headRef());
    if (fallback) {
      repo.refs.set(branchRef, fallback);
      tip = fallback;
    }
  }
  const files = tip ? flattenTree(store, repo.treeOfCommit(tip)) : new Map<string, FileEntry>();
  const existing = files.get(path);
  const blobSha = store.put('blob', content);
  files.set(path, { mode: existing?.mode ?? '100644', oid: blobSha });
  const tree = buildTreeFromFiles(store, files);
  const ts = nextTimestamp();
  const ident = identFor(ts);
  const data = buildCommit({
    tree,
    parents: tip ? [tip] : [],
    author: ident,
    committer: ident,
    message,
  });
  const commitSha = store.put('commit', data);
  repo.refs.set(branchRef, commitSha);
  return { commitSha, blobSha, created: !existing };
}

export function deleteFile(repo: Repo, branch: string, path: string, message: string): { commitSha: string } | null {
  const store = repo.store;
  const branchRef = `refs/heads/${branch}`;
  const tip = repo.refs.get(branchRef);
  if (!tip) return null;
  const files = flattenTree(store, repo.treeOfCommit(tip));
  if (!files.has(path)) return null;
  files.delete(path);
  const tree = buildTreeFromFiles(store, files);
  const ts = nextTimestamp();
  const ident = identFor(ts);
  const data = buildCommit({ tree, parents: [tip], author: ident, committer: ident, message });
  const commitSha = store.put('commit', data);
  repo.refs.set(branchRef, commitSha);
  return { commitSha };
}

/** Every object in a repo (used by the REST git endpoints and tests). */
export function repoReachable(repo: Repo): Set<string> {
  return collectReachable(repo.store, repo.refs.values());
}

export { parseTag };
