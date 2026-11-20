// rest.ts — GitHub REST v3 under /api/v3: repositories, branches, commits,
// git refs, the contents API, labels, issues and comments, pull requests with
// files and merges. Every handler works on the shared forge store, so state
// created here is immediately visible to git pushes, GraphQL and MCP.

import { ZERO_OID, flattenTree, listCommits, parseCommit, parseTree } from './git.ts';
import {
  Repo,
  VIEWER_LOGIN,
  addComment,
  addIssue,
  addPull,
  allRepos,
  commentView,
  commitView,
  createRepo,
  deleteFile,
  deleteRepo,
  findRepo,
  issueView,
  labelView,
  mergePull,
  pullFiles,
  pullView,
  repoView,
  viewerView,
  writeFile,
  type Issue,
  type Pull,
} from './forge.ts';
import { asRecord, errorReply, jsonReply, linkHeader, pageSlice, pagination, str, type Reply } from './web.ts';

export interface RestContext {
  method: string;
  /** Path segments after /api/v3, each percent-decoded. */
  segments: string[];
  query: URLSearchParams;
  body: unknown;
  /** The request's own origin, for absolute pagination links. */
  origin: string;
}

const FORGE_VERSION = 'git-forge 1.0.0';

export function routeRest(ctx: RestContext): Reply {
  const { method, segments } = ctx;
  if (segments.length === 0) {
    if (method !== 'GET') return errorReply(404, 'Not Found');
    return jsonReply(200, {
      current_user_url: `${ctx.origin}/api/v3/user`,
      repository_url: `${ctx.origin}/api/v3/repos/${VIEWER_LOGIN}/{repo}`,
      user_repositories_url: `${ctx.origin}/api/v3/user/repos`,
      organization_url: `${ctx.origin}/api/v3/orgs/{org}`,
      emojis_url: `${ctx.origin}/api/v3/emojis`,
      meta_url: `${ctx.origin}/api/v3/meta`,
    });
  }
  if (segments[0] === 'meta' && segments.length === 1) {
    if (method !== 'GET') return errorReply(404, 'Not Found');
    return jsonReply(200, {
      installed_version: FORGE_VERSION,
      git_internal_version: FORGE_VERSION,
      ssh_host_fingerprints: {},
      ssh_key_fingerprints: {},
    });
  }
  if (segments[0] === 'user' && segments.length === 1) {
    if (method !== 'GET') return errorReply(404, 'Not Found');
    return jsonReply(200, viewerView());
  }
  if (segments[0] === 'user' && segments[1] === 'repos' && segments.length === 2) {
    if (method === 'GET') return listUserRepos(ctx);
    if (method === 'POST') return createUserRepo(ctx);
    return errorReply(404, 'Not Found');
  }
  if (segments[0] === 'repos' && segments.length >= 3) {
    const repo = findRepo(segments[1], segments[2]);
    if (!repo) return errorReply(404, 'Not Found');
    return routeRepo(ctx, repo, segments.slice(3));
  }
  return errorReply(404, 'Not Found');
}

function listUserRepos(ctx: RestContext): Reply {
  const { page, perPage } = pagination(ctx.query);
  const repos = allRepos();
  const headers: Record<string, string> = {};
  const link = linkHeader(`${ctx.origin}/api/v3/user/repos`, page, perPage, repos.length);
  if (link) headers.Link = link;
  return jsonReply(200, pageSlice(repos, page, perPage).map(repoView), headers);
}

function createUserRepo(ctx: RestContext): Reply {
  const body = asRecord(ctx.body);
  const name = str(body.name);
  if (!name) return errorReply(422, 'Repository name is required');
  if (findRepo(VIEWER_LOGIN, name)) return errorReply(422, 'name already exists on this account');
  const repo = createRepo(name, {
    description: str(body.description) ?? '',
    private: body.private === true,
    defaultBranch: str(body.default_branch) ?? undefined,
  });
  return jsonReply(201, repoView(repo));
}

function routeRepo(ctx: RestContext, repo: Repo, rest: string[]): Reply {
  const { method } = ctx;
  if (rest.length === 0) {
    if (method === 'GET') return jsonReply(200, repoView(repo));
    if (method === 'PATCH') {
      const body = asRecord(ctx.body);
      const description = str(body.description);
      if (description !== undefined) repo.description = description;
      if (typeof body.private === 'boolean') repo.isPrivate = body.private;
      const defaultBranch = str(body.default_branch);
      if (defaultBranch !== undefined) repo.defaultBranch = defaultBranch;
      return jsonReply(200, repoView(repo));
    }
    if (method === 'DELETE') {
      deleteRepo(VIEWER_LOGIN, repo.name);
      return { status: 204 };
    }
    return errorReply(404, 'Not Found');
  }
  const [head, ...tail] = rest;
  switch (head) {
    case 'branches':
      return routeBranches(ctx, repo, tail);
    case 'commits':
      return routeCommits(ctx, repo, tail);
    case 'git':
      return routeGitRefs(ctx, repo, tail);
    case 'contents':
      return routeContents(ctx, repo, tail);
    case 'labels':
      return routeLabels(ctx, repo, tail);
    case 'issues':
      return routeIssues(ctx, repo, tail);
    case 'pulls':
      return routePulls(ctx, repo, tail);
    default:
      return errorReply(404, 'Not Found');
  }
}

/* --------------------------------------------------------------- branches */

function routeBranches(ctx: RestContext, repo: Repo, tail: string[]): Reply {
  if (ctx.method !== 'GET') return errorReply(404, 'Not Found');
  if (tail.length === 0) {
    const branches = [...repo.refs.entries()]
      .filter(([ref]) => ref.startsWith('refs/heads/'))
      .map(([ref, oid]) => ({
        name: ref.slice('refs/heads/'.length),
        commit: { sha: oid, url: `${ctx.origin}/api/v3/repos/${VIEWER_LOGIN}/${repo.name}/commits/${oid}` },
        protected: false,
      }))
      .sort((a, b) => (a.name < b.name ? -1 : 1));
    return jsonReply(200, branches);
  }
  const branch = tail.join('/');
  const tip = repo.branchTip(branch);
  if (!tip) return errorReply(404, 'Branch not found');
  return jsonReply(200, {
    name: branch,
    commit: commitView(repo, tip),
    protected: false,
    _links: {},
  });
}

/* ---------------------------------------------------------------- commits */

function routeCommits(ctx: RestContext, repo: Repo, tail: string[]): Reply {
  if (ctx.method !== 'GET') return errorReply(404, 'Not Found');
  if (tail.length === 1) {
    const oid = /^[0-9a-f]{40}$/.test(tail[0]) ? tail[0] : undefined;
    const obj = oid ? repo.store.get(oid) : undefined;
    if (!obj || obj.type !== 'commit') return errorReply(404, 'Not Found');
    return jsonReply(200, commitView(repo, oid as string));
  }
  if (tail.length !== 0) return errorReply(404, 'Not Found');
  const shaParam = ctx.query.get('sha') ?? repo.defaultBranch;
  const tip = repo.resolveCommit(shaParam);
  if (!tip) {
    if (repo.refs.size === 0) return errorReply(409, 'Git Repository is empty.');
    return errorReply(404, 'Not Found');
  }
  const { page, perPage } = pagination(ctx.query);
  const commits = listCommits(repo.store, tip);
  return jsonReply(200, pageSlice(commits, page, perPage).map((oid) => commitView(repo, oid)));
}

/* --------------------------------------------------------------- git refs */

function routeGitRefs(ctx: RestContext, repo: Repo, tail: string[]): Reply {
  if (tail[0] === 'refs' && tail.length === 1) {
    if (ctx.method === 'GET') {
      const refs = [...repo.refs.entries()].map(([ref, oid]) => ({
        ref,
        node_id: '',
        url: `${ctx.origin}/api/v3/repos/${VIEWER_LOGIN}/${repo.name}/git/${ref}`,
        object: { sha: oid, type: repo.store.get(oid)?.type ?? 'commit' },
      }));
      return jsonReply(200, refs);
    }
    if (ctx.method === 'POST') {
      const body = asRecord(ctx.body);
      const ref = str(body.ref);
      const sha = str(body.sha);
      if (!ref || !ref.startsWith('refs/')) return errorReply(422, 'A fully qualified ref is required');
      if (!sha || !repo.store.has(sha)) return errorReply(422, 'The sha does not name an object in this repository');
      if (repo.refs.has(ref)) return errorReply(422, 'Reference already exists');
      repo.refs.set(ref, sha);
      return jsonReply(201, {
        ref,
        node_id: '',
        url: `${ctx.origin}/api/v3/repos/${VIEWER_LOGIN}/${repo.name}/git/${ref}`,
        object: { sha, type: repo.store.get(sha)?.type ?? 'commit' },
      });
    }
    return errorReply(404, 'Not Found');
  }
  if (tail[0] === 'refs' && tail.length >= 2 && ctx.method === 'GET') {
    const ref = `refs/${tail.slice(1).join('/')}`;
    const oid = repo.refs.get(ref);
    if (!oid) return errorReply(404, 'Not Found');
    return jsonReply(200, {
      ref,
      node_id: '',
      url: `${ctx.origin}/api/v3/repos/${VIEWER_LOGIN}/${repo.name}/git/${ref}`,
      object: { sha: oid, type: repo.store.get(oid)?.type ?? 'commit' },
    });
  }
  return errorReply(404, 'Not Found');
}

/* --------------------------------------------------------------- contents */

interface TreeLookup {
  kind: 'file' | 'dir' | 'missing';
  oid?: string;
  size?: number;
}

/** Walk a commit's tree to one path, classifying it as a file, a directory or absent. */
function lookupPath(repo: Repo, commitOid: string, path: string): TreeLookup {
  const commit = repo.store.get(commitOid);
  if (!commit || commit.type !== 'commit') return { kind: 'missing' };
  let treeOid = parseCommit(commit.data).tree;
  if (path === '') return { kind: 'dir', oid: treeOid };
  const parts = path.split('/');
  for (let i = 0; i < parts.length; i += 1) {
    const tree = repo.store.get(treeOid);
    if (!tree || tree.type !== 'tree') return { kind: 'missing' };
    const entry = parseTree(tree.data).find((candidate) => candidate.name === parts[i]);
    if (!entry) return { kind: 'missing' };
    if (i === parts.length - 1) {
      if (entry.mode === '40000') return { kind: 'dir', oid: entry.oid };
      const blob = repo.store.get(entry.oid);
      return { kind: 'file', oid: entry.oid, size: blob?.data.length ?? 0 };
    }
    if (entry.mode !== '40000') return { kind: 'missing' };
    treeOid = entry.oid;
  }
  return { kind: 'missing' };
}

function routeContents(ctx: RestContext, repo: Repo, tail: string[]): Reply {
  const path = tail.join('/');
  const body = asRecord(ctx.body);
  if (ctx.method === 'GET') {
    const ref = ctx.query.get('ref') ?? repo.defaultBranch;
    const commit = repo.resolveCommit(ref);
    if (!commit) return errorReply(404, 'Not Found');
    const found = lookupPath(repo, commit, path);
    if (found.kind === 'missing') return errorReply(404, 'Not Found');
    if (found.kind === 'file') {
      const blob = repo.store.get(found.oid as string);
      const content = blob ? blob.data.toString('base64') : '';
      return jsonReply(200, {
        type: 'file',
        encoding: 'base64',
        content,
        sha: found.oid,
        name: path.split('/').pop() ?? path,
        path,
        size: found.size ?? 0,
      });
    }
    // directory listing: direct children only
    const tree = repo.store.get(found.oid as string);
    const entries = tree && tree.type === 'tree' ? parseTree(tree.data) : [];
    const listing = entries.map((entry) => {
      const childPath = path === '' ? entry.name : `${path}/${entry.name}`;
      const isDir = entry.mode === '40000';
      const blob = isDir ? undefined : repo.store.get(entry.oid);
      return {
        type: isDir ? 'dir' : 'file',
        name: entry.name,
        path: childPath,
        sha: entry.oid,
        size: blob?.data.length ?? 0,
      };
    });
    return jsonReply(200, listing);
  }
  if (ctx.method === 'PUT') {
    const message = str(body.message);
    const contentB64 = str(body.content);
    if (message === undefined || contentB64 === undefined) return errorReply(422, 'Both message and content are required');
    if (path === '') return errorReply(422, 'A file path is required');
    const branch = str(body.branch) ?? repo.defaultBranch;
    const tip = repo.branchTip(branch) ?? repo.branchTip(repo.defaultBranch);
    const existing = tip ? flattenTree(repo.store, repo.treeOfCommit(tip)).get(path) : undefined;
    const shaParam = str(body.sha);
    if (existing && shaParam !== undefined && shaParam !== existing.oid) {
      return errorReply(409, 'The sha parameter does not match the current blob');
    }
    if (existing && shaParam === undefined) return errorReply(422, 'The sha parameter is required to update an existing file');
    const content = Buffer.from(contentB64.replace(/\s+/g, ''), 'base64');
    const result = writeFile(repo, branch, path, content, message);
    return jsonReply(result.created ? 201 : 200, {
      content: {
        type: 'file',
        encoding: 'base64',
        sha: result.blobSha,
        name: path.split('/').pop() ?? path,
        path,
        size: content.length,
      },
      commit: { sha: result.commitSha, message },
    });
  }
  if (ctx.method === 'DELETE') {
    const message = str(body.message);
    const shaParam = str(body.sha);
    if (message === undefined || shaParam === undefined) return errorReply(422, 'Both message and sha are required');
    const branch = str(body.branch) ?? repo.defaultBranch;
    const tip = repo.branchTip(branch);
    const existing = tip ? flattenTree(repo.store, repo.treeOfCommit(tip)).get(path) : undefined;
    if (!existing) return errorReply(404, 'Not Found');
    if (shaParam !== existing.oid) return errorReply(409, 'The sha parameter does not match the current blob');
    const result = deleteFile(repo, branch, path, message);
    if (!result) return errorReply(404, 'Not Found');
    return jsonReply(200, { content: null, commit: { sha: result.commitSha, message } });
  }
  return errorReply(404, 'Not Found');
}

/* ----------------------------------------------------------------- labels */

function routeLabels(ctx: RestContext, repo: Repo, tail: string[]): Reply {
  if (tail.length !== 0) return errorReply(404, 'Not Found');
  if (ctx.method === 'GET') return jsonReply(200, [...repo.labels.values()].map(labelView));
  if (ctx.method === 'POST') {
    const body = asRecord(ctx.body);
    const name = str(body.name);
    if (!name) return errorReply(422, 'Label name is required');
    if (repo.labels.has(name)) return errorReply(422, 'Label already exists');
    const color = (str(body.color) ?? '000000').replace(/^#/, '').toLowerCase();
    const label = { name, color, description: str(body.description) ?? null };
    repo.labels.set(name, label);
    return jsonReply(201, labelView(label));
  }
  return errorReply(404, 'Not Found');
}

/* ----------------------------------------------------------------- issues */

function findIssueOrPull(repo: Repo, number: number): { issue?: Issue; pull?: Pull } {
  const issue = repo.issues.get(number);
  if (issue) return { issue };
  const pull = repo.pulls.get(number);
  if (pull) return { pull };
  return {};
}

function routeIssues(ctx: RestContext, repo: Repo, tail: string[]): Reply {
  if (tail.length === 0) {
    if (ctx.method === 'GET') {
      const state = ctx.query.get('state') ?? 'open';
      const sort = ctx.query.get('sort') ?? 'created';
      const direction = ctx.query.get('direction') ?? 'desc';
      let issues = [...repo.issues.values()];
      if (state === 'open' || state === 'closed') issues = issues.filter((issue) => issue.state === state);
      void sort;
      issues.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
      const { page, perPage } = pagination(ctx.query);
      const headers: Record<string, string> = {};
      const link = linkHeader(`${ctx.origin}/api/v3/repos/${VIEWER_LOGIN}/${repo.name}/issues`, page, perPage, issues.length);
      if (link) headers.Link = link;
      return jsonReply(200, pageSlice(issues, page, perPage).map((issue) => issueView(repo, issue)), headers);
    }
    if (ctx.method === 'POST') {
      const body = asRecord(ctx.body);
      const title = str(body.title);
      if (!title) return errorReply(422, 'Issue title is required');
      const labelNames: string[] = [];
      if (Array.isArray(body.labels)) {
        for (const raw of body.labels) {
          const name = typeof raw === 'string' ? raw : str(asRecord(raw).name);
          if (!name) return errorReply(422, 'Invalid label');
          if (!repo.labels.has(name)) return errorReply(422, `Label '${name}' does not exist in this repository`);
          labelNames.push(name);
        }
      }
      const issue = addIssue(repo, title, str(body.body) ?? '', labelNames);
      return jsonReply(201, issueView(repo, issue));
    }
    return errorReply(404, 'Not Found');
  }
  const number = Number(tail[0]);
  if (!Number.isInteger(number) || number < 1) return errorReply(404, 'Not Found');
  const { issue, pull } = findIssueOrPull(repo, number);
  if (tail.length === 1) {
    if (!issue && !pull) return errorReply(404, 'Not Found');
    if (ctx.method === 'GET') {
      if (issue) return jsonReply(200, issueView(repo, issue));
      const asIssue: Issue = {
        number: (pull as Pull).number,
        dbId: (pull as Pull).dbId,
        title: (pull as Pull).title,
        body: (pull as Pull).body,
        state: (pull as Pull).state,
        labels: [],
        comments: (pull as Pull).comments,
        createdSeq: (pull as Pull).createdSeq,
      };
      const view = issueView(repo, asIssue) as Record<string, unknown>;
      view.pull_request = { url: `${ctx.origin}/api/v3/repos/${VIEWER_LOGIN}/${repo.name}/pulls/${number}` };
      return jsonReply(200, view);
    }
    if (ctx.method === 'PATCH') {
      if (!issue) return errorReply(404, 'Not Found');
      const body = asRecord(ctx.body);
      const state = str(body.state);
      if (state === 'open' || state === 'closed') issue.state = state;
      const title = str(body.title);
      if (title !== undefined) issue.title = title;
      const text = str(body.body);
      if (text !== undefined) issue.body = text;
      return jsonReply(200, issueView(repo, issue));
    }
    return errorReply(404, 'Not Found');
  }
  if (tail.length === 2 && tail[1] === 'comments') {
    const target = issue ?? pull;
    if (!target) return errorReply(404, 'Not Found');
    if (ctx.method === 'GET') return jsonReply(200, target.comments.map((comment) => commentView(repo, comment)));
    if (ctx.method === 'POST') {
      const body = asRecord(ctx.body);
      const text = str(body.body);
      if (text === undefined) return errorReply(422, 'Comment body is required');
      const holder: Issue = issue ?? {
        number: (pull as Pull).number,
        dbId: (pull as Pull).dbId,
        title: (pull as Pull).title,
        body: (pull as Pull).body,
        state: (pull as Pull).state,
        labels: [],
        comments: (pull as Pull).comments,
        createdSeq: (pull as Pull).createdSeq,
      };
      const comment = addComment(repo, holder, text);
      if (pull && !issue) (pull as Pull).comments = holder.comments;
      return jsonReply(201, commentView(repo, comment));
    }
    return errorReply(404, 'Not Found');
  }
  return errorReply(404, 'Not Found');
}

/* ------------------------------------------------------------------ pulls */

function normalizeBranchRef(value: string): string {
  let ref = value;
  const colon = ref.indexOf(':');
  if (colon !== -1 && !ref.startsWith('refs/')) ref = ref.slice(colon + 1);
  if (ref.startsWith('refs/heads/')) ref = ref.slice('refs/heads/'.length);
  return ref;
}

function routePulls(ctx: RestContext, repo: Repo, tail: string[]): Reply {
  if (tail.length === 0) {
    if (ctx.method === 'GET') {
      const state = ctx.query.get('state') ?? 'open';
      let pulls = [...repo.pulls.values()];
      if (state === 'open' || state === 'closed') pulls = pulls.filter((pull) => pull.state === state);
      pulls.sort((a, b) => b.number - a.number);
      const { page, perPage } = pagination(ctx.query);
      return jsonReply(200, pageSlice(pulls, page, perPage).map((pull) => pullView(repo, pull)));
    }
    if (ctx.method === 'POST') {
      const body = asRecord(ctx.body);
      const title = str(body.title);
      const headRaw = str(body.head);
      const baseRaw = str(body.base);
      if (!title || !headRaw || !baseRaw) return errorReply(422, 'title, head and base are required');
      const head = normalizeBranchRef(headRaw);
      const base = normalizeBranchRef(baseRaw);
      const headTip = repo.branchTip(head);
      const baseTip = repo.branchTip(base);
      if (!headTip) return errorReply(422, `Head branch '${head}' does not exist`);
      if (!baseTip) return errorReply(422, `Base branch '${base}' does not exist`);
      if (headTip === baseTip) return errorReply(422, 'No commits between base and head');
      const duplicate = [...repo.pulls.values()].some(
        (pull) => pull.state === 'open' && pull.headRef === head && pull.baseRef === base,
      );
      if (duplicate) return errorReply(422, 'A pull request already exists for this head and base');
      const pull = addPull(repo, title, str(body.body) ?? '', head, base);
      return jsonReply(201, pullView(repo, pull));
    }
    return errorReply(404, 'Not Found');
  }
  const number = Number(tail[0]);
  if (!Number.isInteger(number) || number < 1) return errorReply(404, 'Not Found');
  const pull = repo.pulls.get(number);
  if (tail.length === 1) {
    if (ctx.method !== 'GET') return errorReply(404, 'Not Found');
    if (!pull) return errorReply(404, 'Not Found');
    return jsonReply(200, pullView(repo, pull));
  }
  if (tail.length === 2 && tail[1] === 'files' && ctx.method === 'GET') {
    if (!pull) return errorReply(404, 'Not Found');
    const files = pullFiles(repo, pull).map((diff) => ({
      filename: diff.filename,
      status: diff.status,
      additions: diff.additions,
      deletions: diff.deletions,
      changes: diff.changes,
      sha: repo.resolveCommit(`refs/heads/${pull.headRef}`) ?? ZERO_OID,
    }));
    return jsonReply(200, files);
  }
  if (tail.length === 2 && tail[1] === 'merge' && ctx.method === 'PUT') {
    if (!pull) return errorReply(404, 'Not Found');
    if (pull.merged) return errorReply(405, 'Pull Request has already been merged');
    if (pull.state === 'closed') return errorReply(405, 'Pull Request is closed');
    const body = asRecord(ctx.body);
    const methodRaw = str(body.merge_method) ?? 'merge';
    const method = methodRaw === 'squash' ? 'squash' : methodRaw === 'rebase' ? 'rebase' : 'merge';
    const outcome = mergePull(repo, pull, method);
    if (!outcome.ok) {
      return errorReply(405, outcome.conflict ? 'Merge conflict: this pull request cannot be merged automatically' : outcome.message);
    }
    return jsonReply(200, { sha: outcome.sha, merged: true, message: 'Pull Request successfully merged' });
  }
  return errorReply(404, 'Not Found');
}
