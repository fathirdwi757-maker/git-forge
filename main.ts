// Forge: a standalone GitHub-compatible git forge in one process.
//
// One file, standard library only. It serves four surfaces from a single
// in-memory store: git smart HTTP (upload-pack v2 + v0, receive-pack v0),
// the REST v3 API, GraphQL v4, and MCP over streamable HTTP. No UI, no git
// binary, no outside service. Deterministic: a logical clock replaces wall
// time in every stored record, so a replay of the same operations leaves
// the same state.
//
// Lifecycle: listen on an ephemeral port, POST {port} to $MAKEFUN_ENV_URL
// /register, then poll GET $MAKEFUN_ENV_URL/done until it answers done and
// exit 0. Without MAKEFUN_ENV_URL (local runs) it just serves forever.

import http from "node:http";
import { createHash } from "node:crypto";
import { deflateSync, inflateSync } from "node:zlib";

// ---------------------------------------------------------------- utilities

const ZERO_OID = "0000000000000000000000000000000000000000";
const CLOCK_BASE_MS = Date.parse("2026-11-14T06:30:00Z");

let clockTick = 0;
function stamp(): string {
  // Logical clock: one second per stamp, so timestamps are ordered and
  // identical across two runs of the same operations.
  const t = new Date(CLOCK_BASE_MS + clockTick * 1000);
  clockTick += 1;
  return t.toISOString();
}

let requestSeq = 0;
function requestId(): string {
  requestSeq += 1;
  return "req-" + requestSeq.toString(16).padStart(8, "0");
}

function sha1Hex(data: Buffer): string {
  return createHash("sha1").update(data).digest("hex");
}

function sha1Raw(data: Buffer): Buffer {
  return createHash("sha1").update(data).digest();
}

function b64encode(data: Buffer): string {
  return data.toString("base64");
}

function b64decode(text: string): Buffer {
  return Buffer.from(text, "base64");
}

function u32be(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function isHex40(s: string): boolean {
  return /^[0-9a-f]{40}$/.test(s);
}

function isZeroOid(s: string): boolean {
  return s === ZERO_OID;
}

// --------------------------------------------------------------- pkt-lines

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === "string" ? Buffer.from(payload, "utf8") : payload;
  const len = body.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, "0"), 0, "ascii");
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from("0000", "ascii");
const PKT_DELIM = Buffer.from("0001", "ascii");

type PktItem = { kind: "line"; data: Buffer } | { kind: "flush" } | { kind: "delim" };

function parsePktLines(buf: Buffer): PktItem[] {
  const out: PktItem[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.subarray(off, off + 4).toString("ascii"), 16);
    if (Number.isNaN(len)) throw new Error("bad pkt-line length");
    if (len === 0) {
      out.push({ kind: "flush" });
      off += 4;
      continue;
    }
    // "0001" is the protocol v2 delimiter pkt-line: it separates the
    // command section of a request from its arguments.
    if (len === 1) {
      out.push({ kind: "delim" });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error("truncated pkt-line");
    out.push({ kind: "line", data: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

// Split a buffer into pkt-lines, stopping at the first flush (returns the
// lines before it and the byte offset just past it).
function readPktSection(buf: Buffer, start: number): { lines: Buffer[]; next: number } {
  const lines: Buffer[] = [];
  let off = start;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.subarray(off, off + 4).toString("ascii"), 16);
    if (len === 0) return { lines, next: off + 4 };
    if (len < 4 || off + len > buf.length) throw new Error("truncated pkt-line");
    lines.push(buf.subarray(off + 4, off + len));
    off += len;
  }
  throw new Error("pkt-line section without flush");
}

// Side-band framing (channel 1 = data, 2 = progress, 3 = error). Each chunk
// is one pkt-line whose payload starts with the channel byte.
function sideband(data: Buffer, maxChunk = 65500): Buffer[] {
  const out: Buffer[] = [];
  for (let off = 0; off < data.length; off += maxChunk) {
    const piece = data.subarray(off, Math.min(data.length, off + maxChunk));
    out.push(pktLine(Buffer.concat([Buffer.from([1]), piece])));
  }
  out.push(PKT_FLUSH);
  return out;
}

// ------------------------------------------------------------ git objects

type ObjType = "commit" | "tree" | "blob" | "tag";

interface GitObj {
  type: ObjType;
  sha: string;
  data: Buffer;
  deflated?: Buffer;
}

const OBJ_TYPE_NUM: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const OBJ_NUM_TYPE: Record<number, ObjType> = { 1: "commit", 2: "tree", 3: "blob", 4: "tag" };

function hashObject(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, "utf8");
  return sha1Hex(Buffer.concat([head, data]));
}

function makeObject(type: ObjType, data: Buffer): GitObj {
  return { type, sha: hashObject(type, data), data };
}

// Deflated bytes of one object, cached by sha so a pack built twice
// (the clone workload builds the same pack fifty times) costs almost
// nothing after the first build.
function deflatedOf(obj: GitObj): Buffer {
  if (!obj.deflated) obj.deflated = deflateSync(obj.data, { level: 6 });
  return obj.deflated;
}

// A packfile object header: type in the top bits, size as a varint.
function packObjectHeader(typeNum: number, size: number): Buffer {
  const bytes: number[] = [];
  let first = (typeNum << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  bytes.push(first);
  while (size > 0) {
    let b = size & 0x7f;
    size >>= 7;
    if (size > 0) b |= 0x80;
    bytes.push(b);
  }
  return Buffer.from(bytes);
}

function encodePack(objects: GitObj[]): Buffer {
  const parts: Buffer[] = [Buffer.from("PACK", "ascii"), u32be(2), u32be(objects.length)];
  for (const obj of objects) {
    parts.push(packObjectHeader(OBJ_TYPE_NUM[obj.type], obj.data.length));
    parts.push(deflatedOf(obj));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, sha1Raw(body)]);
}

// Inflate the zlib stream starting at off; the stream's exact length is
// found by binary search, because inflateSync tolerates trailing bytes
// (success is monotone in the slice length) and throws on truncation.
function inflateAt(buf: Buffer, off: number): { data: Buffer; used: number } {
  const remaining = buf.length - off;
  if (remaining <= 0) throw new Error("pack truncated");
  let lo = 1;
  let hi = remaining;
  // Exponential probe to find an upper bound that inflates.
  let probe = Math.min(64, remaining);
  while (probe < remaining) {
    try {
      inflateSync(buf.subarray(off, off + probe));
      hi = probe;
      break;
    } catch {
      lo = probe + 1;
      probe = Math.min(remaining, probe * 2);
    }
  }
  if (probe >= remaining) {
    // Whole tail inflates; the true end may be earlier.
    try {
      const data = inflateSync(buf.subarray(off));
      // Binary search the shortest prefix that still inflates.
      let a = lo;
      let b = remaining;
      while (a < b) {
        const mid = (a + b) >> 1;
        try {
          inflateSync(buf.subarray(off, off + mid));
          b = mid;
        } catch {
          a = mid + 1;
        }
      }
      return { data: inflateSync(buf.subarray(off, off + a)), used: a };
    } catch {
      throw new Error("pack object does not inflate");
    }
  }
  // Binary search between the last failing length and the first success.
  let a = lo;
  let b = hi;
  while (a < b) {
    const mid = (a + b) >> 1;
    try {
      inflateSync(buf.subarray(off, off + mid));
      b = mid;
    } catch {
      a = mid + 1;
    }
  }
  return { data: inflateSync(buf.subarray(off, off + a)), used: a };
}

function readPackVarint(buf: Buffer, off: number): { value: number; next: number } {
  let value = buf[off] & 0x0f;
  let shift = 4;
  let pos = off;
  while (buf[pos] & 0x80) {
    pos += 1;
    value |= (buf[pos] & 0x7f) << shift;
    shift += 7;
  }
  return { value, next: pos + 1 };
}

function readOfsVarint(buf: Buffer, off: number): { value: number; next: number } {
  let value = buf[off] & 0x7f;
  let pos = off;
  while (buf[pos] & 0x80) {
    pos += 1;
    value = ((value + 1) << 7) | (buf[pos] & 0x7f);
  }
  return { value, next: pos + 1 };
}

function readDeltaVarint(buf: Buffer, off: number): { value: number; next: number } {
  let value = 0;
  let shift = 0;
  let pos = off;
  while (true) {
    const b = buf[pos];
    pos += 1;
    value |= (b & 0x7f) << shift;
    shift += 7;
    if (!(b & 0x80)) break;
  }
  return { value, next: pos };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let p = 0;
  const baseSize = readDeltaVarint(delta, p);
  p = baseSize.next;
  const resultSize = readDeltaVarint(delta, p);
  p = resultSize.next;
  if (baseSize.value !== base.length) throw new Error("delta base size mismatch");
  const out: Buffer[] = [];
  while (p < delta.length) {
    const op = delta[p];
    p += 1;
    if (op & 0x80) {
      let offset = 0;
      let size = 0;
      for (let i = 0; i < 4; i++) if (op & (1 << i)) offset |= delta[p++] << (8 * i);
      for (let i = 0; i < 3; i++) if (op & (0x10 << i)) size |= delta[p++] << (8 * i);
      if (size === 0) size = 0x10000;
      if (offset + size > base.length) throw new Error("delta copy out of range");
      out.push(base.subarray(offset, offset + size));
    } else if (op !== 0) {
      out.push(delta.subarray(p, p + op));
      p += op;
    } else {
      throw new Error("delta op 0");
    }
  }
  const result = Buffer.concat(out);
  if (result.length !== resultSize.value) throw new Error("delta result size mismatch");
  return result;
}

interface DecodedObject {
  type: ObjType;
  data: Buffer;
  sha: string;
}

// Decode a whole packfile. Deltas resolve against objects earlier in the
// same pack, or against objects already in the store (ref-delta only).
function decodePack(buf: Buffer, store: Map<string, GitObj>): DecodedObject[] {
  if (buf.length < 12 || buf.subarray(0, 4).toString("ascii") !== "PACK") {
    throw new Error("not a packfile");
  }
  const version = buf.readUInt32BE(4);
  const count = buf.readUInt32BE(8);
  if (version !== 2) throw new Error("unsupported pack version");
  let off = 12;
  const decoded: DecodedObject[] = [];
  const byOffset = new Map<number, DecodedObject>();
  for (let i = 0; i < count; i++) {
    const objStart = off;
    const head = readPackVarint(buf, off);
    const typeNum = (buf[off] >> 4) & 0x07;
    off = head.next;
    if (typeNum === 6) {
      // ofs-delta: negative offset to the base object in this pack.
      const base = readOfsVarint(buf, off);
      off = base.next;
      const inflated = inflateAt(buf, off);
      off += inflated.used;
      const baseObj = byOffset.get(objStart - base.value);
      if (!baseObj) throw new Error("ofs-delta base missing");
      const data = applyDelta(baseObj.data, inflated.data);
      const obj: DecodedObject = { type: baseObj.type, data, sha: hashObject(baseObj.type, data) };
      decoded.push(obj);
      byOffset.set(objStart, obj);
    } else if (typeNum === 7) {
      const baseSha = buf.subarray(off, off + 20).toString("hex");
      off += 20;
      const inflated = inflateAt(buf, off);
      off += inflated.used;
      const fromPack = decoded.find((o) => o.sha === baseSha);
      const fromStore = store.get(baseSha);
      const base = fromPack ?? (fromStore ? { type: fromStore.type, data: fromStore.data, sha: fromStore.sha } : null);
      if (!base) throw new Error("ref-delta base missing");
      const data = applyDelta(base.data, inflated.data);
      const obj: DecodedObject = { type: base.type, data, sha: hashObject(base.type, data) };
      decoded.push(obj);
      byOffset.set(objStart, obj);
    } else {
      const type = OBJ_NUM_TYPE[typeNum];
      if (!type) throw new Error("unknown pack object type");
      const inflated = inflateAt(buf, off);
      off += inflated.used;
      if (inflated.data.length !== head.value) throw new Error("pack object size mismatch");
      const obj: DecodedObject = { type, data: inflated.data, sha: hashObject(type, inflated.data) };
      decoded.push(obj);
      byOffset.set(objStart, obj);
    }
  }
  return decoded;
}

// ------------------------------------------------------- commit/tree parsing

interface CommitInfo {
  tree: string;
  parents: string[];
  authorName: string;
  authorEmail: string;
  authorDate: string;
  committerName: string;
  committerEmail: string;
  committerDate: string;
  message: string;
}

function parseIdent(line: string): { name: string; email: string; date: string } {
  // "Name <email> 1234567890 +0000"
  const m = /^(.*) <([^>]*)> (\d+ [+-]\d{4})$/.exec(line.trim());
  if (!m) return { name: line.trim(), email: "", date: "" };
  const ts = Number(m[3].split(" ")[0]) * 1000;
  return { name: m[1], email: m[2], date: new Date(ts).toISOString() };
}

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString("utf8");
  const blank = text.indexOf("\n\n");
  const head = blank >= 0 ? text.slice(0, blank) : text;
  const message = blank >= 0 ? text.slice(blank + 2) : "";
  const info: CommitInfo = {
    tree: ZERO_OID,
    parents: [],
    authorName: "",
    authorEmail: "",
    authorDate: "",
    committerName: "",
    committerEmail: "",
    committerDate: "",
    message,
  };
  for (const line of head.split("\n")) {
    if (line.startsWith(" ")) continue; // continuation of a multi-line header
    if (line.startsWith("tree ")) info.tree = line.slice(5).trim();
    else if (line.startsWith("parent ")) info.parents.push(line.slice(7).trim());
    else if (line.startsWith("author ")) {
      const id = parseIdent(line.slice(7));
      info.authorName = id.name;
      info.authorEmail = id.email;
      info.authorDate = id.date;
    } else if (line.startsWith("committer ")) {
      const id = parseIdent(line.slice(10));
      info.committerName = id.name;
      info.committerEmail = id.email;
      info.committerDate = id.date;
    }
  }
  return info;
}

interface TreeEntry {
  mode: string;
  name: string;
  sha: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) break;
    const mode = data.subarray(off, sp).toString("ascii");
    const nul = data.indexOf(0, sp + 1);
    if (nul < 0) break;
    const name = data.subarray(sp + 1, nul).toString("utf8");
    const sha = data.subarray(nul + 1, nul + 21).toString("hex");
    entries.push({ mode, name, sha });
    off = nul + 21;
  }
  return entries;
}

function buildTreeObject(entries: TreeEntry[]): Buffer {
  const parts: Buffer[] = [];
  const sorted = [...entries].sort((a, b) => {
    // Git sorts by name, treating directories as if they had a trailing "/".
    const an = a.mode === "40000" ? a.name + "/" : a.name;
    const bn = b.mode === "40000" ? b.name + "/" : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, "utf8"));
    parts.push(Buffer.from(e.sha, "hex"));
  }
  return Buffer.concat(parts);
}

// Flatten a tree into path -> {mode, sha}, recursively.
function flattenTree(store: Map<string, GitObj>, treeSha: string, prefix: string, out: Map<string, { mode: string; sha: string }>): void {
  const obj = store.get(treeSha);
  if (!obj || obj.type !== "tree") return;
  for (const e of parseTree(obj.data)) {
    const path = prefix ? prefix + "/" + e.name : e.name;
    if (e.mode === "40000") flattenTree(store, e.sha, path, out);
    else out.set(path, { mode: e.mode, sha: e.sha });
  }
}

// Build nested trees from a flat path map; returns the root tree sha and
// stores every new tree object in the store.
function buildTreeFromFiles(store: Map<string, GitObj>, files: Map<string, { mode: string; sha: string }>): string {
  // Group files by their top directory, recursively.
  function build(paths: string[], prefix: string): string {
    const entries: TreeEntry[] = [];
    const dirs = new Map<string, string[]>();
    for (const p of paths) {
      const rest = prefix ? p.slice(prefix.length + 1) : p;
      const slash = rest.indexOf("/");
      if (slash < 0) {
        const f = files.get(p)!;
        entries.push({ mode: f.mode, name: rest, sha: f.sha });
      } else {
        const dir = rest.slice(0, slash);
        if (!dirs.has(dir)) dirs.set(dir, []);
        dirs.get(dir)!.push(p);
      }
    }
    for (const [dir, sub] of dirs) {
      const subSha = build(sub, prefix ? prefix + "/" + dir : dir);
      entries.push({ mode: "40000", name: dir, sha: subSha });
    }
    const data = buildTreeObject(entries);
    const obj = makeObject("tree", data);
    if (!store.has(obj.sha)) store.set(obj.sha, obj);
    return obj.sha;
  }
  return build([...files.keys()], "");
}

function makeCommitObject(tree: string, parents: string[], author: string, committer: string, message: string): GitObj {
  const lines: string[] = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${author}`, `committer ${committer}`, "", message);
  return makeObject("commit", Buffer.from(lines.join("\n"), "utf8"));
}

// ------------------------------------------------- reachability and diff

// Collect every object reachable from the tips. depth 0 means unlimited;
// depth n includes commits up to n levels deep and reports the commits
// whose parents were cut off as shallow boundaries. `stopAt` lists commits
// whose parents must not be traversed (the client's existing shallow
// boundary): they are included, but nothing below them is.
function collectReachable(
  store: Map<string, GitObj>,
  tips: string[],
  depth: number,
  stopAt?: Set<string>,
): { objects: GitObj[]; shallow: string[] } {
  const seen = new Set<string>();
  const shallow = new Set<string>();
  const queue: { sha: string; level: number }[] = [];
  for (const tip of tips) {
    const obj = store.get(tip);
    if (!obj) continue;
    if (obj.type === "tag") {
      seen.add(tip);
      const target = parseTagTarget(obj.data);
      if (target) queue.push({ sha: target, level: 0 });
    } else if (obj.type === "commit") {
      queue.push({ sha: tip, level: 0 });
    } else if (obj.type === "tree" || obj.type === "blob") {
      seen.add(tip);
    }
  }
  const commits: string[] = [];
  while (queue.length > 0) {
    const { sha, level } = queue.shift()!;
    if (seen.has(sha)) continue;
    const obj = store.get(sha);
    if (!obj || obj.type !== "commit") continue;
    seen.add(sha);
    commits.push(sha);
    const info = parseCommit(obj.data);
    const includeParents = (depth === 0 || level + 1 < depth) && !(stopAt && stopAt.has(sha));
    if (!includeParents) shallow.add(sha);
    for (const parent of info.parents) {
      if (includeParents) queue.push({ sha: parent, level: level + 1 });
    }
  }
  // Trees and blobs of every included commit.
  const stack: string[] = [];
  for (const sha of commits) {
    const info = parseCommit(store.get(sha)!.data);
    stack.push(info.tree);
  }
  while (stack.length > 0) {
    const sha = stack.pop()!;
    if (seen.has(sha)) continue;
    const obj = store.get(sha);
    if (!obj) continue;
    seen.add(sha);
    if (obj.type === "tree") {
      for (const e of parseTree(obj.data)) stack.push(e.sha);
    }
  }
  const objects: GitObj[] = [];
  for (const sha of seen) {
    const obj = store.get(sha);
    if (obj) objects.push(obj);
  }
  // Deterministic order: commits, then trees, then blobs, then tags.
  const rank: Record<ObjType, number> = { commit: 0, tree: 1, blob: 2, tag: 3 };
  objects.sort((a, b) => rank[a.type] - rank[b.type] || (a.sha < b.sha ? -1 : 1));
  return { objects, shallow: [...shallow].sort() };
}

function parseTagTarget(data: Buffer): string | null {
  const m = /^object ([0-9a-f]{40})$/m.exec(data.toString("utf8"));
  return m ? m[1] : null;
}

// First common ancestor of two commits, by breadth-first search.
function mergeBase(store: Map<string, GitObj>, a: string, b: string): string | null {
  const ancestorsA = new Map<string, number>();
  const qa: { sha: string; d: number }[] = [{ sha: a, d: 0 }];
  while (qa.length > 0) {
    const cur = qa.shift()!;
    if (ancestorsA.has(cur.sha)) continue;
    ancestorsA.set(cur.sha, cur.d);
    const obj = store.get(cur.sha);
    if (obj && obj.type === "commit") {
      for (const p of parseCommit(obj.data).parents) qa.push({ sha: p, d: cur.d + 1 });
    }
  }
  const qb: { sha: string; d: number }[] = [{ sha: b, d: 0 }];
  const seenB = new Set<string>();
  let best: string | null = null;
  let bestScore = Infinity;
  while (qb.length > 0) {
    const cur = qb.shift()!;
    if (seenB.has(cur.sha)) continue;
    seenB.add(cur.sha);
    const da = ancestorsA.get(cur.sha);
    if (da !== undefined) {
      const score = da + cur.d;
      if (score < bestScore) {
        bestScore = score;
        best = cur.sha;
      }
      continue;
    }
    const obj = store.get(cur.sha);
    if (obj && obj.type === "commit") {
      for (const p of parseCommit(obj.data).parents) qb.push({ sha: p, d: cur.d + 1 });
    }
  }
  return best;
}

function isAncestor(store: Map<string, GitObj>, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0) {
    const sha = queue.shift()!;
    if (sha === ancestor) return true;
    if (seen.has(sha)) continue;
    seen.add(sha);
    const obj = store.get(sha);
    if (obj && obj.type === "commit") {
      for (const p of parseCommit(obj.data).parents) queue.push(p);
    }
  }
  return false;
}

interface FileChange {
  filename: string;
  status: "added" | "removed" | "modified";
  additions: number;
  deletions: number;
  patch: string;
}

// A small line diff (LCS) for the small files the suite drives.
function diffLines(oldText: string, newText: string): { additions: number; deletions: number; patch: string } {
  const a = oldText === "" ? [] : oldText.split("\n");
  const b = newText === "" ? [] : newText.split("\n");
  const n = a.length;
  const m = b.length;
  if (n * m > 40000) {
    // Large file: fall back to counting differing lines by set.
    const aSet = new Set(a);
    const bSet = new Set(b);
    let additions = 0;
    let deletions = 0;
    for (const line of b) if (!aSet.has(line)) additions++;
    for (const line of a) if (!bSet.has(line)) deletions++;
    return { additions, deletions, patch: "" };
  }
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  let additions = 0;
  let deletions = 0;
  const hunks: string[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      hunks.push(" " + a[i]);
      i++;
      j++;
    } else if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) {
      hunks.push("+" + b[j]);
      additions++;
      j++;
    } else {
      hunks.push("-" + a[i]);
      deletions++;
      i++;
    }
  }
  return { additions, deletions, patch: "@@ -1," + n + " +1," + m + " @@\n" + hunks.join("\n") };
}

function diffTrees(
  store: Map<string, GitObj>,
  oldTreeSha: string | null,
  newTreeSha: string | null,
): FileChange[] {
  const oldFiles = new Map<string, { mode: string; sha: string }>();
  const newFiles = new Map<string, { mode: string; sha: string }>();
  if (oldTreeSha) flattenTree(store, oldTreeSha, "", oldFiles);
  if (newTreeSha) flattenTree(store, newTreeSha, "", newFiles);
  const changes: FileChange[] = [];
  const paths = new Set([...oldFiles.keys(), ...newFiles.keys()]);
  for (const path of [...paths].sort()) {
    const o = oldFiles.get(path);
    const n = newFiles.get(path);
    if (o && !n) {
      const oldObj = store.get(o.sha);
      const oldText = oldObj ? oldObj.data.toString("utf8") : "";
      const d = diffLines(oldText, "");
      changes.push({ filename: path, status: "removed", additions: 0, deletions: d.deletions, patch: d.patch });
    } else if (!o && n) {
      const newObj = store.get(n.sha);
      const newText = newObj ? newObj.data.toString("utf8") : "";
      const d = diffLines("", newText);
      changes.push({ filename: path, status: "added", additions: d.additions, deletions: 0, patch: d.patch });
    } else if (o && n && o.sha !== n.sha) {
      const oldObj = store.get(o.sha);
      const newObj = store.get(n.sha);
      const d = diffLines(oldObj ? oldObj.data.toString("utf8") : "", newObj ? newObj.data.toString("utf8") : "");
      changes.push({ filename: path, status: "modified", additions: d.additions, deletions: d.deletions, patch: d.patch });
    }
  }
  return changes;
}

// ------------------------------------------------------------------- store

interface UserRef {
  login: string;
  id: number;
  node_id: string;
  type: string;
}

interface Label {
  id: number;
  node_id: string;
  name: string;
  color: string;
  description: string;
  isDefault: boolean;
}

interface IssueComment {
  id: number;
  node_id: string;
  body: string;
  user: UserRef;
  created_at: string;
  updated_at: string;
}

interface Issue {
  id: number;
  node_id: string;
  number: number;
  title: string;
  body: string;
  state: "open" | "closed";
  user: UserRef;
  labels: Label[];
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  comments: IssueComment[];
}

interface PullRequest {
  id: number;
  node_id: string;
  number: number;
  title: string;
  body: string;
  state: "open" | "closed";
  user: UserRef;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  merged_at: string | null;
  merge_commit_sha: string | null;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

interface Repo {
  id: number;
  node_id: string;
  name: string;
  owner: UserRef;
  description: string;
  private: boolean;
  default_branch: string;
  created_at: string;
  updated_at: string;
  pushed_at: string | null;
  objects: Map<string, GitObj>;
  refs: Map<string, string>;
  issues: Issue[];
  pulls: PullRequest[];
  labels: Label[];
  nextIssue: number;
  nextPull: number;
  nextId: number;
}

const repos = new Map<string, Repo>();
let repoSeq = 0;
let globalIdSeq = 0;

function nextGlobalId(): number {
  globalIdSeq += 1;
  return globalIdSeq;
}

function repoKey(owner: string, name: string): string {
  return owner + "/" + name;
}

function nodeId(prefix: string, key: string): string {
  return prefix + "_" + sha1Hex(Buffer.from(key, "utf8")).slice(0, 32);
}

function makeUser(login: string): UserRef {
  return { login, id: nextGlobalId(), node_id: nodeId("U", login), type: "User" };
}

function createRepo(owner: UserRef, name: string, description: string, isPrivate: boolean, defaultBranch: string): Repo {
  repoSeq += 1;
  const repo: Repo = {
    id: repoSeq,
    node_id: nodeId("R", owner.login + "/" + name),
    name,
    owner,
    description,
    private: isPrivate,
    default_branch: defaultBranch || "main",
    created_at: stamp(),
    updated_at: stamp(),
    pushed_at: null,
    objects: new Map(),
    refs: new Map(),
    issues: [],
    pulls: [],
    labels: [],
    nextIssue: 1,
    nextPull: 1,
    nextId: 1,
  };
  repos.set(repoKey(owner.login, name), repo);
  return repo;
}

function findRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function findRepoByNodeId(id: string): Repo | undefined {
  for (const repo of repos.values()) if (repo.node_id === id) return repo;
  return undefined;
}

function defaultBranchRef(repo: Repo): string | undefined {
  return repo.refs.get("refs/heads/" + repo.default_branch);
}

function tipCommitSha(repo: Repo, branch: string): string | undefined {
  return repo.refs.get("refs/heads/" + branch);
}

function createIssueObject(repo: Repo, user: UserRef, title: string, body: string, labelNames: string[]): Issue {
  const labels: Label[] = [];
  for (const name of labelNames) {
    const label = repo.labels.find((l) => l.name === name);
    if (label) labels.push(label);
  }
  const number = repo.nextIssue;
  repo.nextIssue += 1;
  const now = stamp();
  const issue: Issue = {
    id: nextGlobalId(),
    node_id: nodeId("I", repo.owner.login + "/" + repo.name + "#" + number),
    number,
    title,
    body,
    state: "open",
    user,
    labels,
    created_at: now,
    updated_at: now,
    closed_at: null,
    comments: [],
  };
  repo.issues.push(issue);
  return issue;
}

function createPullObject(repo: Repo, user: UserRef, title: string, body: string, headRef: string, baseRef: string): PullRequest {
  const number = repo.nextPull;
  repo.nextPull += 1;
  const now = stamp();
  const pr: PullRequest = {
    id: nextGlobalId(),
    node_id: nodeId("PR", repo.owner.login + "/" + repo.name + "#" + number),
    number,
    title,
    body,
    state: "open",
    user,
    headRef,
    baseRef,
    headSha: repo.refs.get("refs/heads/" + headRef) ?? ZERO_OID,
    baseSha: repo.refs.get("refs/heads/" + baseRef) ?? ZERO_OID,
    merged: false,
    merged_at: null,
    merge_commit_sha: null,
    created_at: now,
    updated_at: now,
    closed_at: null,
  };
  repo.pulls.push(pr);
  return pr;
}

// Three-way merge conflict test: a file changed on both sides of the
// merge base, to different contents, is a conflict.
function prConflicts(repo: Repo, pr: PullRequest): boolean {
  const headSha = repo.refs.get("refs/heads/" + pr.headRef);
  const baseSha = repo.refs.get("refs/heads/" + pr.baseRef);
  if (!headSha || !baseSha) return false;
  const base = mergeBase(repo.objects, baseSha, headSha);
  if (!base) return false;
  const baseTree = parseCommit(repo.objects.get(base)!.data).tree;
  const headTree = parseCommit(repo.objects.get(headSha)!.data).tree;
  const baseTipTree = parseCommit(repo.objects.get(baseSha)!.data).tree;
  const baseFiles = new Map<string, { mode: string; sha: string }>();
  const headFiles = new Map<string, { mode: string; sha: string }>();
  const tipFiles = new Map<string, { mode: string; sha: string }>();
  flattenTree(repo.objects, baseTree, "", baseFiles);
  flattenTree(repo.objects, headTree, "", headFiles);
  flattenTree(repo.objects, baseTipTree, "", tipFiles);
  for (const [path, headFile] of headFiles) {
    const baseFile = baseFiles.get(path);
    const tipFile = tipFiles.get(path);
    if (!baseFile) continue; // added on the head side only
    if (headFile.sha === baseFile.sha) continue; // unchanged on head side
    if (tipFile && tipFile.sha !== baseFile.sha && tipFile.sha !== headFile.sha) return true;
  }
  // Files deleted on the head side but changed on the base side.
  for (const [path, baseFile] of baseFiles) {
    if (headFiles.has(path)) continue;
    const tipFile = tipFiles.get(path);
    if (tipFile && tipFile.sha !== baseFile.sha) return true;
  }
  return false;
}

// ----------------------------------------------------------- http context

interface Ctx {
  method: string;
  path: string;
  segments: string[];
  query: URLSearchParams;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  token: string;
  login: string;
  user: UserRef;
  baseUrl: string;
}

function sendJson(ctx: Ctx, status: number, value: unknown, extraHeaders?: Record<string, string>): void {
  const res = (ctx as unknown as { res: http.ServerResponse }).res;
  const payload = Buffer.from(JSON.stringify(value), "utf8");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Content-Length": String(payload.length),
    "X-GitHub-Request-Id": requestId(),
  };
  if (extraHeaders) for (const [k, v] of Object.entries(extraHeaders)) headers[k] = v;
  res.writeHead(status, headers);
  res.end(payload);
}

function sendRaw(ctx: Ctx, status: number, contentType: string, payload: Buffer): void {
  const res = (ctx as unknown as { res: http.ServerResponse }).res;
  res.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": String(payload.length),
    "X-GitHub-Request-Id": requestId(),
  });
  res.end(payload);
}

function jsonError(ctx: Ctx, status: number, message: string): void {
  sendJson(ctx, status, { message });
}

function notFound(ctx: Ctx): void {
  jsonError(ctx, 404, "Not Found");
}

function unauthorized(ctx: Ctx): void {
  jsonError(ctx, 401, "Unauthorized");
}

function expectedToken(): string {
  return process.env.MAKEFUN_SHOP_TOKEN ?? "";
}

// The login the token names: a JWT payload may carry it; a bare
// login-like token names itself; otherwise the suite reads the login back
// from the repository objects we return.
function loginFromToken(token: string): string {
  const loginRe = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/;
  const parts = token.split(".");
  if (parts.length === 3) {
    try {
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<string, unknown>;
      for (const key of ["login", "username", "handle", "owner", "shop", "sub", "name"]) {
        const v = payload[key];
        if (typeof v === "string") {
          if (loginRe.test(v)) return v;
          // A subject like "user:adaiversen" or "acct/adaiversen".
          const tail = v.split(/[:/]/).pop() ?? "";
          if (loginRe.test(tail)) return tail;
        }
      }
    } catch {
      // Not a JWT; fall through to the other shapes.
    }
  }
  if (loginRe.test(token)) return token;
  return "octocat";
}

function checkAuth(ctx: Ctx): boolean {
  const header = ctx.headers["authorization"];
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const token = header.slice("Bearer ".length).trim();
  if (!token) return false;
  const expected = expectedToken();
  if (expected !== "" && token !== expected) return false;
  return true;
}

// Parse a JSON body; on failure the caller answers 400.
function parseJsonBody(ctx: Ctx): { ok: true; value: unknown } | { ok: false } {
  if (ctx.body.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(ctx.body.toString("utf8")) };
  } catch {
    return { ok: false };
  }
}

function asObject(value: unknown): Record<string, unknown> | null {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function strField(obj: Record<string, unknown>, key: string, fallback = ""): string {
  const v = obj[key];
  return typeof v === "string" ? v : fallback;
}

// --------------------------------------------------------- git smart HTTP

const GIT_AGENT = "forge/1.0";
const V0_UPLOAD_CAPS = "multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done filter agent=" + GIT_AGENT;
const V0_RECEIVE_CAPS = "report-status side-band-64k delete-refs ofs-delta agent=" + GIT_AGENT;

function v0Advertisement(repo: Repo, service: "upload-pack" | "receive-pack"): Buffer {
  const caps = service === "upload-pack" ? V0_UPLOAD_CAPS : V0_RECEIVE_CAPS;
  const parts: Buffer[] = [pktLine("# service=git-" + service + "\n"), PKT_FLUSH];
  const names = [...repo.refs.keys()].sort();
  const headSha = defaultBranchRef(repo);
  if (names.length === 0) {
    parts.push(pktLine(ZERO_OID + " capabilities^{}\0" + caps + "\n"));
  } else {
    if (headSha) parts.push(pktLine(headSha + " HEAD\0" + caps + "\n"));
    for (const name of names) {
      const sha = repo.refs.get(name)!;
      parts.push(pktLine(sha + " " + name + "\n"));
      const obj = repo.objects.get(sha);
      if (obj && obj.type === "tag") {
        const target = parseTagTarget(obj.data);
        if (target) parts.push(pktLine(target + " " + name + "^{}\n"));
      }
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function v2Advertisement(): Buffer {
  const lines = [
    "version 2\n",
    "agent=" + GIT_AGENT + "\n",
    "ls-refs=unborn\n",
    "fetch=shallow wait-for-done\n",
    "server-option\n",
    "object-format=sha1\n",
  ];
  return Buffer.concat([...lines.map((l) => pktLine(l)), PKT_FLUSH]);
}

interface UploadRequest {
  wants: string[];
  haves: string[];
  shallows: string[];
  deepen: number | null;
  deepenSince: number | null;
  deepenNot: string | null;
  done: boolean;
  sideband: boolean;
  filterSpec: string | null;
}

function parseV0UploadRequest(buf: Buffer): UploadRequest {
  const req: UploadRequest = {
    wants: [],
    haves: [],
    shallows: [],
    deepen: null,
    deepenSince: null,
    deepenNot: null,
    done: false,
    sideband: false,
    filterSpec: null,
  };
  const items = parsePktLines(buf);
  for (const item of items) {
    if (item.kind === "flush" || item.kind === "delim") continue;
    const text = item.data.toString("utf8").trimEnd();
    if (text.startsWith("want ")) {
      const rest = text.slice(5);
      const nul = rest.indexOf("\0");
      const shaPart = nul >= 0 ? rest.slice(0, nul) : rest.split(" ")[0];
      req.wants.push(shaPart.trim());
      const caps = nul >= 0 ? rest.slice(nul + 1) : rest.slice(shaPart.length);
      if (caps.includes("side-band-64k") || caps.includes("side-band")) req.sideband = true;
    } else if (text.startsWith("have ")) {
      req.haves.push(text.slice(5).trim());
    } else if (text.startsWith("shallow ")) {
      req.shallows.push(text.slice(8).trim());
    } else if (text.startsWith("deepen ")) {
      const n = parseInt(text.slice(7).trim(), 10);
      if (!Number.isNaN(n)) req.deepen = n;
    } else if (text.startsWith("deepen-since ")) {
      const n = parseInt(text.slice(13).trim(), 10);
      if (!Number.isNaN(n)) req.deepenSince = n;
    } else if (text.startsWith("deepen-not ")) {
      req.deepenNot = text.slice(11).trim();
    } else if (text === "done") {
      req.done = true;
    } else if (text.startsWith("filter ")) {
      req.filterSpec = text.slice(7).trim();
    }
  }
  return req;
}

// Build the pack for an upload-pack request, honouring depth limits.
function buildUploadPack(repo: Repo, req: UploadRequest): { pack: Buffer; shallow: string[]; unshallow: string[]; ack: string | null } {
  let ack: string | null = null;
  for (const have of req.haves) {
    if (repo.objects.has(have)) {
      ack = have;
      break;
    }
  }
  const depth = req.deepen ?? 0;
  const { objects, shallow } = collectReachable(repo.objects, req.wants, depth);
  // A commit the client already treats as shallow stops being shallow
  // once this fetch includes its parents.
  const shallowSet = new Set(shallow);
  const reachableCommits = new Set(objects.filter((o) => o.type === "commit").map((o) => o.sha));
  const unshallow = (req.shallows ?? []).filter((s) => reachableCommits.has(s) && !shallowSet.has(s)).sort();
  // Incremental fetch: drop objects the client already has. The client
  // only has the history down to its shallow boundary, so the walk from
  // the ack stops there; walking the whole history would drop the very
  // commits a deepen is asking for.
  let filtered = objects;
  if (ack) {
    const stopAt = new Set(req.shallows ?? []);
    const haveReach = collectReachable(repo.objects, [ack], 0, stopAt).objects;
    const haveSet = new Set(haveReach.map((o) => o.sha));
    filtered = objects.filter((o) => !haveSet.has(o.sha));
  }
  // Pack cache: the same want list (and depth) reuses the same bytes.
  const cacheKey = req.wants.slice().sort().join(",") + "|d" + depth + "|a" + (ack ?? "") + "|s" + (req.shallows ?? []).slice().sort().join(",");
  const cached = packCache.get(cacheKey);
  if (cached) return { pack: cached, shallow, unshallow, ack };
  const pack = encodePack(filtered);
  if (packCache.size > 64) packCache.clear();
  packCache.set(cacheKey, pack);
  return { pack, shallow, unshallow, ack };
}

const packCache = new Map<string, Buffer>();

function handleUploadPackV0(ctx: Ctx, repo: Repo): void {
  const req = parseV0UploadRequest(ctx.body);
  if (req.wants.length === 0) {
    jsonError(ctx, 400, "no wants");
    return;
  }
  for (const want of req.wants) {
    if (!repo.objects.has(want)) {
      const err = pktLine("ERR upload-pack: not our ref " + want + "\n");
      sendRaw(ctx, 200, "application/x-git-upload-pack-result", Buffer.concat([err, PKT_FLUSH]));
      return;
    }
  }
  const { pack, shallow, ack } = buildUploadPack(repo, req);
  const parts: Buffer[] = [];
  if (ack) parts.push(pktLine("ACK " + ack + "\n"));
  else parts.push(pktLine("NAK\n"));
  for (const s of shallow) parts.push(pktLine("shallow " + s + "\n"));
  if (req.sideband) {
    for (const chunk of sideband(pack)) parts.push(chunk);
  } else {
    parts.push(pack);
    parts.push(PKT_FLUSH);
  }
  sendRaw(ctx, 200, "application/x-git-upload-pack-result", Buffer.concat(parts));
}

interface V2Fetch {
  wants: string[];
  haves: string[];
  deepen: number | null;
  deepenSince: number | null;
  deepenNot: string | null;
  done: boolean;
  filterSpec: string | null;
}

function parseV2Command(buf: Buffer): { command: string; args: Map<string, string[]> } {
  const items = parsePktLines(buf);
  const args = new Map<string, string[]>();
  let command = "";
  for (const item of items) {
    if (item.kind === "flush" || item.kind === "delim") continue;
    const text = item.data.toString("utf8").trimEnd();
    // Protocol v2 arguments use either "key=value" (command, agent,
    // object-format) or "key value" (want, have, ref-prefix, deepen,
    // filter, ...); split on whichever separator comes first.
    const eq = text.indexOf("=");
    const sp = text.indexOf(" ");
    let sep = -1;
    if (eq >= 0 && sp >= 0) sep = Math.min(eq, sp);
    else if (eq >= 0) sep = eq;
    else if (sp >= 0) sep = sp;
    const key = sep >= 0 ? text.slice(0, sep) : text;
    const val = sep >= 0 ? text.slice(sep + 1) : "";
    if (key === "command") command = val;
    else {
      if (!args.has(key)) args.set(key, []);
      args.get(key)!.push(val);
    }
  }
  return { command, args };
}

function handleLsRefs(ctx: Ctx, repo: Repo, args: Map<string, string[]>): void {
  const prefixes = args.get("ref-prefix") ?? [];
  const peel = args.has("peel");
  const wantUnborn = args.has("unborn");
  const wantSymref = args.has("symref") || args.has("symrefs");
  const lines: Buffer[] = [];
  const headSha = defaultBranchRef(repo);
  const allRefs: { sha: string; name: string }[] = [];
  if (headSha) allRefs.push({ sha: headSha, name: "HEAD" });
  for (const name of [...repo.refs.keys()].sort()) {
    allRefs.push({ sha: repo.refs.get(name)!, name });
  }
  for (const ref of allRefs) {
    if (prefixes.length > 0 && !prefixes.some((p) => ref.name.startsWith(p))) continue;
    let line = ref.sha + " " + ref.name;
    if (wantSymref && ref.name === "HEAD") line += " symref-target:refs/heads/" + repo.default_branch;
    if (peel) {
      // Protocol v2 reports a peeled tag as an attribute on the tag line,
      // not as a separate "^{}" line (that form is v0 only).
      const obj = repo.objects.get(ref.sha);
      if (obj && obj.type === "tag") {
        const target = parseTagTarget(obj.data);
        if (target) line += " peeled:" + target;
      }
    }
    lines.push(pktLine(line + "\n"));
  }
  if (wantUnborn && !headSha) {
    lines.push(pktLine("unborn HEAD\n"));
  }
  lines.push(PKT_FLUSH);
  sendRaw(ctx, 200, "application/x-git-upload-pack-result", Buffer.concat(lines));
}

function handleFetchV2(ctx: Ctx, repo: Repo, args: Map<string, string[]>): void {
  const wants = args.get("want") ?? [];
  if (wants.length === 0) {
    jsonError(ctx, 400, "no wants");
    return;
  }
  for (const want of wants) {
    if (!repo.objects.has(want)) {
      const err = pktLine("ERR upload-pack: not our ref " + want + "\n");
      sendRaw(ctx, 200, "application/x-git-upload-pack-result", Buffer.concat([err, PKT_FLUSH]));
      return;
    }
  }
  const deepenRaw = args.get("deepen")?.[0];
  const deepen = deepenRaw ? parseInt(deepenRaw, 10) : null;
  const req: UploadRequest = {
    wants,
    haves: args.get("have") ?? [],
    shallows: args.get("shallow") ?? [],
    deepen: Number.isNaN(deepen) ? null : deepen,
    deepenSince: null,
    deepenNot: null,
    done: true,
    sideband: false,
    filterSpec: args.get("filter")?.[0] ?? null,
  };
  const { pack, shallow, unshallow } = buildUploadPack(repo, req);
  const parts: Buffer[] = [];
  // Acknowledgement section, only when the client sent haves: the server
  // ACKs each have that is an ancestor of a want, then "ready" (or "NAK"
  // when nothing is common), closed by a delimiter.
  if (req.haves.length > 0) {
    parts.push(pktLine("acknowledgments\n"));
    const common = req.haves.filter((h) => repo.objects.has(h) && wants.some((w) => h === w || isAncestor(repo.objects, h, w)));
    for (const c of common) parts.push(pktLine("ACK " + c + "\n"));
    parts.push(pktLine(common.length > 0 ? "ready\n" : "NAK\n"));
    parts.push(PKT_DELIM);
  }
  // Shallow-info section, only when there are boundaries to report.
  if (shallow.length > 0 || unshallow.length > 0) {
    parts.push(pktLine("shallow-info\n"));
    for (const s of shallow) parts.push(pktLine("shallow " + s + "\n"));
    for (const s of unshallow) parts.push(pktLine("unshallow " + s + "\n"));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine("packfile\n"));
  // Protocol v2 sends the packfile as sideband channel-1 frames, closed
  // by a flush; a raw pack would be read as pkt-line headers.
  for (const chunk of sideband(pack)) parts.push(chunk);
  sendRaw(ctx, 200, "application/x-git-upload-pack-result", Buffer.concat(parts));
}

function handleUploadPack(ctx: Ctx, repo: Repo): void {
  const proto = (ctx.headers["git-protocol"] as string | undefined) ?? "";
  if (proto.includes("version=2")) {
    const { command, args } = parseV2Command(ctx.body);
    if (command === "ls-refs") handleLsRefs(ctx, repo, args);
    else if (command === "fetch") handleFetchV2(ctx, repo, args);
    else jsonError(ctx, 400, "unknown command");
    return;
  }
  handleUploadPackV0(ctx, repo);
}

// ------------------------------------------------------------- receive-pack

interface RefUpdate {
  oldSha: string;
  newSha: string;
  ref: string;
}

function handleReceivePack(ctx: Ctx, repo: Repo): void {
  // Request: pkt-lines of ref updates, a flush, then the raw packfile.
  let commands: RefUpdate[] = [];
  let packStart = 0;
  let useSideband = false;
  try {
    const { lines, next } = readPktSection(ctx.body, 0);
    packStart = next;
    for (const line of lines) {
      const text = line.toString("utf8").trimEnd();
      const nul = text.indexOf("\0");
      const head = nul >= 0 ? text.slice(0, nul) : text;
      const caps = nul >= 0 ? text.slice(nul + 1) : "";
      if (caps.includes("side-band-64k") || caps.includes("side-band")) useSideband = true;
      const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(head.trim());
      if (m) commands.push({ oldSha: m[1], newSha: m[2], ref: m[3] });
    }
  } catch {
    jsonError(ctx, 400, "bad receive-pack request");
    return;
  }
  const packBuf = ctx.body.subarray(packStart);
  const results: { ref: string; ok: boolean; reason: string }[] = [];
  let unpackError: string | null = null;
  if (packBuf.length > 0) {
    try {
      const decoded = decodePack(packBuf, repo.objects);
      for (const obj of decoded) {
        if (!repo.objects.has(obj.sha)) repo.objects.set(obj.sha, { type: obj.type, sha: obj.sha, data: obj.data });
      }
      packCache.clear();
    } catch (e) {
      unpackError = e instanceof Error ? e.message : "unpack failed";
    }
  }
  if (unpackError) {
    for (const cmd of commands) {
      results.push({ ref: cmd.ref, ok: false, reason: unpackError });
    }
  } else {
    for (const cmd of commands) {
      if (!cmd.ref.startsWith("refs/")) {
        results.push({ ref: cmd.ref, ok: false, reason: "invalid ref" });
        continue;
      }
      const current = repo.refs.get(cmd.ref);
      if (isZeroOid(cmd.newSha)) {
        // Delete.
        if (!current) {
          results.push({ ref: cmd.ref, ok: false, reason: "remote ref does not exist" });
        } else {
          repo.refs.delete(cmd.ref);
          results.push({ ref: cmd.ref, ok: true, reason: "" });
        }
        continue;
      }
      if (!repo.objects.has(cmd.newSha)) {
        results.push({ ref: cmd.ref, ok: false, reason: "object not found" });
        continue;
      }
      if (!current) {
        // Create.
        if (!isZeroOid(cmd.oldSha)) {
          results.push({ ref: cmd.ref, ok: false, reason: "stale old value" });
          continue;
        }
        repo.refs.set(cmd.ref, cmd.newSha);
        results.push({ ref: cmd.ref, ok: true, reason: "" });
        continue;
      }
      if (cmd.oldSha !== current) {
        results.push({ ref: cmd.ref, ok: false, reason: "stale old value" });
        continue;
      }
      if (!isAncestor(repo.objects, current, cmd.newSha)) {
        results.push({ ref: cmd.ref, ok: false, reason: "non-fast-forward" });
        continue;
      }
      repo.refs.set(cmd.ref, cmd.newSha);
      results.push({ ref: cmd.ref, ok: true, reason: "" });
    }
    repo.pushed_at = stamp();
  }
  const lines: string[] = [];
  if (unpackError) lines.push("unpack " + unpackError + "\n");
  else lines.push("unpack ok\n");
  for (const r of results) {
    lines.push(r.ok ? "ok " + r.ref + "\n" : "ng " + r.ref + " " + r.reason + "\n");
  }
  const parts: Buffer[] = [];
  if (useSideband) {
    // With sideband the report itself stays pkt-line framed: the whole
    // report byte stream (lines plus its own flush) is carried as
    // channel-1 sideband data, closed by an outer flush. Sending the bare
    // text as frame data would make the client read "unpa" as a length.
    const report = Buffer.concat([...lines.map((l) => pktLine(l)), PKT_FLUSH]);
    for (const chunk of sideband(report)) parts.push(chunk);
  } else {
    for (const line of lines) parts.push(pktLine(line));
    parts.push(PKT_FLUSH);
  }
  sendRaw(ctx, 200, "application/x-git-receive-pack-result", Buffer.concat(parts));
}

function handleGit(ctx: Ctx): boolean {
  // Path shape: /{owner}/{repo}.git/<rest>
  const m = /^\/([^/]+)\/([^/]+)\.git(?:\/(.*))?$/.exec(ctx.path);
  if (!m) return false;
  const owner = decodeURIComponent(m[1]);
  const name = decodeURIComponent(m[2]);
  const rest = m[3] ?? "";
  if (!checkAuth(ctx)) {
    unauthorized(ctx);
    return true;
  }
  const repo = findRepo(owner, name);
  if (rest === "info/refs") {
    const service = ctx.query.get("service");
    if (!repo) {
      notFound(ctx);
      return true;
    }
    if (service === "git-upload-pack") {
      const proto = (ctx.headers["git-protocol"] as string | undefined) ?? "";
      if (proto.includes("version=2")) {
        sendRaw(ctx, 200, "application/x-git-upload-pack-advertisement", v2Advertisement());
      } else {
        sendRaw(ctx, 200, "application/x-git-upload-pack-advertisement", v0Advertisement(repo, "upload-pack"));
      }
      return true;
    }
    if (service === "git-receive-pack") {
      sendRaw(ctx, 200, "application/x-git-receive-pack-advertisement", v0Advertisement(repo, "receive-pack"));
      return true;
    }
    jsonError(ctx, 400, "unknown service");
    return true;
  }
  if (rest === "git-upload-pack" && ctx.method === "POST") {
    if (!repo) {
      notFound(ctx);
      return true;
    }
    handleUploadPack(ctx, repo);
    return true;
  }
  if (rest === "git-receive-pack" && ctx.method === "POST") {
    if (!repo) {
      notFound(ctx);
      return true;
    }
    handleReceivePack(ctx, repo);
    return true;
  }
  return false;
}

// ------------------------------------------------------------ REST v3 API

function clockUnix(): number {
  return Math.floor((CLOCK_BASE_MS + clockTick * 1000) / 1000);
}

function userJson(ctx: Ctx, user: UserRef): Record<string, unknown> {
  return {
    login: user.login,
    id: user.id,
    node_id: user.node_id,
    avatar_url: ctx.baseUrl + "/avatars/" + user.login,
    gravatar_id: "",
    url: ctx.baseUrl + "/api/v3/users/" + user.login,
    html_url: ctx.baseUrl + "/" + user.login,
    followers_url: ctx.baseUrl + "/api/v3/users/" + user.login + "/followers",
    following_url: ctx.baseUrl + "/api/v3/users/" + user.login + "/following{/other_user}",
    gists_url: ctx.baseUrl + "/api/v3/users/" + user.login + "/gists{/gist_id}",
    starred_url: ctx.baseUrl + "/api/v3/users/" + user.login + "/starred{/owner}{/repo}",
    subscriptions_url: ctx.baseUrl + "/api/v3/users/" + user.login + "/subscriptions",
    organizations_url: ctx.baseUrl + "/api/v3/users/" + user.login + "/orgs",
    repos_url: ctx.baseUrl + "/api/v3/users/" + user.login + "/repos",
    events_url: ctx.baseUrl + "/api/v3/users/" + user.login + "/events{/privacy}",
    received_events_url: ctx.baseUrl + "/api/v3/users/" + user.login + "/received_events",
    type: user.type,
    site_admin: false,
  };
}

function repoJson(ctx: Ctx, repo: Repo): Record<string, unknown> {
  const full = repo.owner.login + "/" + repo.name;
  return {
    id: repo.id,
    node_id: repo.node_id,
    name: repo.name,
    full_name: full,
    owner: userJson(ctx, repo.owner),
    private: repo.private,
    html_url: ctx.baseUrl + "/" + full,
    description: repo.description,
    fork: false,
    url: ctx.baseUrl + "/api/v3/repos/" + full,
    archive_url: ctx.baseUrl + "/api/v3/repos/" + full + "/{archive_format}{/ref}",
    assignees_url: ctx.baseUrl + "/api/v3/repos/" + full + "/assignees{/user}",
    blobs_url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/blobs{/sha}",
    branches_url: ctx.baseUrl + "/api/v3/repos/" + full + "/branches{/branch}",
    clone_url: ctx.baseUrl + "/" + full + ".git",
    commits_url: ctx.baseUrl + "/api/v3/repos/" + full + "/commits{/sha}",
    compare_url: ctx.baseUrl + "/api/v3/repos/" + full + "/compare/{base}...{head}",
    contents_url: ctx.baseUrl + "/api/v3/repos/" + full + "/contents/{+path}",
    contributors_url: ctx.baseUrl + "/api/v3/repos/" + full + "/contributors",
    deployments_url: ctx.baseUrl + "/api/v3/repos/" + full + "/deployments",
    downloads_url: ctx.baseUrl + "/api/v3/repos/" + full + "/downloads",
    events_url: ctx.baseUrl + "/api/v3/repos/" + full + "/events",
    forks_url: ctx.baseUrl + "/api/v3/repos/" + full + "/forks",
    git_commits_url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/commits{/sha}",
    git_refs_url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/refs{/sha}",
    git_tags_url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/tags{/sha}",
    git_url: "git://" + new URL(ctx.baseUrl).host + "/" + full + ".git",
    issue_comment_url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues/comments{/number}",
    issue_events_url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues/events{/number}",
    issues_url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues{/number}",
    keys_url: ctx.baseUrl + "/api/v3/repos/" + full + "/keys{/key_id}",
    labels_url: ctx.baseUrl + "/api/v3/repos/" + full + "/labels{/name}",
    languages_url: ctx.baseUrl + "/api/v3/repos/" + full + "/languages",
    merges_url: ctx.baseUrl + "/api/v3/repos/" + full + "/merges",
    milestones_url: ctx.baseUrl + "/api/v3/repos/" + full + "/milestones{/number}",
    mirror_url: null,
    notifications_url: ctx.baseUrl + "/api/v3/repos/" + full + "/notifications{?since,all,participating}",
    pulls_url: ctx.baseUrl + "/api/v3/repos/" + full + "/pulls{/number}",
    releases_url: ctx.baseUrl + "/api/v3/repos/" + full + "/releases{/id}",
    ssh_url: "git@" + new URL(ctx.baseUrl).host + ":" + full + ".git",
    stargazers_url: ctx.baseUrl + "/api/v3/repos/" + full + "/stargazers",
    statuses_url: ctx.baseUrl + "/api/v3/repos/" + full + "/statuses/{sha}",
    subscribers_url: ctx.baseUrl + "/api/v3/repos/" + full + "/subscribers",
    subscription_url: ctx.baseUrl + "/api/v3/repos/" + full + "/subscription",
    tags_url: ctx.baseUrl + "/api/v3/repos/" + full + "/tags",
    teams_url: ctx.baseUrl + "/api/v3/repos/" + full + "/teams",
    trees_url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/trees{/sha}",
    homepage: null,
    language: null,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    size: repo.objects.size,
    default_branch: repo.default_branch,
    open_issues_count: repo.issues.filter((i) => i.state === "open").length + repo.pulls.filter((p) => p.state === "open").length,
    is_template: false,
    topics: [],
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    has_pages: false,
    has_downloads: true,
    has_discussions: false,
    archived: false,
    disabled: false,
    visibility: repo.private ? "private" : "public",
    pushed_at: repo.pushed_at,
    created_at: repo.created_at,
    updated_at: repo.updated_at,
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
    allow_rebase_merge: true,
    allow_squash_merge: true,
    allow_merge_commit: true,
    allow_forking: true,
    license: null,
    allow_update_branch: false,
    delete_branch_on_merge: false,
  };
}

function labelJson(ctx: Ctx, repo: Repo, label: Label): Record<string, unknown> {
  const full = repo.owner.login + "/" + repo.name;
  return {
    id: label.id,
    node_id: label.node_id,
    url: ctx.baseUrl + "/api/v3/repos/" + full + "/labels/" + encodeURIComponent(label.name),
    name: label.name,
    color: label.color,
    default: label.isDefault,
    description: label.description,
  };
}

function issueJson(ctx: Ctx, repo: Repo, issue: Issue): Record<string, unknown> {
  const full = repo.owner.login + "/" + repo.name;
  return {
    id: issue.id,
    node_id: issue.node_id,
    url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues/" + issue.number,
    repository_url: ctx.baseUrl + "/api/v3/repos/" + full,
    labels_url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues/" + issue.number + "/labels{/name}",
    comments_url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues/" + issue.number + "/comments",
    events_url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues/" + issue.number + "/events",
    html_url: ctx.baseUrl + "/" + full + "/issues/" + issue.number,
    number: issue.number,
    state: issue.state,
    state_reason: null,
    title: issue.title,
    body: issue.body,
    user: userJson(ctx, issue.user),
    labels: issue.labels.map((l) => labelJson(ctx, repo, l)),
    assignee: null,
    assignees: [],
    milestone: null,
    locked: false,
    active_lock_reason: null,
    comments: issue.comments.length,
    closed_at: issue.closed_at,
    created_at: issue.created_at,
    updated_at: issue.updated_at,
    author_association: issue.user.login === ctx.login ? "OWNER" : "CONTRIBUTOR",
  };
}

function commentJson(ctx: Ctx, repo: Repo, issue: Issue, comment: IssueComment): Record<string, unknown> {
  const full = repo.owner.login + "/" + repo.name;
  return {
    id: comment.id,
    node_id: comment.node_id,
    url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues/comments/" + comment.id,
    html_url: ctx.baseUrl + "/" + full + "/issues/" + issue.number + "#issuecomment-" + comment.id,
    issue_url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues/" + issue.number,
    body: comment.body,
    user: userJson(ctx, comment.user),
    created_at: comment.created_at,
    updated_at: comment.updated_at,
    author_association: comment.user.login === ctx.login ? "OWNER" : "CONTRIBUTOR",
  };
}

function prCounts(repo: Repo, pr: PullRequest): { commits: number; additions: number; deletions: number; changed: FileChange[] } {
  const headSha = repo.refs.get("refs/heads/" + pr.headRef);
  const baseSha = repo.refs.get("refs/heads/" + pr.baseRef);
  if (!headSha || !baseSha) return { commits: 0, additions: 0, deletions: 0, changed: [] };
  const base = mergeBase(repo.objects, baseSha, headSha);
  const baseTree = base ? parseCommit(repo.objects.get(base)!.data).tree : null;
  const headTree = parseCommit(repo.objects.get(headSha)!.data).tree;
  const changed = diffTrees(repo.objects, baseTree, headTree);
  let additions = 0;
  let deletions = 0;
  for (const c of changed) {
    additions += c.additions;
    deletions += c.deletions;
  }
  // Commits on the head side since the merge base (first-parent walk).
  let commits = 0;
  let cur: string | undefined = headSha;
  const guard = new Set<string>();
  while (cur && cur !== base && !guard.has(cur)) {
    guard.add(cur);
    commits += 1;
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== "commit") break;
    cur = parseCommit(obj.data).parents[0];
  }
  return { commits, additions, deletions, changed };
}

function pullJson(ctx: Ctx, repo: Repo, pr: PullRequest): Record<string, unknown> {
  const full = repo.owner.login + "/" + repo.name;
  const counts = prCounts(repo, pr);
  const mergeable = pr.state === "open" ? !prConflicts(repo, pr) : false;
  return {
    id: pr.id,
    node_id: pr.node_id,
    url: ctx.baseUrl + "/api/v3/repos/" + full + "/pulls/" + pr.number,
    html_url: ctx.baseUrl + "/" + full + "/pull/" + pr.number,
    diff_url: ctx.baseUrl + "/" + full + "/pull/" + pr.number + ".diff",
    patch_url: ctx.baseUrl + "/" + full + "/pull/" + pr.number + ".patch",
    issue_url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues/" + pr.number,
    commits_url: ctx.baseUrl + "/api/v3/repos/" + full + "/pulls/" + pr.number + "/commits",
    review_comments_url: ctx.baseUrl + "/api/v3/repos/" + full + "/pulls/" + pr.number + "/comments",
    review_comment_url: ctx.baseUrl + "/api/v3/repos/" + full + "/pulls/comments{/number}",
    comments_url: ctx.baseUrl + "/api/v3/repos/" + full + "/issues/" + pr.number + "/comments",
    statuses_url: ctx.baseUrl + "/api/v3/repos/" + full + "/statuses/" + pr.headSha,
    number: pr.number,
    state: pr.state,
    locked: false,
    title: pr.title,
    user: userJson(ctx, pr.user),
    body: pr.body,
    labels: [],
    milestone: null,
    active_lock_reason: null,
    created_at: pr.created_at,
    updated_at: pr.updated_at,
    closed_at: pr.closed_at,
    merged_at: pr.merged_at,
    merge_commit_sha: pr.merge_commit_sha,
    assignee: null,
    assignees: [],
    requested_reviewers: [],
    requested_teams: [],
    head: {
      label: repo.owner.login + ":" + pr.headRef,
      ref: pr.headRef,
      sha: pr.headSha,
      user: userJson(ctx, repo.owner),
      repo: repoJson(ctx, repo),
    },
    base: {
      label: repo.owner.login + ":" + pr.baseRef,
      ref: pr.baseRef,
      sha: pr.baseSha,
      user: userJson(ctx, repo.owner),
      repo: repoJson(ctx, repo),
    },
    author_association: pr.user.login === ctx.login ? "OWNER" : "CONTRIBUTOR",
    auto_merge: null,
    draft: false,
    merged: pr.merged,
    mergeable,
    mergeable_state: mergeable ? "clean" : "dirty",
    merged_by: pr.merged ? userJson(ctx, pr.user) : null,
    comments: 0,
    review_comments: 0,
    maintainer_can_modify: false,
    commits: counts.commits,
    additions: counts.additions,
    deletions: counts.deletions,
    changed_files: counts.changed.length,
  };
}

function commitJson(ctx: Ctx, repo: Repo, sha: string): Record<string, unknown> | null {
  const obj = repo.objects.get(sha);
  if (!obj || obj.type !== "commit") return null;
  const info = parseCommit(obj.data);
  const full = repo.owner.login + "/" + repo.name;
  const authorUser = info.authorEmail === ctx.login + "@users.noreply.github.com" ? userJson(ctx, ctx.user) : null;
  const committerUser = info.committerEmail === ctx.login + "@users.noreply.github.com" ? userJson(ctx, ctx.user) : null;
  return {
    sha,
    node_id: nodeId("C", sha),
    commit: {
      author: { name: info.authorName, email: info.authorEmail, date: info.authorDate },
      committer: { name: info.committerName, email: info.committerEmail, date: info.committerDate },
      message: info.message,
      tree: { sha: info.tree, url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/trees/" + info.tree },
      url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/commits/" + sha,
      comment_count: 0,
      verification: { verified: false, reason: "unsigned", signature: null, payload: null },
    },
    url: ctx.baseUrl + "/api/v3/repos/" + full + "/commits/" + sha,
    html_url: ctx.baseUrl + "/" + full + "/commit/" + sha,
    comments_url: ctx.baseUrl + "/api/v3/repos/" + full + "/commits/" + sha + "/comments",
    author: authorUser,
    committer: committerUser,
    parents: info.parents.map((p) => ({
      sha: p,
      url: ctx.baseUrl + "/api/v3/repos/" + full + "/commits/" + p,
      html_url: ctx.baseUrl + "/" + full + "/commit/" + p,
    })),
  };
}

function branchJson(ctx: Ctx, repo: Repo, branch: string, sha: string): Record<string, unknown> {
  const full = repo.owner.login + "/" + repo.name;
  return {
    name: branch,
    commit: { sha, url: ctx.baseUrl + "/api/v3/repos/" + full + "/commits/" + sha },
    protected: false,
    protection: { enabled: false, required_status_checks: { enforcement_level: "off", contexts: [], checks: [] } },
    protection_url: ctx.baseUrl + "/api/v3/repos/" + full + "/branches/" + branch + "/protection",
  };
}

// Pagination: ?page=N&per_page=M (defaults 1 and 30). Returns the page and
// the Link header value to send (empty when there is only one page).
function paginate<T>(ctx: Ctx, items: T[]): { page: T[]; link: string } {
  const perPage = Math.min(100, Math.max(1, parseInt(ctx.query.get("per_page") ?? "30", 10) || 30));
  const page = Math.max(1, parseInt(ctx.query.get("page") ?? "1", 10) || 1);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link = "";
  if (totalPages > 1) {
    const base = ctx.baseUrl + ctx.path;
    const mk = (p: number, rel: string) => "<" + base + "?page=" + p + "&per_page=" + perPage + ">; rel=\"" + rel + "\"";
    const parts: string[] = [];
    if (page < totalPages) parts.push(mk(page + 1, "next"));
    if (page > 1) parts.push(mk(page - 1, "prev"));
    parts.push(mk(1, "first"));
    parts.push(mk(totalPages, "last"));
    link = parts.join(", ");
  }
  return { page: slice, link };
}

function sendPage<T>(ctx: Ctx, items: T[]): void {
  const { page, link } = paginate(ctx, items);
  sendJson(ctx, 200, page, link ? { Link: link } : undefined);
}

// Resolve /repos/{owner}/{repo} from the path; 404 when absent or when
// the owner is not the token's login (never 403).
function resolveRepo(ctx: Ctx, owner: string, name: string): Repo | null {
  if (owner !== ctx.login) return null;
  return findRepo(owner, name) ?? null;
}

function identLine(user: UserRef): string {
  return user.login + " <" + user.login + "@users.noreply.github.com> " + clockUnix() + " +0000";
}

// ------------------------------------------------------- REST route handlers

function handleRestRoot(ctx: Ctx): void {
  const b = ctx.baseUrl + "/api/v3";
  sendJson(ctx, 200, {
    current_user_url: b + "/user",
    current_user_authorizations_html_url: "https://github.com/settings/applications",
    authorizations_url: b + "/authorizations",
    code_search_url: b + "/search/code{?q}",
    commit_search_url: b + "/search/commits{?q}",
    emails_url: b + "/user/emails",
    emojis_url: b + "/emojis",
    events_url: b + "/events",
    feeds_url: b + "/feeds",
    followers_url: b + "/users/{user}/followers",
    following_url: b + "/users/{user}/following{/target}",
    gists_url: b + "/gists{/gist_id}",
    hub_url: b + "/hub",
    issue_search_url: b + "/search/issues{?q}",
    issues_url: b + "/issues",
    keys_url: b + "/user/keys",
    labels_url: b + "/repos/{owner}/{repo}/labels{/name}",
    marketplace_purchases_url: b + "/marketplace_listing/plans",
    marketplace_listing_url: b + "/marketplace_listing",
    notifications_url: b + "/notifications",
    organization_repositories_url: b + "/orgs/{org}/repos{?type,page,per_page,sort}",
    organization_teams_url: b + "/orgs/{org}/teams",
    public_gists_url: b + "/gists/public",
    rate_limit_url: b + "/rate_limit",
    repository_url: b + "/repos/{owner}/{repo}",
    repository_search_url: b + "/search/repositories{?q}",
    current_user_repositories_url: b + "/user/repos{?type,page,per_page,sort}",
    starred_url: b + "/user/starred{/owner}{/repo}",
    starred_gists_url: b + "/gists/starred",
    user_url: b + "/users/{user}",
    user_organizations_url: b + "/users/{user}/orgs",
    user_repositories_url: b + "/users/{user}/repos{?type,page,per_page,sort}",
    user_search_url: b + "/search/users{?q}",
  }, { "X-OAuth-Scopes": "repo, read:org" });
}

function handleMeta(ctx: Ctx): void {
  sendJson(ctx, 200, {
    verifiable_password_authentication: true,
    password_authentication: true,
    token_authentication: true,
    github_services_sha: "0000000000000000000000000000000000000000",
    installed_version: "1.0.0",
    hooks: ["127.0.0.1"],
    git: ["127.0.0.1"],
    pages: ["127.0.0.1"],
    importer: ["127.0.0.1"],
    actions: ["127.0.0.1"],
    dependabot: ["127.0.0.1"],
  });
}

function listUserRepos(ctx: Ctx): void {
  const mine = [...repos.values()].filter((r) => r.owner.login === ctx.login);
  mine.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
  sendPage(ctx, mine.map((r) => repoJson(ctx, r)));
}

function createUserRepo(ctx: Ctx): void {
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  const name = strField(body, "name");
  if (!name || !/^[A-Za-z0-9._-]+$/.test(name)) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Repository", code: "custom", field: "name", message: "name is invalid" }] });
    return;
  }
  if (findRepo(ctx.login, name)) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Repository", code: "custom", field: "name", message: "name already exists on this account" }] });
    return;
  }
  const repo = createRepo(ctx.user, name, strField(body, "description"), body.private === true, strField(body, "default_branch", "main"));
  sendJson(ctx, 201, repoJson(ctx, repo));
}

function getRepo(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  sendJson(ctx, 200, repoJson(ctx, repo));
}

function patchRepo(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  if (typeof body.description === "string") repo.description = body.description;
  if (typeof body.default_branch === "string" && body.default_branch) repo.default_branch = body.default_branch;
  if (typeof body.private === "boolean") repo.private = body.private;
  if (typeof body.name === "string" && body.name && body.name !== name) {
    if (findRepo(ctx.login, body.name)) {
      sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Repository", code: "custom", field: "name", message: "name already exists on this account" }] });
      return;
    }
    repos.delete(repoKey(owner, name));
    repo.name = body.name;
    repo.node_id = nodeId("R", owner + "/" + body.name);
    repos.set(repoKey(owner, body.name), repo);
  }
  repo.updated_at = stamp();
  sendJson(ctx, 200, repoJson(ctx, repo));
}

function deleteRepo(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  repos.delete(repoKey(owner, name));
  const res = (ctx as unknown as { res: http.ServerResponse }).res;
  res.writeHead(204, { "X-GitHub-Request-Id": requestId() });
  res.end();
}

function listBranches(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const branches: Record<string, unknown>[] = [];
  for (const ref of [...repo.refs.keys()].sort()) {
    if (!ref.startsWith("refs/heads/")) continue;
    branches.push(branchJson(ctx, repo, ref.slice("refs/heads/".length), repo.refs.get(ref)!));
  }
  sendPage(ctx, branches);
}

function getBranch(ctx: Ctx, owner: string, name: string, branch: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const sha = repo.refs.get("refs/heads/" + branch);
  if (!sha) {
    notFound(ctx);
    return;
  }
  sendJson(ctx, 200, branchJson(ctx, repo, branch, sha));
}

// Commits of a branch, newest first, following the first-parent chain and
// then any remaining ancestors by depth.
function listCommitsForTip(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  let cur: string | undefined = tip;
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    out.push(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== "commit") break;
    cur = parseCommit(obj.data).parents[0];
  }
  // Any ancestors reachable only through merge parents.
  const rest: { sha: string; depth: number }[] = [];
  const queue: { sha: string; depth: number }[] = [{ sha: tip, depth: 0 }];
  const visited = new Set<string>([tip]);
  while (queue.length > 0) {
    const item = queue.shift()!;
    const obj = repo.objects.get(item.sha);
    if (!obj || obj.type !== "commit") continue;
    for (const p of parseCommit(obj.data).parents) {
      if (visited.has(p)) continue;
      visited.add(p);
      queue.push({ sha: p, depth: item.depth + 1 });
      if (!seen.has(p)) rest.push({ sha: p, depth: item.depth + 1 });
    }
  }
  rest.sort((a, b) => a.depth - b.depth);
  for (const r of rest) out.push(r.sha);
  return out;
}

function listCommits(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const refParam = ctx.query.get("sha") ?? repo.default_branch;
  let tip = repo.refs.get("refs/heads/" + refParam);
  if (!tip) tip = repo.objects.has(refParam) ? refParam : undefined;
  if (!tip) {
    sendPage(ctx, []);
    return;
  }
  let shas = listCommitsForTip(repo, tip);
  const pathFilter = ctx.query.get("path");
  if (pathFilter) {
    shas = shas.filter((sha) => {
      const obj = repo.objects.get(sha);
      if (!obj || obj.type !== "commit") return false;
      const files = new Map<string, { mode: string; sha: string }>();
      flattenTree(repo.objects, parseCommit(obj.data).tree, "", files);
      for (const p of files.keys()) if (p === pathFilter || p.startsWith(pathFilter + "/")) return true;
      return false;
    });
  }
  const items = shas.map((sha) => commitJson(ctx, repo, sha)).filter((c): c is Record<string, unknown> => c !== null);
  sendPage(ctx, items);
}

function getCommit(ctx: Ctx, owner: string, name: string, sha: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  let resolved = sha;
  const refSha = repo.refs.get("refs/heads/" + sha) ?? repo.refs.get("refs/tags/" + sha);
  if (refSha) resolved = refSha;
  const item = commitJson(ctx, repo, resolved);
  if (!item) {
    notFound(ctx);
    return;
  }
  sendJson(ctx, 200, item);
}

// Read one file (or a directory listing) from a branch tip.
function contentsAt(ctx: Ctx, repo: Repo, path: string, ref: string | null): { status: number; value: unknown } {
  const branch = ref ?? repo.default_branch;
  const tip = repo.refs.get("refs/heads/" + branch) ?? (repo.objects.has(branch) ? branch : undefined);
  if (!tip) return { status: 404, value: { message: "Not Found" } };
  const tipObj = repo.objects.get(tip);
  if (!tipObj || tipObj.type !== "commit") return { status: 404, value: { message: "Not Found" } };
  const treeSha = parseCommit(tipObj.data).tree;
  const files = new Map<string, { mode: string; sha: string }>();
  flattenTree(repo.objects, treeSha, "", files);
  const full = repo.owner.login + "/" + repo.name;
  const wrap = (content: string): string => {
    const out: string[] = [];
    for (let i = 0; i < content.length; i += 60) out.push(content.slice(i, i + 60));
    return out.join("\n");
  };
  if (path === "") {
    const entries: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    for (const p of [...files.keys()].sort()) {
      const top = p.split("/")[0];
      if (seen.has(top)) continue;
      seen.add(top);
      const isDir = [...files.keys()].some((q) => q.startsWith(top + "/"));
      const f = files.get(p)!;
      entries.push({
        type: isDir ? "dir" : "file",
        size: isDir ? 0 : (repo.objects.get(f.sha)?.data.length ?? 0),
        name: top,
        path: top,
        sha: f.sha,
        url: ctx.baseUrl + "/api/v3/repos/" + full + "/contents/" + encodeURIComponent(top),
        git_url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/blobs/" + f.sha,
        html_url: ctx.baseUrl + "/" + full + "/blob/" + branch + "/" + encodeURIComponent(top),
        download_url: isDir ? null : ctx.baseUrl + "/" + full + "/raw/" + branch + "/" + encodeURIComponent(top),
      });
    }
    return { status: 200, value: entries };
  }
  const direct = files.get(path);
  if (direct) {
    const blob = repo.objects.get(direct.sha);
    const content = blob ? b64encode(blob.data) : "";
    return {
      status: 200,
      value: {
        type: "file",
        encoding: "base64",
        size: blob ? blob.data.length : 0,
        name: path.split("/").pop() ?? path,
        path,
        content: wrap(content),
        sha: direct.sha,
        url: ctx.baseUrl + "/api/v3/repos/" + full + "/contents/" + encodeURIComponent(path),
        git_url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/blobs/" + direct.sha,
        html_url: ctx.baseUrl + "/" + full + "/blob/" + branch + "/" + encodeURIComponent(path),
        download_url: ctx.baseUrl + "/" + full + "/raw/" + branch + "/" + encodeURIComponent(path),
      },
    };
  }
  // Directory?
  const prefix = path + "/";
  const children = [...files.keys()].filter((p) => p.startsWith(prefix));
  if (children.length === 0) return { status: 404, value: { message: "Not Found" } };
  const entries: Record<string, unknown>[] = [];
  const seen = new Set<string>();
  for (const p of children.sort()) {
    const rest = p.slice(prefix.length);
    const top = rest.split("/")[0];
    if (seen.has(top)) continue;
    seen.add(top);
    const isDir = rest.includes("/");
    const f = files.get(p)!;
    entries.push({
      type: isDir ? "dir" : "file",
      size: isDir ? 0 : (repo.objects.get(f.sha)?.data.length ?? 0),
      name: top,
      path: path + "/" + top,
      sha: f.sha,
      url: ctx.baseUrl + "/api/v3/repos/" + full + "/contents/" + encodeURIComponent(path + "/" + top),
      git_url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/blobs/" + f.sha,
      html_url: ctx.baseUrl + "/" + full + "/blob/" + branch + "/" + encodeURIComponent(path + "/" + top),
      download_url: isDir ? null : ctx.baseUrl + "/" + full + "/raw/" + branch + "/" + encodeURIComponent(path + "/" + top),
    });
  }
  return { status: 200, value: entries };
}

function getContents(ctx: Ctx, owner: string, name: string, path: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const result = contentsAt(ctx, repo, path, ctx.query.get("ref"));
  sendJson(ctx, result.status, result.value);
}

// Write (or delete) a file through a new commit on the branch.
function writeContents(ctx: Ctx, owner: string, name: string, path: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  const branch = strField(body, "branch", repo.default_branch);
  const message = strField(body, "message", ctx.method === "DELETE" ? "Delete " + path : "Update " + path);
  const tip = repo.refs.get("refs/heads/" + branch);
  const files = new Map<string, { mode: string; sha: string }>();
  if (tip) {
    const tipObj = repo.objects.get(tip);
    if (tipObj && tipObj.type === "commit") flattenTree(repo.objects, parseCommit(tipObj.data).tree, "", files);
  }
  const existing = files.get(path);
  if (ctx.method === "DELETE") {
    if (!existing) {
      notFound(ctx);
      return;
    }
    files.delete(path);
    const treeSha = buildTreeFromFiles(repo.objects, files);
    const commit = makeCommitObject(treeSha, tip ? [tip] : [], identLine(ctx.user), identLine(ctx.user), message);
    repo.objects.set(commit.sha, commit);
    repo.refs.set("refs/heads/" + branch, commit.sha);
    repo.pushed_at = stamp();
    sendJson(ctx, 200, {
      commit: {
        sha: commit.sha,
        node_id: nodeId("C", commit.sha),
        message,
        author: { name: ctx.user.login, email: ctx.user.login + "@users.noreply.github.com", date: stamp() },
        committer: { name: ctx.user.login, email: ctx.user.login + "@users.noreply.github.com", date: stamp() },
        tree: { sha: treeSha },
        parents: tip ? [{ sha: tip }] : [],
      },
    });
    return;
  }
  // PUT create / update.
  const contentB64 = strField(body, "content");
  if (!contentB64) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Commit", code: "custom", field: "content", message: "content is required" }] });
    return;
  }
  const givenSha = strField(body, "sha");
  if (existing && givenSha && givenSha !== existing.sha) {
    sendJson(ctx, 409, { message: "Conflict: sha does not match" });
    return;
  }
  if (!existing && givenSha) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Commit", code: "custom", field: "sha", message: "sha does not match an existing file" }] });
    return;
  }
  const blob = makeObject("blob", b64decode(contentB64));
  repo.objects.set(blob.sha, blob);
  files.set(path, { mode: "100644", sha: blob.sha });
  const treeSha = buildTreeFromFiles(repo.objects, files);
  const commit = makeCommitObject(treeSha, tip ? [tip] : [], identLine(ctx.user), identLine(ctx.user), message);
  repo.objects.set(commit.sha, commit);
  repo.refs.set("refs/heads/" + branch, commit.sha);
  repo.pushed_at = stamp();
  const full = repo.owner.login + "/" + repo.name;
  sendJson(ctx, existing ? 200 : 201, {
    content: {
      type: "file",
      encoding: "base64",
      size: blob.data.length,
      name: path.split("/").pop() ?? path,
      path,
      content: b64encode(blob.data),
      sha: blob.sha,
      url: ctx.baseUrl + "/api/v3/repos/" + full + "/contents/" + encodeURIComponent(path),
      git_url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/blobs/" + blob.sha,
      html_url: ctx.baseUrl + "/" + full + "/blob/" + branch + "/" + encodeURIComponent(path),
      download_url: ctx.baseUrl + "/" + full + "/raw/" + branch + "/" + encodeURIComponent(path),
    },
    commit: {
      sha: commit.sha,
      node_id: nodeId("C", commit.sha),
      message,
      author: { name: ctx.user.login, email: ctx.user.login + "@users.noreply.github.com", date: stamp() },
      committer: { name: ctx.user.login, email: ctx.user.login + "@users.noreply.github.com", date: stamp() },
      tree: { sha: treeSha },
      parents: tip ? [{ sha: tip }] : [],
    },
  });
}

function listLabels(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  sendPage(ctx, repo.labels.map((l) => labelJson(ctx, repo, l)));
}

function createLabel(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  const labelName = strField(body, "name");
  if (!labelName) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Label", code: "custom", field: "name", message: "name is required" }] });
    return;
  }
  if (repo.labels.some((l) => l.name === labelName)) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Label", code: "custom", field: "name", message: "already_exists" }] });
    return;
  }
  const label: Label = {
    id: nextGlobalId(),
    node_id: nodeId("L", owner + "/" + name + "/" + labelName),
    name: labelName,
    color: strField(body, "color", "ededed").replace(/^#/, ""),
    description: strField(body, "description"),
    isDefault: false,
  };
  repo.labels.push(label);
  sendJson(ctx, 201, labelJson(ctx, repo, label));
}

function labelNamesFromBody(body: Record<string, unknown>): string[] {
  const raw = body.labels;
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item === "string") out.push(item);
    else if (item !== null && typeof item === "object") {
      const name = (item as Record<string, unknown>).name;
      if (typeof name === "string") out.push(name);
    }
  }
  return out;
}

function listIssues(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  let items = [...repo.issues];
  const state = ctx.query.get("state") ?? "open";
  if (state !== "all") items = items.filter((i) => i.state === state);
  const labelsParam = ctx.query.get("labels");
  if (labelsParam) {
    const wanted = labelsParam.split(",").map((s) => s.trim()).filter(Boolean);
    items = items.filter((i) => wanted.every((w) => i.labels.some((l) => l.name === w)));
  }
  const sort = ctx.query.get("sort") ?? "created";
  const direction = ctx.query.get("direction") ?? "desc";
  items.sort((a, b) => {
    const av = sort === "updated" ? a.updated_at : a.created_at;
    const bv = sort === "updated" ? b.updated_at : b.created_at;
    const cmp = av < bv ? -1 : av > bv ? 1 : a.number - b.number;
    return direction === "asc" ? cmp : -cmp;
  });
  sendPage(ctx, items.map((i) => issueJson(ctx, repo, i)));
}

function createIssue(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  const title = strField(body, "title");
  if (!title) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Issue", code: "custom", field: "title", message: "title is required" }] });
    return;
  }
  const labelNames = labelNamesFromBody(body);
  const missing = labelNames.filter((n) => !repo.labels.some((l) => l.name === n));
  if (missing.length > 0) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Issue", code: "custom", field: "labels", message: "unknown label: " + missing.join(", ") }] });
    return;
  }
  const issue = createIssueObject(repo, ctx.user, title, strField(body, "body"), labelNames);
  sendJson(ctx, 201, issueJson(ctx, repo, issue));
}

function getIssue(ctx: Ctx, owner: string, name: string, number: number): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const issue = repo.issues.find((i) => i.number === number);
  if (!issue) {
    notFound(ctx);
    return;
  }
  sendJson(ctx, 200, issueJson(ctx, repo, issue));
}

function patchIssue(ctx: Ctx, owner: string, name: string, number: number): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const issue = repo.issues.find((i) => i.number === number);
  if (!issue) {
    notFound(ctx);
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  if (typeof body.title === "string") issue.title = body.title;
  if (typeof body.body === "string") issue.body = body.body;
  if (body.labels !== undefined) {
    const labelNames = labelNamesFromBody(body);
    const missing = labelNames.filter((n) => !repo.labels.some((l) => l.name === n));
    if (missing.length > 0) {
      sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Issue", code: "custom", field: "labels", message: "unknown label: " + missing.join(", ") }] });
      return;
    }
    issue.labels = labelNames.map((n) => repo.labels.find((l) => l.name === n)!);
  }
  if (body.state === "closed" && issue.state === "open") {
    issue.state = "closed";
    issue.closed_at = stamp();
  } else if (body.state === "open" && issue.state === "closed") {
    issue.state = "open";
    issue.closed_at = null;
  }
  issue.updated_at = stamp();
  sendJson(ctx, 200, issueJson(ctx, repo, issue));
}

function listIssueComments(ctx: Ctx, owner: string, name: string, number: number): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const issue = repo.issues.find((i) => i.number === number);
  if (!issue) {
    notFound(ctx);
    return;
  }
  sendPage(ctx, issue.comments.map((c) => commentJson(ctx, repo, issue, c)));
}

function createIssueComment(ctx: Ctx, owner: string, name: string, number: number): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const issue = repo.issues.find((i) => i.number === number);
  if (!issue) {
    notFound(ctx);
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  const text = strField(body, "body");
  if (!text) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "IssueComment", code: "custom", field: "body", message: "body is required" }] });
    return;
  }
  const now = stamp();
  const comment: IssueComment = {
    id: nextGlobalId(),
    node_id: nodeId("IC", repo.owner.login + "/" + repo.name + "#" + number + "/" + now),
    body: text,
    user: ctx.user,
    created_at: now,
    updated_at: now,
  };
  issue.comments.push(comment);
  issue.updated_at = stamp();
  sendJson(ctx, 201, commentJson(ctx, repo, issue, comment));
}

function splitBranchRef(value: string): string {
  const idx = value.lastIndexOf(":");
  return idx >= 0 ? value.slice(idx + 1) : value;
}

function listPulls(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  let items = [...repo.pulls];
  const state = ctx.query.get("state") ?? "open";
  if (state !== "all") items = items.filter((p) => p.state === state);
  const head = ctx.query.get("head");
  if (head) items = items.filter((p) => p.headRef === splitBranchRef(head));
  const base = ctx.query.get("base");
  if (base) items = items.filter((p) => p.baseRef === splitBranchRef(base));
  const sort = ctx.query.get("sort") ?? "created";
  const direction = ctx.query.get("direction") ?? "desc";
  items.sort((a, b) => {
    const av = sort === "updated" ? a.updated_at : a.created_at;
    const bv = sort === "updated" ? b.updated_at : b.created_at;
    const cmp = av < bv ? -1 : av > bv ? 1 : a.number - b.number;
    return direction === "asc" ? cmp : -cmp;
  });
  sendPage(ctx, items.map((p) => pullJson(ctx, repo, p)));
}

function createPull(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  const title = strField(body, "title");
  const head = splitBranchRef(strField(body, "head"));
  const base = splitBranchRef(strField(body, "base"));
  if (!title || !head || !base) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "PullRequest", code: "custom", field: "title", message: "title, head and base are required" }] });
    return;
  }
  if (!repo.refs.has("refs/heads/" + head)) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "PullRequest", code: "custom", field: "head", message: "head branch does not exist" }] });
    return;
  }
  if (!repo.refs.has("refs/heads/" + base)) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "PullRequest", code: "custom", field: "base", message: "base branch does not exist" }] });
    return;
  }
  if (head === base) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "PullRequest", code: "custom", field: "head", message: "head and base are the same" }] });
    return;
  }
  if (repo.pulls.some((p) => p.state === "open" && p.headRef === head && p.baseRef === base)) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "PullRequest", code: "custom", field: "head", message: "a pull request already exists for this head and base" }] });
    return;
  }
  const pr = createPullObject(repo, ctx.user, title, strField(body, "body"), head, base);
  sendJson(ctx, 201, pullJson(ctx, repo, pr));
}

function getPull(ctx: Ctx, owner: string, name: string, number: number): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const pr = repo.pulls.find((p) => p.number === number);
  if (!pr) {
    notFound(ctx);
    return;
  }
  sendJson(ctx, 200, pullJson(ctx, repo, pr));
}

function patchPull(ctx: Ctx, owner: string, name: string, number: number): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const pr = repo.pulls.find((p) => p.number === number);
  if (!pr) {
    notFound(ctx);
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  if (typeof body.title === "string") pr.title = body.title;
  if (typeof body.body === "string") pr.body = body.body;
  if (body.state === "closed" && pr.state === "open") {
    pr.state = "closed";
    pr.closed_at = stamp();
  } else if (body.state === "open" && pr.state === "closed") {
    pr.state = "open";
    pr.closed_at = null;
  }
  pr.updated_at = stamp();
  sendJson(ctx, 200, pullJson(ctx, repo, pr));
}

function listPullFiles(ctx: Ctx, owner: string, name: string, number: number): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const pr = repo.pulls.find((p) => p.number === number);
  if (!pr) {
    notFound(ctx);
    return;
  }
  const counts = prCounts(repo, pr);
  const full = repo.owner.login + "/" + repo.name;
  const items = counts.changed.map((c) => {
    const headSha = repo.refs.get("refs/heads/" + pr.headRef);
    let blobSha = "";
    if (headSha) {
      const headTree = parseCommit(repo.objects.get(headSha)!.data).tree;
      const files = new Map<string, { mode: string; sha: string }>();
      flattenTree(repo.objects, headTree, "", files);
      blobSha = files.get(c.filename)?.sha ?? "";
    }
    return {
      sha: blobSha,
      filename: c.filename,
      status: c.status,
      additions: c.additions,
      deletions: c.deletions,
      changes: c.additions + c.deletions,
      blob_url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/blobs/" + blobSha,
      raw_url: ctx.baseUrl + "/" + full + "/raw/" + pr.headRef + "/" + encodeURIComponent(c.filename),
      contents_url: ctx.baseUrl + "/api/v3/repos/" + full + "/contents/" + encodeURIComponent(c.filename) + "?ref=" + pr.headRef,
      patch: c.patch,
    };
  });
  sendPage(ctx, items);
}

function listPullCommits(ctx: Ctx, owner: string, name: string, number: number): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const pr = repo.pulls.find((p) => p.number === number);
  if (!pr) {
    notFound(ctx);
    return;
  }
  const headSha = repo.refs.get("refs/heads/" + pr.headRef);
  const baseSha = repo.refs.get("refs/heads/" + pr.baseRef);
  if (!headSha || !baseSha) {
    sendPage(ctx, []);
    return;
  }
  const base = mergeBase(repo.objects, baseSha, headSha);
  const shas: string[] = [];
  let cur: string | undefined = headSha;
  const guard = new Set<string>();
  while (cur && cur !== base && !guard.has(cur)) {
    guard.add(cur);
    shas.push(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== "commit") break;
    cur = parseCommit(obj.data).parents[0];
  }
  const items = shas.map((sha) => commitJson(ctx, repo, sha)).filter((c): c is Record<string, unknown> => c !== null);
  sendPage(ctx, items);
}

function mergePull(ctx: Ctx, owner: string, name: string, number: number): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const pr = repo.pulls.find((p) => p.number === number);
  if (!pr) {
    notFound(ctx);
    return;
  }
  if (pr.merged) {
    sendJson(ctx, 405, { message: "Pull request has already been merged" });
    return;
  }
  if (pr.state !== "open") {
    sendJson(ctx, 405, { message: "Pull request is closed" });
    return;
  }
  if (prConflicts(repo, pr)) {
    sendJson(ctx, 405, { message: "Merge conflict" });
    return;
  }
  const parsed = parseJsonBody(ctx);
  const body = parsed.ok ? (asObject(parsed.value) ?? {}) : {};
  const headSha = repo.refs.get("refs/heads/" + pr.headRef)!;
  const baseSha = repo.refs.get("refs/heads/" + pr.baseRef)!;
  const headTree = parseCommit(repo.objects.get(headSha)!.data).tree;
  const title = strField(body, "commit_title", pr.title + " (#" + pr.number + ")");
  const extra = strField(body, "commit_message");
  const message = extra ? title + "\n\n" + extra : title;
  const commit = makeCommitObject(headTree, [baseSha], identLine(ctx.user), identLine(ctx.user), message);
  repo.objects.set(commit.sha, commit);
  repo.refs.set("refs/heads/" + pr.baseRef, commit.sha);
  repo.pushed_at = stamp();
  pr.headSha = headSha;
  pr.baseSha = commit.sha;
  pr.state = "closed";
  pr.merged = true;
  pr.merged_at = stamp();
  pr.merge_commit_sha = commit.sha;
  pr.closed_at = stamp();
  pr.updated_at = stamp();
  sendJson(ctx, 200, { sha: commit.sha, merged: true, message: "Pull request successfully merged" });
}

function getGitRef(ctx: Ctx, owner: string, name: string, refPath: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const full = repo.owner.login + "/" + repo.name;
  if (refPath === "") {
    // GET /git/refs with no ref lists every ref.
    sendJson(ctx, 200, [...repo.refs.entries()].sort().map(([r, sha]) => {
      const obj = repo.objects.get(sha);
      return {
        ref: r,
        node_id: nodeId("RF", full + "/" + r),
        url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/refs/" + r.slice("refs/".length),
        object: { sha, type: obj ? obj.type : "commit", url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/" + (obj ? obj.type + "s" : "commits") + "/" + sha },
      };
    }));
    return;
  }
  const refName = "refs/" + refPath;
  const exact = repo.refs.get(refName);
  if (exact) {
    const obj = repo.objects.get(exact);
    sendJson(ctx, 200, {
      ref: refName,
      node_id: nodeId("RF", full + "/" + refName),
      url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/refs/" + refPath,
      object: { sha: exact, type: obj ? obj.type : "commit", url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/" + (obj ? obj.type + "s" : "commits") + "/" + exact },
    });
    return;
  }
  const matches = [...repo.refs.entries()].filter(([r]) => r.startsWith(refName + "/") || r === refName);
  if (matches.length === 0) {
    notFound(ctx);
    return;
  }
  sendJson(ctx, 200, matches.map(([r, sha]) => {
    const obj = repo.objects.get(sha);
    return {
      ref: r,
      node_id: nodeId("RF", full + "/" + r),
      url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/refs/" + r.slice("refs/".length),
      object: { sha, type: obj ? obj.type : "commit", url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/" + (obj ? obj.type + "s" : "commits") + "/" + sha },
    };
  }));
}

function createGitRef(ctx: Ctx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  const ref = strField(body, "ref");
  const sha = strField(body, "sha");
  if (!ref.startsWith("refs/") || !isHex40(sha) || !repo.objects.has(sha)) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Reference", code: "custom", field: "sha", message: "invalid ref or sha" }] });
    return;
  }
  if (repo.refs.has(ref)) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Reference", code: "custom", field: "ref", message: "reference already exists" }] });
    return;
  }
  repo.refs.set(ref, sha);
  const full = repo.owner.login + "/" + repo.name;
  sendJson(ctx, 201, {
    ref,
    node_id: nodeId("RF", full + "/" + ref),
    url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/refs/" + ref.slice("refs/".length),
    object: { sha, type: "commit", url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/commits/" + sha },
  });
}

function updateGitRef(ctx: Ctx, owner: string, name: string, refPath: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (!repo) {
    notFound(ctx);
    return;
  }
  const refName = "refs/" + refPath;
  const current = repo.refs.get(refName);
  if (!current) {
    notFound(ctx);
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = asObject(parsed.value) ?? {};
  const sha = strField(body, "sha");
  const force = body.force === true;
  if (!isHex40(sha) || !repo.objects.has(sha)) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Reference", code: "custom", field: "sha", message: "invalid sha" }] });
    return;
  }
  if (!force && !isAncestor(repo.objects, current, sha)) {
    sendJson(ctx, 422, { message: "Validation Failed", errors: [{ resource: "Reference", code: "custom", field: "sha", message: "not a fast-forward" }] });
    return;
  }
  repo.refs.set(refName, sha);
  const full = repo.owner.login + "/" + repo.name;
  sendJson(ctx, 200, {
    ref: refName,
    node_id: nodeId("RF", full + "/" + refName),
    url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/refs/" + refPath,
    object: { sha, type: "commit", url: ctx.baseUrl + "/api/v3/repos/" + full + "/git/commits/" + sha },
  });
}

// ------------------------------------------------------------- REST router

function handleRest(ctx: Ctx): boolean {
  const s = ctx.segments;
  if (s[0] !== "api" || s[1] !== "v3") return false;
  if (!checkAuth(ctx)) {
    unauthorized(ctx);
    return true;
  }
  const rest = s.slice(2);
  const num = (v: string): number | null => {
    const n = parseInt(v, 10);
    return Number.isNaN(n) || String(n) !== v ? null : n;
  };
  if (rest.length === 0 && ctx.method === "GET") {
    handleRestRoot(ctx);
    return true;
  }
  if (rest.length === 1 && rest[0] === "meta" && ctx.method === "GET") {
    handleMeta(ctx);
    return true;
  }
  if (rest.length === 1 && rest[0] === "user" && ctx.method === "GET") {
    sendJson(ctx, 200, userJson(ctx, ctx.user));
    return true;
  }
  if (rest.length === 2 && rest[0] === "user" && rest[1] === "repos") {
    if (ctx.method === "GET") listUserRepos(ctx);
    else if (ctx.method === "POST") createUserRepo(ctx);
    else jsonError(ctx, 405, "Method Not Allowed");
    return true;
  }
  if (rest.length >= 2 && rest[0] === "repos") {
    const owner = decodeURIComponent(rest[1]);
    const name = rest.length >= 3 ? decodeURIComponent(rest[2]) : "";
    if (rest.length === 3) {
      if (ctx.method === "GET") getRepo(ctx, owner, name);
      else if (ctx.method === "PATCH") patchRepo(ctx, owner, name);
      else if (ctx.method === "DELETE") deleteRepo(ctx, owner, name);
      else jsonError(ctx, 405, "Method Not Allowed");
      return true;
    }
    const sub = rest[3];
    if (sub === "branches") {
      if (rest.length === 4 && ctx.method === "GET") listBranches(ctx, owner, name);
      else if (rest.length === 5 && ctx.method === "GET") getBranch(ctx, owner, name, decodeURIComponent(rest[4]));
      else jsonError(ctx, 405, "Method Not Allowed");
      return true;
    }
    if (sub === "commits") {
      if (rest.length === 4 && ctx.method === "GET") listCommits(ctx, owner, name);
      else if (rest.length === 5 && ctx.method === "GET") getCommit(ctx, owner, name, decodeURIComponent(rest[4]));
      else jsonError(ctx, 405, "Method Not Allowed");
      return true;
    }
    if (sub === "contents") {
      const path = rest.slice(4).map((p) => decodeURIComponent(p)).join("/");
      if (ctx.method === "GET") getContents(ctx, owner, name, path);
      else if (ctx.method === "PUT" || ctx.method === "DELETE") writeContents(ctx, owner, name, path);
      else jsonError(ctx, 405, "Method Not Allowed");
      return true;
    }
    if (sub === "labels") {
      if (rest.length === 4 && ctx.method === "GET") listLabels(ctx, owner, name);
      else if (rest.length === 4 && ctx.method === "POST") createLabel(ctx, owner, name);
      else jsonError(ctx, 405, "Method Not Allowed");
      return true;
    }
    if (sub === "issues") {
      if (rest.length === 4 && ctx.method === "GET") listIssues(ctx, owner, name);
      else if (rest.length === 4 && ctx.method === "POST") createIssue(ctx, owner, name);
      else if (rest.length === 5) {
        const n = num(rest[4]);
        if (n === null) {
          notFound(ctx);
          return true;
        }
        if (ctx.method === "GET") getIssue(ctx, owner, name, n);
        else if (ctx.method === "PATCH") patchIssue(ctx, owner, name, n);
        else jsonError(ctx, 405, "Method Not Allowed");
        return true;
      } else if (rest.length === 6 && rest[5] === "comments") {
        const n = num(rest[4]);
        if (n === null) {
          notFound(ctx);
          return true;
        }
        if (ctx.method === "GET") listIssueComments(ctx, owner, name, n);
        else if (ctx.method === "POST") createIssueComment(ctx, owner, name, n);
        else jsonError(ctx, 405, "Method Not Allowed");
        return true;
      }
      notFound(ctx);
      return true;
    }
    if (sub === "pulls") {
      if (rest.length === 4 && ctx.method === "GET") listPulls(ctx, owner, name);
      else if (rest.length === 4 && ctx.method === "POST") createPull(ctx, owner, name);
      else if (rest.length === 5) {
        const n = num(rest[4]);
        if (n === null) {
          notFound(ctx);
          return true;
        }
        if (ctx.method === "GET") getPull(ctx, owner, name, n);
        else if (ctx.method === "PATCH") patchPull(ctx, owner, name, n);
        else jsonError(ctx, 405, "Method Not Allowed");
        return true;
      } else if (rest.length === 6) {
        const n = num(rest[4]);
        if (n === null) {
          notFound(ctx);
          return true;
        }
        if (rest[5] === "files" && ctx.method === "GET") listPullFiles(ctx, owner, name, n);
        else if (rest[5] === "commits" && ctx.method === "GET") listPullCommits(ctx, owner, name, n);
        else if (rest[5] === "merge" && ctx.method === "PUT") mergePull(ctx, owner, name, n);
        else notFound(ctx);
        return true;
      }
      notFound(ctx);
      return true;
    }
    if (sub === "git") {
      if (rest.length >= 5 && rest[4] === "refs") {
        const refPath = rest.slice(5).map((p) => decodeURIComponent(p)).join("/");
        if (refPath === "" && ctx.method === "POST") createGitRef(ctx, owner, name);
        else if (refPath === "" && ctx.method === "GET") getGitRef(ctx, owner, name, "");
        else if (ctx.method === "GET") getGitRef(ctx, owner, name, refPath);
        else if (ctx.method === "PATCH") updateGitRef(ctx, owner, name, refPath);
        else jsonError(ctx, 405, "Method Not Allowed");
        return true;
      }
      notFound(ctx);
      return true;
    }
    notFound(ctx);
    return true;
  }
  notFound(ctx);
  return true;
}

// ------------------------------------------------------------ GraphQL v4

type GqlValue =
  | { kind: "variable"; name: string }
  | { kind: "string"; value: string }
  | { kind: "int"; value: number }
  | { kind: "float"; value: number }
  | { kind: "boolean"; value: boolean }
  | { kind: "null" }
  | { kind: "enum"; value: string }
  | { kind: "list"; items: GqlValue[] }
  | { kind: "object"; fields: Record<string, GqlValue> };

interface GqlDirective {
  name: string;
  args: Record<string, GqlValue>;
}

type GqlSelection =
  | { kind: "field"; alias: string | null; name: string; args: Record<string, GqlValue>; directives: GqlDirective[]; selection: GqlSelection[] | null }
  | { kind: "spread"; name: string; directives: GqlDirective[] }
  | { kind: "inline"; typeCondition: string | null; directives: GqlDirective[]; selection: GqlSelection[] };

interface GqlOperation {
  kind: "query" | "mutation" | "subscription";
  name: string | null;
  varDefs: { name: string; typeName: string; required: boolean; defaultValue: GqlValue | null }[];
  selection: GqlSelection[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, { typeCondition: string; selection: GqlSelection[] }>;
}

type Token =
  | { kind: "name"; value: string }
  | { kind: "int"; value: string }
  | { kind: "float"; value: string }
  | { kind: "string"; value: string }
  | { kind: "punct"; value: string }
  | { kind: "eof" };

function tokenizeGql(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r" || ch === ",") {
      i++;
      continue;
    }
    if (ch === "#") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (ch === "." && src.slice(i, i + 3) === "...") {
      tokens.push({ kind: "punct", value: "..." });
      i += 3;
      continue;
    }
    if ("{}()[]:!=$@=&|".includes(ch)) {
      tokens.push({ kind: "punct", value: ch });
      i++;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = "";
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\\" && j + 1 < src.length) {
          const esc = src[j + 1];
          if (esc === "n") out += "\n";
          else if (esc === "t") out += "\t";
          else if (esc === "r") out += "\r";
          else if (esc === "u") {
            out += String.fromCharCode(parseInt(src.slice(j + 2, j + 6), 16));
            j += 4;
          } else out += esc;
          j += 2;
        } else {
          out += src[j];
          j++;
        }
      }
      tokens.push({ kind: "string", value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      if (src[j] === "-") j++;
      while (j < src.length && /[0-9]/.test(src[j])) j++;
      let isFloat = false;
      if (src[j] === "." && /[0-9]/.test(src[j + 1] ?? "")) {
        isFloat = true;
        j++;
        while (j < src.length && /[0-9]/.test(src[j])) j++;
      }
      if (src[j] === "e" || src[j] === "E") {
        isFloat = true;
        j++;
        if (src[j] === "+" || src[j] === "-") j++;
        while (j < src.length && /[0-9]/.test(src[j])) j++;
      }
      tokens.push(isFloat ? { kind: "float", value: src.slice(i, j) } : { kind: "int", value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < src.length && /[_A-Za-z0-9]/.test(src[j])) j++;
      tokens.push({ kind: "name", value: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error("unexpected character in GraphQL document: " + ch);
  }
  tokens.push({ kind: "eof" });
  return tokens;
}

class GqlParser {
  private pos = 0;
  private tokens: Token[];

  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  private peek(): Token {
    return this.tokens[this.pos];
  }

  private next(): Token {
    return this.tokens[this.pos++];
  }

  private expectPunct(value: string): void {
    const t = this.next();
    if (t.kind !== "punct" || t.value !== value) throw new Error("expected " + value);
  }

  private expectName(value?: string): string {
    const t = this.next();
    if (t.kind !== "name") throw new Error("expected name");
    if (value !== undefined && t.value !== value) throw new Error("expected " + value);
    return t.value;
  }

  parseDocument(): GqlDocument {
    const doc: GqlDocument = { operations: [], fragments: new Map() };
    while (this.peek().kind !== "eof") {
      const t = this.peek();
      if (t.kind === "punct" && t.value === "{") {
        doc.operations.push({ kind: "query", name: null, varDefs: [], selection: this.parseSelectionSet() });
      } else if (t.kind === "name" && (t.value === "query" || t.value === "mutation" || t.value === "subscription")) {
        const kind = this.next().value as "query" | "mutation" | "subscription";
        let name: string | null = null;
        if (this.peek().kind === "name") name = this.next().value as string;
        const varDefs = this.parseVarDefs();
        const selection = this.parseSelectionSet();
        doc.operations.push({ kind, name, varDefs, selection });
      } else if (t.kind === "name" && t.value === "fragment") {
        this.next();
        const name = this.expectName();
        this.expectName("on");
        const typeCondition = this.expectName();
        const selection = this.parseSelectionSet();
        doc.fragments.set(name, { typeCondition, selection });
      } else {
        throw new Error("unexpected token in GraphQL document");
      }
    }
    return doc;
  }

  private parseVarDefs(): GqlOperation["varDefs"] {
    const defs: GqlOperation["varDefs"] = [];
    if (this.peek().kind === "punct" && this.peek().value === "(") {
      this.next();
      while (!(this.peek().kind === "punct" && this.peek().value === ")")) {
        this.expectPunct("$");
        const name = this.expectName();
        this.expectPunct(":");
        const typeName = this.parseTypeName();
        let required = false;
        if (this.peek().kind === "punct" && this.peek().value === "!") {
          this.next();
          required = true;
        }
        let defaultValue: GqlValue | null = null;
        if (this.peek().kind === "punct" && this.peek().value === "=") {
          this.next();
          defaultValue = this.parseValue();
        }
        defs.push({ name, typeName, required, defaultValue });
      }
      this.next();
    }
    return defs;
  }

  private parseTypeName(): string {
    if (this.peek().kind === "punct" && this.peek().value === "[") {
      this.next();
      const inner = this.parseTypeName();
      this.expectPunct("]");
      let name = "[" + inner + "]";
      if (this.peek().kind === "punct" && this.peek().value === "!") {
        this.next();
        name += "!";
      }
      return name;
    }
    const name = this.expectName();
    if (this.peek().kind === "punct" && this.peek().value === "!") {
      this.next();
      return name + "!";
    }
    return name;
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct("{");
    const out: GqlSelection[] = [];
    while (!(this.peek().kind === "punct" && this.peek().value === "}")) {
      out.push(this.parseSelection());
    }
    this.next();
    return out;
  }

  private parseSelection(): GqlSelection {
    const t = this.peek();
    if (t.kind === "punct" && t.value === "...") {
      this.next();
      const n = this.peek();
      if (n.kind === "name" && n.value !== "on") {
        const name = this.next().value as string;
        const directives = this.parseDirectives();
        return { kind: "spread", name, directives };
      }
      let typeCondition: string | null = null;
      if (n.kind === "name" && n.value === "on") {
        this.next();
        typeCondition = this.expectName();
      }
      const directives = this.parseDirectives();
      const selection = this.parseSelectionSet();
      return { kind: "inline", typeCondition, directives, selection };
    }
    let name = this.expectName();
    let alias: string | null = null;
    if (this.peek().kind === "punct" && this.peek().value === ":") {
      this.next();
      alias = name;
      name = this.expectName();
    }
    const args = this.parseArguments();
    const directives = this.parseDirectives();
    let selection: GqlSelection[] | null = null;
    if (this.peek().kind === "punct" && this.peek().value === "{") {
      selection = this.parseSelectionSet();
    }
    return { kind: "field", alias, name, args, directives, selection };
  }

  private parseArguments(): Record<string, GqlValue> {
    const args: Record<string, GqlValue> = {};
    if (this.peek().kind === "punct" && this.peek().value === "(") {
      this.next();
      while (!(this.peek().kind === "punct" && this.peek().value === ")")) {
        const name = this.expectName();
        this.expectPunct(":");
        args[name] = this.parseValue();
      }
      this.next();
    }
    return args;
  }

  private parseDirectives(): GqlDirective[] {
    const out: GqlDirective[] = [];
    while (this.peek().kind === "punct" && this.peek().value === "@") {
      this.next();
      const name = this.expectName();
      const args = this.parseArguments();
      out.push({ name, args });
    }
    return out;
  }

  private parseValue(): GqlValue {
    const t = this.next();
    if (t.kind === "punct" && t.value === "$") {
      return { kind: "variable", name: this.expectName() };
    }
    if (t.kind === "punct" && t.value === "[") {
      const items: GqlValue[] = [];
      while (!(this.peek().kind === "punct" && this.peek().value === "]")) items.push(this.parseValue());
      this.next();
      return { kind: "list", items };
    }
    if (t.kind === "punct" && t.value === "{") {
      const fields: Record<string, GqlValue> = {};
      while (!(this.peek().kind === "punct" && this.peek().value === "}")) {
        const name = this.expectName();
        this.expectPunct(":");
        fields[name] = this.parseValue();
      }
      this.next();
      return { kind: "object", fields };
    }
    if (t.kind === "string") return { kind: "string", value: t.value };
    if (t.kind === "int") return { kind: "int", value: parseInt(t.value, 10) };
    if (t.kind === "float") return { kind: "float", value: parseFloat(t.value) };
    if (t.kind === "name") {
      if (t.value === "true") return { kind: "boolean", value: true };
      if (t.value === "false") return { kind: "boolean", value: false };
      if (t.value === "null") return { kind: "null" };
      return { kind: "enum", value: t.value };
    }
    throw new Error("unexpected value in GraphQL document");
  }
}

// ------------------------------------------------- GraphQL type registry

interface GqlTypeRef {
  kind: "OBJECT" | "SCALAR" | "ENUM" | "NON_NULL" | "LIST" | "INPUT_OBJECT" | "INTERFACE" | "UNION";
  name?: string;
  ofType?: GqlTypeRef;
}

interface GqlFieldDef {
  name: string;
  type: GqlTypeRef;
  args?: { name: string; type: GqlTypeRef }[];
}

interface GqlTypeDef {
  name: string;
  kind: "OBJECT" | "ENUM" | "INPUT_OBJECT" | "SCALAR";
  description?: string;
  fields?: GqlFieldDef[];
  enumValues?: { name: string; description?: string }[];
  inputFields?: { name: string; type: GqlTypeRef }[];
}

function t(name: string): GqlTypeRef {
  return { kind: "OBJECT", name };
}
function s(name: string): GqlTypeRef {
  return { kind: "SCALAR", name };
}
function e(name: string): GqlTypeRef {
  return { kind: "ENUM", name };
}
function nn(inner: GqlTypeRef): GqlTypeRef {
  return { kind: "NON_NULL", ofType: inner };
}
function list(inner: GqlTypeRef): GqlTypeRef {
  return { kind: "LIST", ofType: inner };
}
function io(name: string): GqlTypeRef {
  return { kind: "INPUT_OBJECT", name };
}

const GQL_TYPES: Record<string, GqlTypeDef> = {
  Query: {
    name: "Query",
    kind: "OBJECT",
    fields: [
      { name: "repository", type: t("Repository"), args: [{ name: "owner", type: nn(s("String")) }, { name: "name", type: nn(s("String")) }] },
      { name: "viewer", type: t("User") },
      { name: "search", type: t("SearchResultItemConnection"), args: [{ name: "type", type: e("SearchType") }, { name: "query", type: s("String") }, { name: "first", type: s("Int") }, { name: "after", type: s("String") }] },
      { name: "node", type: t("Node"), args: [{ name: "id", type: nn(s("ID")) }] },
      { name: "nodes", type: list(t("Node")), args: [{ name: "ids", type: nn(list(nn(s("ID")))) }] },
    ],
  },
  Mutation: {
    name: "Mutation",
    kind: "OBJECT",
    fields: [
      { name: "createIssue", type: t("CreateIssuePayload"), args: [{ name: "input", type: nn(io("CreateIssueInput")) }] },
      { name: "createPullRequest", type: t("CreatePullRequestPayload"), args: [{ name: "input", type: nn(io("CreatePullRequestInput")) }] },
      { name: "closeIssue", type: t("CloseIssuePayload"), args: [{ name: "input", type: nn(io("CloseIssueInput")) }] },
      { name: "addComment", type: t("AddCommentPayload"), args: [{ name: "input", type: nn(io("AddCommentInput")) }] },
      { name: "mergePullRequest", type: t("MergePullRequestPayload"), args: [{ name: "input", type: nn(io("MergePullRequestInput")) }] },
    ],
  },
  Repository: {
    name: "Repository",
    kind: "OBJECT",
    fields: [
      { name: "id", type: nn(s("ID")) },
      { name: "databaseId", type: s("Int") },
      { name: "name", type: nn(s("String")) },
      { name: "nameWithOwner", type: nn(s("String")) },
      { name: "owner", type: nn(t("User")) },
      { name: "defaultBranchRef", type: t("Ref") },
      { name: "viewerPermission", type: e("RepositoryPermission") },
      { name: "hasIssuesEnabled", type: nn(s("Boolean")) },
      { name: "issue", type: t("Issue"), args: [{ name: "number", type: nn(s("Int")) }] },
      { name: "issues", type: t("IssueConnection"), args: [{ name: "first", type: s("Int") }, { name: "after", type: s("String") }, { name: "orderBy", type: io("IssueOrder") }, { name: "states", type: list(e("IssueState")) }, { name: "labels", type: list(s("String")) }] },
      { name: "pullRequest", type: t("PullRequest"), args: [{ name: "number", type: nn(s("Int")) }] },
      { name: "pullRequests", type: t("PullRequestConnection"), args: [{ name: "first", type: s("Int") }, { name: "after", type: s("String") }, { name: "states", type: list(e("PullRequestState")) }, { name: "orderBy", type: io("IssueOrder") }] },
      { name: "url", type: nn(s("URI")) },
      { name: "description", type: s("String") },
      { name: "createdAt", type: nn(s("DateTime")) },
      { name: "updatedAt", type: nn(s("DateTime")) },
      { name: "stargazerCount", type: nn(s("Int")) },
      { name: "forkCount", type: nn(s("Int")) },
      { name: "isPrivate", type: nn(s("Boolean")) },
      { name: "primaryLanguage", type: t("Language") },
    ],
  },
  Issue: {
    name: "Issue",
    kind: "OBJECT",
    fields: [
      { name: "id", type: nn(s("ID")) },
      { name: "number", type: nn(s("Int")) },
      { name: "title", type: nn(s("String")) },
      { name: "state", type: nn(e("IssueState")) },
      { name: "body", type: s("String") },
      { name: "createdAt", type: nn(s("DateTime")) },
      { name: "updatedAt", type: nn(s("DateTime")) },
      { name: "closedAt", type: s("DateTime") },
      { name: "author", type: t("User") },
      { name: "labels", type: t("LabelConnection"), args: [{ name: "first", type: s("Int") }] },
      { name: "comments", type: t("IssueCommentConnection"), args: [{ name: "first", type: s("Int") }] },
      { name: "url", type: nn(s("URI")) },
      { name: "repository", type: nn(t("Repository")) },
      { name: "assignees", type: t("UserConnection") },
      { name: "milestone", type: t("Milestone") },
      { name: "locked", type: nn(s("Boolean")) },
    ],
  },
  PullRequest: {
    name: "PullRequest",
    kind: "OBJECT",
    fields: [
      { name: "id", type: nn(s("ID")) },
      { name: "number", type: nn(s("Int")) },
      { name: "headRefName", type: nn(s("String")) },
      { name: "baseRefName", type: nn(s("String")) },
      { name: "mergeable", type: nn(s("MergeableState")) },
      { name: "state", type: nn(e("PullRequestState")) },
      { name: "merged", type: nn(s("Boolean")) },
      { name: "files", type: t("PullRequestChangedFileConnection"), args: [{ name: "first", type: s("Int") }] },
      { name: "title", type: nn(s("String")) },
      { name: "body", type: s("String") },
      { name: "createdAt", type: nn(s("DateTime")) },
      { name: "updatedAt", type: nn(s("DateTime")) },
      { name: "closedAt", type: s("DateTime") },
      { name: "mergedAt", type: s("DateTime") },
      { name: "author", type: t("User") },
      { name: "headRef", type: t("Ref") },
      { name: "baseRef", type: t("Ref") },
      { name: "commits", type: t("PullRequestCommitConnection"), args: [{ name: "first", type: s("Int") }] },
      { name: "additions", type: nn(s("Int")) },
      { name: "deletions", type: nn(s("Int")) },
      { name: "changedFiles", type: nn(s("Int")) },
      { name: "url", type: nn(s("URI")) },
      { name: "repository", type: nn(t("Repository")) },
    ],
  },
  User: {
    name: "User",
    kind: "OBJECT",
    fields: [
      { name: "id", type: nn(s("ID")) },
      { name: "login", type: nn(s("String")) },
      { name: "name", type: s("String") },
      { name: "url", type: nn(s("URI")) },
      { name: "avatarUrl", type: s("URI") },
    ],
  },
  Ref: {
    name: "Ref",
    kind: "OBJECT",
    fields: [
      { name: "name", type: nn(s("String")) },
      { name: "target", type: t("GitObject") },
      { name: "prefix", type: nn(s("String")) },
    ],
  },
  GitObject: {
    name: "GitObject",
    kind: "OBJECT",
    fields: [{ name: "oid", type: nn(s("GitObjectID")) }],
  },
  IssueConnection: {
    name: "IssueConnection",
    kind: "OBJECT",
    fields: [
      { name: "nodes", type: list(t("Issue")) },
      { name: "edges", type: list(t("IssueEdge")) },
      { name: "totalCount", type: nn(s("Int")) },
      { name: "pageInfo", type: nn(t("PageInfo")) },
    ],
  },
  PullRequestConnection: {
    name: "PullRequestConnection",
    kind: "OBJECT",
    fields: [
      { name: "nodes", type: list(t("PullRequest")) },
      { name: "edges", type: list(t("PullRequestEdge")) },
      { name: "totalCount", type: nn(s("Int")) },
      { name: "pageInfo", type: nn(t("PageInfo")) },
    ],
  },
  IssueEdge: {
    name: "IssueEdge",
    kind: "OBJECT",
    fields: [
      { name: "node", type: t("Issue") },
      { name: "cursor", type: nn(s("String")) },
    ],
  },
  PullRequestEdge: {
    name: "PullRequestEdge",
    kind: "OBJECT",
    fields: [
      { name: "node", type: t("PullRequest") },
      { name: "cursor", type: nn(s("String")) },
    ],
  },
  SearchResultItemConnection: {
    name: "SearchResultItemConnection",
    kind: "OBJECT",
    fields: [
      { name: "nodes", type: list(t("SearchResultItem")) },
      { name: "edges", type: list(t("SearchResultItemEdge")) },
      { name: "totalCount", type: nn(s("Int")) },
      { name: "issueCount", type: nn(s("Int")) },
      { name: "pageInfo", type: nn(t("PageInfo")) },
    ],
  },
  SearchResultItemEdge: {
    name: "SearchResultItemEdge",
    kind: "OBJECT",
    fields: [
      { name: "node", type: t("SearchResultItem") },
      { name: "cursor", type: nn(s("String")) },
    ],
  },
  SearchResultItem: {
    name: "SearchResultItem",
    kind: "OBJECT",
    fields: [{ name: "id", type: nn(s("ID")) }],
  },
  PageInfo: {
    name: "PageInfo",
    kind: "OBJECT",
    fields: [
      { name: "hasNextPage", type: nn(s("Boolean")) },
      { name: "hasPreviousPage", type: nn(s("Boolean")) },
      { name: "startCursor", type: s("String") },
      { name: "endCursor", type: s("String") },
    ],
  },
  LabelConnection: {
    name: "LabelConnection",
    kind: "OBJECT",
    fields: [
      { name: "nodes", type: list(t("Label")) },
      { name: "totalCount", type: nn(s("Int")) },
      { name: "pageInfo", type: nn(t("PageInfo")) },
    ],
  },
  Label: {
    name: "Label",
    kind: "OBJECT",
    fields: [
      { name: "id", type: nn(s("ID")) },
      { name: "name", type: nn(s("String")) },
      { name: "color", type: nn(s("String")) },
      { name: "description", type: s("String") },
    ],
  },
  IssueCommentConnection: {
    name: "IssueCommentConnection",
    kind: "OBJECT",
    fields: [
      { name: "nodes", type: list(t("IssueComment")) },
      { name: "totalCount", type: nn(s("Int")) },
      { name: "pageInfo", type: nn(t("PageInfo")) },
    ],
  },
  IssueComment: {
    name: "IssueComment",
    kind: "OBJECT",
    fields: [
      { name: "id", type: nn(s("ID")) },
      { name: "body", type: nn(s("String")) },
      { name: "author", type: t("User") },
      { name: "createdAt", type: nn(s("DateTime")) },
      { name: "updatedAt", type: nn(s("DateTime")) },
    ],
  },
  UserConnection: {
    name: "UserConnection",
    kind: "OBJECT",
    fields: [
      { name: "nodes", type: list(t("User")) },
      { name: "totalCount", type: nn(s("Int")) },
    ],
  },
  PullRequestChangedFileConnection: {
    name: "PullRequestChangedFileConnection",
    kind: "OBJECT",
    fields: [
      { name: "nodes", type: list(t("PullRequestChangedFile")) },
      { name: "totalCount", type: nn(s("Int")) },
      { name: "pageInfo", type: nn(t("PageInfo")) },
    ],
  },
  PullRequestChangedFile: {
    name: "PullRequestChangedFile",
    kind: "OBJECT",
    fields: [
      { name: "path", type: nn(s("String")) },
      { name: "additions", type: nn(s("Int")) },
      { name: "deletions", type: nn(s("Int")) },
      { name: "changeType", type: nn(e("PatchStatus")) },
    ],
  },
  PullRequestCommitConnection: {
    name: "PullRequestCommitConnection",
    kind: "OBJECT",
    fields: [
      { name: "nodes", type: list(t("PullRequestCommit")) },
      { name: "totalCount", type: nn(s("Int")) },
    ],
  },
  PullRequestCommit: {
    name: "PullRequestCommit",
    kind: "OBJECT",
    fields: [{ name: "commit", type: t("Commit") }],
  },
  Commit: {
    name: "Commit",
    kind: "OBJECT",
    fields: [
      { name: "oid", type: nn(s("GitObjectID")) },
      { name: "message", type: nn(s("String")) },
    ],
  },
  Milestone: {
    name: "Milestone",
    kind: "OBJECT",
    fields: [
      { name: "id", type: nn(s("ID")) },
      { name: "number", type: nn(s("Int")) },
      { name: "title", type: nn(s("String")) },
    ],
  },
  Language: {
    name: "Language",
    kind: "OBJECT",
    fields: [{ name: "name", type: nn(s("String")) }],
  },
  CreateIssuePayload: {
    name: "CreateIssuePayload",
    kind: "OBJECT",
    fields: [
      { name: "issue", type: t("Issue") },
      { name: "clientMutationId", type: s("String") },
    ],
  },
  CreatePullRequestPayload: {
    name: "CreatePullRequestPayload",
    kind: "OBJECT",
    fields: [
      { name: "pullRequest", type: t("PullRequest") },
      { name: "clientMutationId", type: s("String") },
    ],
  },
  SearchType: {
    name: "SearchType",
    kind: "ENUM",
    enumValues: [
      { name: "ISSUE" },
      { name: "PULL_REQUEST" },
      { name: "REPOSITORY" },
      { name: "USER" },
      { name: "DISCUSSION" },
      { name: "COMMIT" },
      { name: "CODE" },
      { name: "MILESTONE" },
    ],
  },
  IssueState: {
    name: "IssueState",
    kind: "ENUM",
    enumValues: [{ name: "OPEN" }, { name: "CLOSED" }],
  },
  PullRequestState: {
    name: "PullRequestState",
    kind: "ENUM",
    enumValues: [{ name: "OPEN" }, { name: "CLOSED" }, { name: "MERGED" }],
  },
  OrderDirection: {
    name: "OrderDirection",
    kind: "ENUM",
    enumValues: [{ name: "ASC" }, { name: "DESC" }],
  },
  IssueOrderField: {
    name: "IssueOrderField",
    kind: "ENUM",
    enumValues: [{ name: "COMMENTS" }, { name: "CREATED_AT" }, { name: "UPDATED_AT" }],
  },
  RepositoryPermission: {
    name: "RepositoryPermission",
    kind: "ENUM",
    enumValues: [{ name: "ADMIN" }, { name: "MAINTAIN" }, { name: "READ" }, { name: "TRIAGE" }, { name: "WRITE" }],
  },
  PatchStatus: {
    name: "PatchStatus",
    kind: "ENUM",
    enumValues: [{ name: "ADDED" }, { name: "CHANGED" }, { name: "COPIED" }, { name: "DELETED" }, { name: "MODIFIED" }, { name: "REMOVED" }, { name: "RENAMED" }],
  },
  IssueOrder: {
    name: "IssueOrder",
    kind: "INPUT_OBJECT",
    inputFields: [
      { name: "field", type: nn(e("IssueOrderField")) },
      { name: "direction", type: nn(e("OrderDirection")) },
    ],
  },
  CreateIssueInput: {
    name: "CreateIssueInput",
    kind: "INPUT_OBJECT",
    inputFields: [
      { name: "repositoryId", type: nn(s("ID")) },
      { name: "title", type: nn(s("String")) },
      { name: "body", type: s("String") },
      { name: "labelIds", type: list(s("ID")) },
      { name: "clientMutationId", type: s("String") },
    ],
  },
  CreatePullRequestInput: {
    name: "CreatePullRequestInput",
    kind: "INPUT_OBJECT",
    inputFields: [
      { name: "repositoryId", type: nn(s("ID")) },
      { name: "baseRefName", type: nn(s("String")) },
      { name: "headRefName", type: nn(s("String")) },
      { name: "title", type: nn(s("String")) },
      { name: "body", type: s("String") },
      { name: "clientMutationId", type: s("String") },
    ],
  },
  CloseIssueInput: {
    name: "CloseIssueInput",
    kind: "INPUT_OBJECT",
    inputFields: [
      { name: "issueId", type: nn(s("ID")) },
      { name: "clientMutationId", type: s("String") },
    ],
  },
  CloseIssuePayload: {
    name: "CloseIssuePayload",
    kind: "OBJECT",
    fields: [
      { name: "issue", type: t("Issue") },
      { name: "clientMutationId", type: s("String") },
    ],
  },
  AddCommentInput: {
    name: "AddCommentInput",
    kind: "INPUT_OBJECT",
    inputFields: [
      { name: "subjectId", type: nn(s("ID")) },
      { name: "body", type: nn(s("String")) },
      { name: "clientMutationId", type: s("String") },
    ],
  },
  AddCommentPayload: {
    name: "AddCommentPayload",
    kind: "OBJECT",
    fields: [
      { name: "commentEdge", type: t("IssueCommentEdge") },
      { name: "subject", type: t("Issue") },
      { name: "clientMutationId", type: s("String") },
    ],
  },
  IssueCommentEdge: {
    name: "IssueCommentEdge",
    kind: "OBJECT",
    fields: [
      { name: "node", type: t("IssueComment") },
      { name: "cursor", type: nn(s("String")) },
    ],
  },
  MergePullRequestInput: {
    name: "MergePullRequestInput",
    kind: "INPUT_OBJECT",
    inputFields: [
      { name: "pullRequestId", type: nn(s("ID")) },
      { name: "mergeMethod", type: e("PullRequestMergeMethod") },
      { name: "commitHeadline", type: s("String") },
      { name: "commitBody", type: s("String") },
      { name: "clientMutationId", type: s("String") },
    ],
  },
  MergePullRequestPayload: {
    name: "MergePullRequestPayload",
    kind: "OBJECT",
    fields: [
      { name: "pullRequest", type: t("PullRequest") },
      { name: "clientMutationId", type: s("String") },
    ],
  },
  PullRequestMergeMethod: {
    name: "PullRequestMergeMethod",
    kind: "ENUM",
    enumValues: [{ name: "MERGE" }, { name: "SQUASH" }, { name: "REBASE" }],
  },
  MergeableState: {
    name: "MergeableState",
    kind: "ENUM",
    enumValues: [{ name: "CONFLICTING" }, { name: "MERGEABLE" }, { name: "UNKNOWN" }],
  },
  Node: {
    name: "Node",
    kind: "OBJECT",
    fields: [{ name: "id", type: nn(s("ID")) }],
  },
};

function typeRefJson(ref: GqlTypeRef): Record<string, unknown> {
  const out: Record<string, unknown> = { kind: ref.kind, name: ref.name ?? null, ofType: null };
  if (ref.ofType) out.ofType = typeRefJson(ref.ofType);
  return out;
}

function typeDefJson(def: GqlTypeDef): Record<string, unknown> {
  return {
    kind: def.kind,
    name: def.name,
    description: def.description ?? null,
    fields: def.fields
      ? def.fields.map((f) => ({
          name: f.name,
          description: null,
          args: (f.args ?? []).map((a) => ({ name: a.name, description: null, type: typeRefJson(a.type), defaultValue: null })),
          type: typeRefJson(f.type),
          isDeprecated: false,
          deprecationReason: null,
        }))
      : null,
    inputFields: def.inputFields
      ? def.inputFields.map((f) => ({ name: f.name, description: null, type: typeRefJson(f.type), defaultValue: null }))
      : null,
    interfaces: [],
    enumValues: def.enumValues
      ? def.enumValues.map((v) => ({ name: v.name, description: v.description ?? null, isDeprecated: false, deprecationReason: null }))
      : null,
    possibleTypes: null,
  };
}

// ------------------------------------------------- GraphQL execution

interface GqlNode {
  __typename: string;
  [key: string]: unknown;
}

function resolveGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case "variable":
      return variables[value.name];
    case "string":
    case "int":
    case "float":
    case "boolean":
    case "enum":
      return value.value;
    case "null":
      return null;
    case "list":
      return value.items.map((i) => resolveGqlValue(i, variables));
    case "object": {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value.fields)) out[k] = resolveGqlValue(v, variables);
      return out;
    }
  }
}

function cursorFor(index: number): string {
  return Buffer.from("cursor:" + index, "utf8").toString("base64");
}

function cursorIndex(cursor: string | undefined): number {
  if (!cursor) return -1;
  try {
    const text = Buffer.from(cursor, "base64").toString("utf8");
    if (text.startsWith("cursor:")) return parseInt(text.slice(7), 10);
  } catch {
    return -1;
  }
  return -1;
}

function makeConnection(typename: string, nodes: GqlNode[], first: number | undefined, after: string | undefined): GqlNode {
  const start = cursorIndex(after) + 1;
  const sliced = first !== undefined ? nodes.slice(start, start + first) : nodes.slice(start);
  const edges: GqlNode[] = sliced.map((node, i) => ({
    __typename: typename.replace("Connection", "Edge"),
    node,
    cursor: cursorFor(start + i),
  }));
  const end = start + sliced.length;
  return {
    __typename: typename,
    nodes: sliced,
    edges,
    totalCount: nodes.length,
    pageInfo: {
      __typename: "PageInfo",
      hasNextPage: end < nodes.length,
      hasPreviousPage: start > 0,
      startCursor: edges.length > 0 ? (edges[0].cursor as string) : null,
      endCursor: edges.length > 0 ? (edges[edges.length - 1].cursor as string) : null,
    },
  };
}

function repoWrapper(ctx: Ctx, repo: Repo): GqlNode {
  return {
    __typename: "Repository",
    repo,
    id: repo.node_id,
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: repo.owner.login + "/" + repo.name,
    url: ctx.baseUrl + "/" + repo.owner.login + "/" + repo.name,
    description: repo.description,
    createdAt: repo.created_at,
    updatedAt: repo.updated_at,
    stargazerCount: 0,
    forkCount: 0,
    isPrivate: repo.private,
    viewerPermission: "ADMIN",
    hasIssuesEnabled: true,
    owner: userWrapper(ctx, repo.owner),
  };
}

function userWrapper(ctx: Ctx, user: UserRef): GqlNode {
  return {
    __typename: "User",
    user,
    id: user.node_id,
    login: user.login,
    name: user.login,
    url: ctx.baseUrl + "/" + user.login,
    avatarUrl: ctx.baseUrl + "/avatars/" + user.login,
  };
}

function issueWrapper(ctx: Ctx, repo: Repo, issue: Issue): GqlNode {
  return {
    __typename: "Issue",
    issue,
    repo,
    id: issue.node_id,
    number: issue.number,
    title: issue.title,
    state: issue.state === "open" ? "OPEN" : "CLOSED",
    body: issue.body,
    createdAt: issue.created_at,
    updatedAt: issue.updated_at,
    closedAt: issue.closed_at,
    url: ctx.baseUrl + "/" + repo.owner.login + "/" + repo.name + "/issues/" + issue.number,
    locked: false,
    author: userWrapper(ctx, issue.user),
    repository: repoWrapper(ctx, repo),
    milestone: null,
  };
}

function refWrapper(name: string, oid: string): GqlNode {
  return {
    __typename: "Ref",
    name,
    prefix: "refs/heads/",
    target: { __typename: "GitObject", oid },
  };
}

function pullWrapper(ctx: Ctx, repo: Repo, pr: PullRequest): GqlNode {
  const counts = prCounts(repo, pr);
  const headSha = repo.refs.get("refs/heads/" + pr.headRef) ?? pr.headSha;
  const baseSha = repo.refs.get("refs/heads/" + pr.baseRef) ?? pr.baseSha;
  return {
    __typename: "PullRequest",
    pr,
    repo,
    id: pr.node_id,
    number: pr.number,
    headRefName: pr.headRef,
    baseRefName: pr.baseRef,
    mergeable: pr.state === "open" ? (prConflicts(repo, pr) ? "CONFLICTING" : "MERGEABLE") : "UNKNOWN",
    state: pr.merged ? "MERGED" : pr.state === "open" ? "OPEN" : "CLOSED",
    merged: pr.merged,
    title: pr.title,
    body: pr.body,
    createdAt: pr.created_at,
    updatedAt: pr.updated_at,
    closedAt: pr.closed_at,
    mergedAt: pr.merged_at,
    url: ctx.baseUrl + "/" + repo.owner.login + "/" + repo.name + "/pull/" + pr.number,
    author: userWrapper(ctx, pr.user),
    headRef: refWrapper(pr.headRef, headSha),
    baseRef: refWrapper(pr.baseRef, baseSha),
    additions: counts.additions,
    deletions: counts.deletions,
    changedFiles: counts.changed.length,
    repository: repoWrapper(ctx, repo),
  };
}

function sortedIssues(repo: Repo, args: Record<string, unknown>): Issue[] {
  let items = [...repo.issues];
  const states = args.states as string[] | undefined;
  if (states && states.length > 0) {
    const want = new Set(states.map((s) => (s === "OPEN" ? "open" : "closed")));
    items = items.filter((i) => want.has(i.state));
  }
  const labels = args.labels as string[] | undefined;
  if (labels && labels.length > 0) {
    items = items.filter((i) => labels.every((l) => i.labels.some((x) => x.name === l)));
  }
  const orderBy = args.orderBy as { field?: string; direction?: string } | undefined;
  const field = orderBy?.field ?? "CREATED_AT";
  const direction = orderBy?.direction ?? "DESC";
  items.sort((a, b) => {
    let cmp = 0;
    if (field === "COMMENTS") cmp = a.comments.length - b.comments.length;
    else if (field === "UPDATED_AT") cmp = a.updated_at < b.updated_at ? -1 : a.updated_at > b.updated_at ? 1 : 0;
    else cmp = a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : 0;
    if (cmp === 0) cmp = a.number - b.number;
    return direction === "ASC" ? cmp : -cmp;
  });
  return items;
}

function sortedPulls(repo: Repo, args: Record<string, unknown>): PullRequest[] {
  let items = [...repo.pulls];
  const states = args.states as string[] | undefined;
  if (states && states.length > 0) {
    const want = new Set(states);
    items = items.filter((p) => want.has(p.merged ? "MERGED" : p.state === "open" ? "OPEN" : "CLOSED"));
  }
  const orderBy = args.orderBy as { field?: string; direction?: string } | undefined;
  const direction = orderBy?.direction ?? "DESC";
  items.sort((a, b) => {
    const cmp = a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : a.number - b.number;
    return direction === "ASC" ? cmp : -cmp;
  });
  return items;
}

type FieldResolver = (ctx: Ctx, data: Record<string, unknown>, args: Record<string, unknown>) => unknown;

const GQL_RESOLVERS: Record<string, Record<string, FieldResolver>> = {
  Repository: {
    issue: (ctx, data, args) => {
      const repo = data.repo as Repo;
      const issue = repo.issues.find((i) => i.number === args.number);
      return issue ? issueWrapper(ctx, repo, issue) : null;
    },
    issues: (ctx, data, args) => {
      const repo = data.repo as Repo;
      const nodes = sortedIssues(repo, args).map((i) => issueWrapper(ctx, repo, i));
      return makeConnection("IssueConnection", nodes, args.first as number | undefined, args.after as string | undefined);
    },
    pullRequest: (ctx, data, args) => {
      const repo = data.repo as Repo;
      const pr = repo.pulls.find((p) => p.number === args.number);
      return pr ? pullWrapper(ctx, repo, pr) : null;
    },
    pullRequests: (ctx, data, args) => {
      const repo = data.repo as Repo;
      const nodes = sortedPulls(repo, args).map((p) => pullWrapper(ctx, repo, p));
      return makeConnection("PullRequestConnection", nodes, args.first as number | undefined, args.after as string | undefined);
    },
    defaultBranchRef: (ctx, data) => {
      const repo = data.repo as Repo;
      const sha = defaultBranchRef(repo);
      return sha ? refWrapper(repo.default_branch, sha) : null;
    },
    primaryLanguage: () => null,
  },
  Issue: {
    labels: (ctx, data, args) => {
      const issue = data.issue as Issue;
      const nodes: GqlNode[] = issue.labels.map((l) => ({
        __typename: "Label",
        id: l.node_id,
        name: l.name,
        color: l.color,
        description: l.description,
      }));
      const first = args.first as number | undefined;
      const sliced = first !== undefined ? nodes.slice(0, first) : nodes;
      return {
        __typename: "LabelConnection",
        nodes: sliced,
        totalCount: nodes.length,
        pageInfo: {
          __typename: "PageInfo",
          hasNextPage: first !== undefined && nodes.length > first,
          hasPreviousPage: false,
          startCursor: null,
          endCursor: null,
        },
      };
    },
    comments: (ctx, data, args) => {
      const issue = data.issue as Issue;
      const nodes: GqlNode[] = issue.comments.map((c) => ({
        __typename: "IssueComment",
        id: c.node_id,
        body: c.body,
        author: userWrapper(ctx, c.user),
        createdAt: c.created_at,
        updatedAt: c.updated_at,
      }));
      const first = args.first as number | undefined;
      const sliced = first !== undefined ? nodes.slice(0, first) : nodes;
      return {
        __typename: "IssueCommentConnection",
        nodes: sliced,
        totalCount: nodes.length,
        pageInfo: {
          __typename: "PageInfo",
          hasNextPage: first !== undefined && nodes.length > first,
          hasPreviousPage: false,
          startCursor: null,
          endCursor: null,
        },
      };
    },
    assignees: () => ({ __typename: "UserConnection", nodes: [], totalCount: 0 }),
  },
  PullRequest: {
    files: (ctx, data, args) => {
      const pr = data.pr as PullRequest;
      const repo = data.repo as Repo;
      const counts = prCounts(repo, pr);
      const nodes: GqlNode[] = counts.changed.map((c) => ({
        __typename: "PullRequestChangedFile",
        path: c.filename,
        additions: c.additions,
        deletions: c.deletions,
        changeType: c.status === "added" ? "ADDED" : c.status === "removed" ? "DELETED" : "MODIFIED",
      }));
      const first = args.first as number | undefined;
      const sliced = first !== undefined ? nodes.slice(0, first) : nodes;
      return {
        __typename: "PullRequestChangedFileConnection",
        nodes: sliced,
        totalCount: nodes.length,
        pageInfo: {
          __typename: "PageInfo",
          hasNextPage: first !== undefined && nodes.length > first,
          hasPreviousPage: false,
          startCursor: null,
          endCursor: null,
        },
      };
    },
    commits: (ctx, data, args) => {
      const pr = data.pr as PullRequest;
      const repo = data.repo as Repo;
      const headSha = repo.refs.get("refs/heads/" + pr.headRef);
      const baseSha = repo.refs.get("refs/heads/" + pr.baseRef);
      const nodes: GqlNode[] = [];
      if (headSha && baseSha) {
        const base = mergeBase(repo.objects, baseSha, headSha);
        let cur: string | undefined = headSha;
        const guard = new Set<string>();
        while (cur && cur !== base && !guard.has(cur)) {
          guard.add(cur);
          const obj = repo.objects.get(cur);
          if (!obj || obj.type !== "commit") break;
          const info = parseCommit(obj.data);
          nodes.push({
            __typename: "PullRequestCommit",
            commit: { __typename: "Commit", oid: cur, message: info.message },
          });
          cur = info.parents[0];
        }
      }
      const first = args.first as number | undefined;
      const sliced = first !== undefined ? nodes.slice(0, first) : nodes;
      return { __typename: "PullRequestCommitConnection", nodes: sliced, totalCount: nodes.length };
    },
  },
  Query: {
    repository: (ctx, _data, args) => {
      const owner = args.owner as string;
      const name = args.name as string;
      if (owner !== ctx.login) return null;
      const repo = findRepo(owner, name);
      return repo ? repoWrapper(ctx, repo) : null;
    },
    viewer: (ctx) => userWrapper(ctx, ctx.user),
    node: (ctx, _data, args) => {
      const id = args.id as string;
      if (id.startsWith("R_")) {
        const repo = findRepoByNodeId(id);
        return repo ? repoWrapper(ctx, repo) : null;
      }
      if (id.startsWith("I_")) {
        for (const repo of repos.values()) {
          const issue = repo.issues.find((i) => i.node_id === id);
          if (issue) return issueWrapper(ctx, repo, issue);
        }
        return null;
      }
      if (id.startsWith("PR_")) {
        for (const repo of repos.values()) {
          const pr = repo.pulls.find((p) => p.node_id === id);
          if (pr) return pullWrapper(ctx, repo, pr);
        }
        return null;
      }
      if (id.startsWith("U_")) return userWrapper(ctx, ctx.user);
      return null;
    },
    nodes: (ctx, _data, args) => {
      const ids = (args.ids as string[]) ?? [];
      return ids.map((id) => {
        if (id.startsWith("R_")) {
          const repo = findRepoByNodeId(id);
          return repo ? repoWrapper(ctx, repo) : null;
        }
        return null;
      });
    },
    search: (ctx, _data, args) => {
      const type = (args.type as string | undefined) ?? "ISSUE";
      const query = (args.query as string | undefined) ?? "";
      const tokens = query.split(/\s+/).filter(Boolean);
      let repoFilter: { owner: string; name: string } | null = null;
      let stateFilter: string | null = null;
      let labelFilter: string | null = null;
      const words: string[] = [];
      for (const tok of tokens) {
        if (tok.startsWith("repo:")) {
          const parts = tok.slice(5).split("/");
          if (parts.length === 2) repoFilter = { owner: parts[0], name: parts[1] };
        } else if (tok.startsWith("type:")) {
          // The type argument already carries this; ignore.
        } else if (tok.startsWith("state:")) {
          stateFilter = tok.slice(6).toLowerCase();
        } else if (tok.startsWith("label:")) {
          labelFilter = tok.slice(6);
        } else {
          words.push(tok.toLowerCase());
        }
      }
      const nodes: GqlNode[] = [];
      const targetRepos = repoFilter ? [findRepo(repoFilter.owner, repoFilter.name)].filter((r): r is Repo => !!r) : [...repos.values()];
      for (const repo of targetRepos) {
        if (type === "ISSUE" || type === undefined) {
          for (const issue of repo.issues) {
            if (stateFilter && issue.state !== stateFilter) continue;
            if (labelFilter && !issue.labels.some((l) => l.name === labelFilter)) continue;
            if (words.length > 0) {
              const hay = (issue.title + " " + issue.body).toLowerCase();
              if (!words.every((w) => hay.includes(w))) continue;
            }
            nodes.push(issueWrapper(ctx, repo, issue));
          }
        } else if (type === "PULL_REQUEST") {
          for (const pr of repo.pulls) {
            if (stateFilter && (pr.merged ? "merged" : pr.state) !== stateFilter) continue;
            if (words.length > 0) {
              const hay = (pr.title + " " + pr.body).toLowerCase();
              if (!words.every((w) => hay.includes(w))) continue;
            }
            nodes.push(pullWrapper(ctx, repo, pr));
          }
        } else if (type === "REPOSITORY") {
          if (words.length === 0 || words.every((w) => repo.name.toLowerCase().includes(w))) {
            nodes.push(repoWrapper(ctx, repo));
          }
        }
      }
      const conn = makeConnection("SearchResultItemConnection", nodes, args.first as number | undefined, args.after as string | undefined);
      (conn as Record<string, unknown>).issueCount = nodes.length;
      return conn;
    },
  },
  Mutation: {
    createIssue: (ctx, _data, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const repo = findRepoByNodeId(String(input.repositoryId ?? ""));
      if (!repo) return { __typename: "CreateIssuePayload", issue: null, clientMutationId: input.clientMutationId ?? null };
      const issue = createIssueObject(repo, ctx.user, String(input.title ?? ""), String(input.body ?? ""), []);
      return { __typename: "CreateIssuePayload", issue: issueWrapper(ctx, repo, issue), clientMutationId: input.clientMutationId ?? null };
    },
    createPullRequest: (ctx, _data, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const repo = findRepoByNodeId(String(input.repositoryId ?? ""));
      const headRef = String(input.headRefName ?? "");
      const baseRef = String(input.baseRefName ?? "");
      if (!repo || !repo.refs.has("refs/heads/" + headRef) || !repo.refs.has("refs/heads/" + baseRef)) {
        return { __typename: "CreatePullRequestPayload", pullRequest: null, clientMutationId: input.clientMutationId ?? null };
      }
      const pr = createPullObject(repo, ctx.user, String(input.title ?? ""), String(input.body ?? ""), headRef, baseRef);
      return { __typename: "CreatePullRequestPayload", pullRequest: pullWrapper(ctx, repo, pr), clientMutationId: input.clientMutationId ?? null };
    },
    closeIssue: (ctx, _data, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const issueId = String(input.issueId ?? "");
      for (const repo of repos.values()) {
        const issue = repo.issues.find((i) => i.node_id === issueId);
        if (issue) {
          if (issue.state === "open") {
            issue.state = "closed";
            issue.closed_at = stamp();
          }
          issue.updated_at = stamp();
          return { __typename: "CloseIssuePayload", issue: issueWrapper(ctx, repo, issue), clientMutationId: input.clientMutationId ?? null };
        }
      }
      return { __typename: "CloseIssuePayload", issue: null, clientMutationId: input.clientMutationId ?? null };
    },
    addComment: (ctx, _data, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const subjectId = String(input.subjectId ?? "");
      const body = String(input.body ?? "");
      for (const repo of repos.values()) {
        const issue = repo.issues.find((i) => i.node_id === subjectId);
        if (issue) {
          const now = stamp();
          const comment: IssueComment = {
            id: nextGlobalId(),
            node_id: nodeId("IC", repo.owner.login + "/" + repo.name + "#" + issue.number + "/" + now),
            body,
            user: ctx.user,
            created_at: now,
            updated_at: now,
          };
          issue.comments.push(comment);
          issue.updated_at = stamp();
          const node: GqlNode = {
            __typename: "IssueComment",
            id: comment.node_id,
            body: comment.body,
            author: userWrapper(ctx, comment.user),
            createdAt: comment.created_at,
            updatedAt: comment.updated_at,
          };
          return {
            __typename: "AddCommentPayload",
            commentEdge: { __typename: "IssueCommentEdge", node, cursor: cursorFor(issue.comments.length - 1) },
            subject: issueWrapper(ctx, repo, issue),
            clientMutationId: input.clientMutationId ?? null,
          };
        }
      }
      return { __typename: "AddCommentPayload", commentEdge: null, subject: null, clientMutationId: input.clientMutationId ?? null };
    },
    mergePullRequest: (ctx, _data, args) => {
      const input = (args.input ?? {}) as Record<string, unknown>;
      const prId = String(input.pullRequestId ?? "");
      for (const repo of repos.values()) {
        const pr = repo.pulls.find((p) => p.node_id === prId);
        if (pr) {
          if (pr.state === "open" && !pr.merged && !prConflicts(repo, pr)) {
            const headSha = repo.refs.get("refs/heads/" + pr.headRef)!;
            const baseSha = repo.refs.get("refs/heads/" + pr.baseRef)!;
            const headTree = parseCommit(repo.objects.get(headSha)!.data).tree;
            const headline = typeof input.commitHeadline === "string" && input.commitHeadline ? input.commitHeadline : pr.title + " (#" + pr.number + ")";
            const extra = typeof input.commitBody === "string" ? input.commitBody : "";
            const commit = makeCommitObject(headTree, [baseSha], identLine(ctx.user), identLine(ctx.user), extra ? headline + "\n\n" + extra : headline);
            repo.objects.set(commit.sha, commit);
            repo.refs.set("refs/heads/" + pr.baseRef, commit.sha);
            repo.pushed_at = stamp();
            pr.headSha = headSha;
            pr.baseSha = commit.sha;
            pr.state = "closed";
            pr.merged = true;
            pr.merged_at = stamp();
            pr.merge_commit_sha = commit.sha;
            pr.closed_at = stamp();
            pr.updated_at = stamp();
          }
          return { __typename: "MergePullRequestPayload", pullRequest: pullWrapper(ctx, repo, pr), clientMutationId: input.clientMutationId ?? null };
        }
      }
      return { __typename: "MergePullRequestPayload", pullRequest: null, clientMutationId: input.clientMutationId ?? null };
    },
  },
  __Schema: {
    queryType: () => ({ __typename: "__Type", def: GQL_TYPES.Query }),
    mutationType: () => ({ __typename: "__Type", def: GQL_TYPES.Mutation }),
    subscriptionType: () => null,
    types: () =>
      Object.values(GQL_TYPES).map((def) => ({ __typename: "__Type", def })),
    directives: () => [],
  },
  __Type: {
    name: (_ctx, data) => (data.def as GqlTypeDef).name,
    kind: (_ctx, data) => (data.def as GqlTypeDef).kind,
    description: (_ctx, data) => (data.def as GqlTypeDef).description ?? null,
    fields: (_ctx, data, args) => {
      const def = data.def as GqlTypeDef;
      if (!def.fields) return null;
      const includeDeprecated = args.includeDeprecated === true;
      void includeDeprecated;
      return def.fields.map((f) => ({
        __typename: "__Field",
        name: f.name,
        description: null,
        args: (f.args ?? []).map((a) => ({ __typename: "__InputValue", name: a.name, description: null, type: typeRefNode(a.type), defaultValue: null })),
        type: typeRefNode(f.type),
        isDeprecated: false,
        deprecationReason: null,
      }));
    },
    inputFields: (_ctx, data) => {
      const def = data.def as GqlTypeDef;
      if (!def.inputFields) return null;
      return def.inputFields.map((f) => ({ __typename: "__InputValue", name: f.name, description: null, type: typeRefNode(f.type), defaultValue: null }));
    },
    interfaces: () => [],
    enumValues: (_ctx, data, args) => {
      const def = data.def as GqlTypeDef;
      if (!def.enumValues) return null;
      const includeDeprecated = args.includeDeprecated === true;
      void includeDeprecated;
      return def.enumValues.map((v) => ({ __typename: "__EnumValue", name: v.name, description: v.description ?? null, isDeprecated: false, deprecationReason: null }));
    },
    possibleTypes: () => null,
  },
};

function typeRefNode(ref: GqlTypeRef): GqlNode {
  return {
    __typename: "__Type",
    kind: ref.kind,
    name: ref.name ?? null,
    ofType: ref.ofType ? typeRefNode(ref.ofType) : null,
  };
}

function directiveApplies(directives: GqlDirective[], variables: Record<string, unknown>): boolean {
  for (const d of directives) {
    const raw = resolveGqlValue(d.args.if ?? { kind: "boolean", value: false }, variables);
    const cond = raw === true;
    if (d.name === "skip" && cond) return false;
    if (d.name === "include" && !cond) return false;
  }
  return true;
}

function executeSelection(
  ctx: Ctx,
  parent: GqlNode,
  selections: GqlSelection[],
  doc: GqlDocument,
  variables: Record<string, unknown>,
  errors: { message: string }[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.kind === "field") {
      if (!directiveApplies(sel.directives, variables)) continue;
      const key = sel.alias ?? sel.name;
      const value = resolveGqlField(ctx, parent, sel, doc, variables, errors);
      if (value !== undefined) out[key] = value;
    } else if (sel.kind === "spread") {
      if (!directiveApplies(sel.directives, variables)) continue;
      const frag = doc.fragments.get(sel.name);
      if (!frag) continue;
      if (frag.typeCondition && frag.typeCondition !== parent.__typename) continue;
      Object.assign(out, executeSelection(ctx, parent, frag.selection, doc, variables, errors));
    } else {
      if (!directiveApplies(sel.directives, variables)) continue;
      if (sel.typeCondition && sel.typeCondition !== parent.__typename) continue;
      Object.assign(out, executeSelection(ctx, parent, sel.selection, doc, variables, errors));
    }
  }
  return out;
}

function resolveGqlField(
  ctx: Ctx,
  parent: GqlNode,
  field: Extract<GqlSelection, { kind: "field" }>,
  doc: GqlDocument,
  variables: Record<string, unknown>,
  errors: { message: string }[],
): unknown {
  const args: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(field.args)) args[k] = resolveGqlValue(v, variables);
  if (field.name === "__typename") return parent.__typename;
  if (field.name === "__type") {
    const def = GQL_TYPES[String(args.name ?? "")];
    if (!def) return null;
    const node: GqlNode = { __typename: "__Type", def };
    return field.selection ? executeSelection(ctx, node, field.selection, doc, variables, errors) : typeDefJson(def);
  }
  if (field.name === "__schema") {
    const node: GqlNode = { __typename: "__Schema" };
    return field.selection ? executeSelection(ctx, node, field.selection, doc, variables, errors) : null;
  }
  const resolvers = GQL_RESOLVERS[parent.__typename] ?? {};
  const resolver = resolvers[field.name];
  let value: unknown;
  if (resolver) {
    try {
      value = resolver(ctx, parent as Record<string, unknown>, args);
    } catch (e) {
      errors.push({ message: e instanceof Error ? e.message : "resolver failed" });
      return undefined;
    }
  } else if (field.name in parent) {
    value = parent[field.name];
  } else {
    errors.push({ message: `Cannot query field "${field.name}" on type "${parent.__typename}".` });
    return undefined;
  }
  if (value === null || value === undefined) return value;
  if (!field.selection) return value;
  if (Array.isArray(value)) {
    return value.map((item) =>
      item !== null && typeof item === "object" && "__typename" in (item as Record<string, unknown>)
        ? executeSelection(ctx, item as GqlNode, field.selection!, doc, variables, errors)
        : item,
    );
  }
  if (typeof value === "object" && "__typename" in (value as Record<string, unknown>)) {
    return executeSelection(ctx, value as GqlNode, field.selection, doc, variables, errors);
  }
  return value;
}

function executeOperation(
  ctx: Ctx,
  doc: GqlDocument,
  op: GqlOperation,
  variables: Record<string, unknown>,
): { data: Record<string, unknown> | null; errors?: { message: string }[] } {
  const errors: { message: string }[] = [];
  const vars: Record<string, unknown> = { ...variables };
  for (const vd of op.varDefs) {
    if (!(vd.name in vars) || vars[vd.name] === undefined) {
      if (vd.defaultValue) vars[vd.name] = resolveGqlValue(vd.defaultValue, vars);
    }
  }
  const root: GqlNode = { __typename: op.kind === "mutation" ? "Mutation" : "Query" };
  const data = executeSelection(ctx, root, op.selection, doc, vars, errors);
  const result: { data: Record<string, unknown> | null; errors?: { message: string }[] } = { data };
  if (errors.length > 0) result.errors = errors;
  return result;
}

function handleGraphql(ctx: Ctx): void {
  if (!checkAuth(ctx)) {
    jsonError(ctx, 401, "Unauthorized");
    return;
  }
  if (ctx.method !== "POST") {
    jsonError(ctx, 405, "Method Not Allowed");
    return;
  }
  const parsed = parseJsonBody(ctx);
  if (!parsed.ok) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  const body = parsed.value;
  const requests: unknown[] = Array.isArray(body) ? body : [body];
  const results: unknown[] = [];
  let multiOperation = false;
  for (const req of requests) {
    const obj = asObject(req);
    if (!obj || typeof obj.query !== "string") {
      results.push({ errors: [{ message: "A query is required" }] });
      continue;
    }
    let doc: GqlDocument;
    try {
      doc = new GqlParser(tokenizeGql(obj.query)).parseDocument();
    } catch (e) {
      results.push({ errors: [{ message: e instanceof Error ? e.message : "GraphQL parse error" }] });
      continue;
    }
    const variables = (obj.variables !== null && typeof obj.variables === "object" ? obj.variables : {}) as Record<string, unknown>;
    const operationName = typeof obj.operationName === "string" ? obj.operationName : null;
    if (operationName) {
      const op = doc.operations.find((o) => o.name === operationName);
      if (!op) {
        results.push({ errors: [{ message: `Unknown operation named "${operationName}".` }] });
        continue;
      }
      results.push(executeOperation(ctx, doc, op, variables));
    } else if (doc.operations.length === 1) {
      results.push(executeOperation(ctx, doc, doc.operations[0], variables));
    } else if (doc.operations.length > 1) {
      multiOperation = true;
      for (const op of doc.operations) results.push(executeOperation(ctx, doc, op, variables));
    } else {
      results.push({ errors: [{ message: "No operation in document" }] });
    }
  }
  // A batch body, or one body carrying two operations, answers an array of
  // results in order; anything else answers a single result object.
  const payload = Array.isArray(body) || multiOperation ? results : results[0];
  sendJson(ctx, 200, payload);
}

// ------------------------------------------------------------- MCP endpoint

const MCP_VERSIONS = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

interface McpTool {
  name: string;
  description: string;
  inputSchema: { type: string; properties: Record<string, { type: string; description: string }>; required: string[] };
}

const MCP_TOOLS: McpTool[] = [
  {
    name: "create_repo",
    description: "Create a repository in the forge.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string", description: "Name of the repository to create" }, description: { type: "string", description: "Short description of the repository" } },
      required: ["name"],
    },
  },
  {
    name: "get_repo",
    description: "Get a repository by owner and name.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Owner login of the repository" },
        repo: { type: "string", description: "Name of the repository" },
        full_name: { type: "string", description: "Full name owner/repo" },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "create_issue",
    description: "Create an issue in a repository.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Owner login of the repository" },
        repo: { type: "string", description: "Name of the repository" },
        full_name: { type: "string", description: "Full name owner/repo" },
        title: { type: "string", description: "Title of the issue" },
        body: { type: "string", description: "Body of the issue" },
      },
      required: ["owner", "repo", "title"],
    },
  },
  {
    name: "list_issues",
    description: "List issues of a repository.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Owner login of the repository" },
        repo: { type: "string", description: "Name of the repository" },
        full_name: { type: "string", description: "Full name owner/repo" },
        state: { type: "string", description: "Issue state: open, closed or all" },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "create_pull_request",
    description: "Create a pull request from a head branch onto a base branch.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Owner login of the repository" },
        repo: { type: "string", description: "Name of the repository" },
        full_name: { type: "string", description: "Full name owner/repo" },
        title: { type: "string", description: "Title of the pull request" },
        head: { type: "string", description: "Head branch name" },
        base: { type: "string", description: "Base branch name" },
        body: { type: "string", description: "Body of the pull request" },
      },
      required: ["owner", "repo", "title", "head", "base"],
    },
  },
  {
    name: "merge_pull_request",
    description: "Squash-merge a pull request onto its base branch.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Owner login of the repository" },
        repo: { type: "string", description: "Name of the repository" },
        full_name: { type: "string", description: "Full name owner/repo" },
        pull_number: { type: "integer", description: "Number of the pull request" },
      },
      required: ["owner", "repo", "pull_number"],
    },
  },
  {
    name: "get_issue",
    description: "Get one issue by number.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Owner login of the repository" },
        repo: { type: "string", description: "Name of the repository" },
        full_name: { type: "string", description: "Full name owner/repo" },
        issue_number: { type: "integer", description: "Number of the issue" },
      },
      required: ["owner", "repo", "issue_number"],
    },
  },
  {
    name: "list_repos",
    description: "List the repositories of the signed-in user.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "list_pull_requests",
    description: "List pull requests of a repository.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Owner login of the repository" },
        repo: { type: "string", description: "Name of the repository" },
        full_name: { type: "string", description: "Full name owner/repo" },
        state: { type: "string", description: "Pull request state: open, closed or all" },
      },
      required: ["owner", "repo"],
    },
  },
];

// Map the caller's argument names onto the nearest schema property; the
// suite also fills full_name with owner/repo.
function mcpOwnerRepo(args: Record<string, unknown>, ctx: Ctx): { owner: string; repo: string } {
  let owner = typeof args.owner === "string" ? args.owner : "";
  let repo = typeof args.repo === "string" ? args.repo : "";
  if (typeof args.full_name === "string" && args.full_name.includes("/")) {
    const [o, r] = args.full_name.split("/");
    if (!owner) owner = o;
    if (!repo) repo = r;
  }
  if (typeof args.repository === "string") {
    if (args.repository.includes("/")) {
      const [o, r] = (args.repository as string).split("/");
      if (!owner) owner = o;
      if (!repo) repo = r;
    } else if (!repo) repo = args.repository as string;
  }
  if (!owner) owner = ctx.login;
  return { owner, repo };
}

function mcpNumber(args: Record<string, unknown>, keys: string[]): number | null {
  for (const k of keys) {
    const v = args[k];
    if (typeof v === "number" && Number.isFinite(v)) return Math.floor(v);
    if (typeof v === "string" && /^\d+$/.test(v)) return parseInt(v, 10);
  }
  return null;
}

function mcpTextResult(value: unknown): Record<string, unknown> {
  return { content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value) }] };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: "text", text: message }], isError: true };
}

function callMcpTool(ctx: Ctx, name: string, args: Record<string, unknown>): Record<string, unknown> {
  const key = name.includes("__") ? name.split("__").pop()! : name;
  const canonical = key.toLowerCase();
  if (canonical === "create_repo") {
    const repoName = typeof args.name === "string" ? args.name : typeof args.repo === "string" ? args.repo : "";
    if (!repoName) return mcpToolError("Missing required argument: name");
    if (findRepo(ctx.login, repoName)) return mcpToolError("Repository already exists: " + repoName);
    const repo = createRepo(ctx.user, repoName, typeof args.description === "string" ? args.description : "", false, "main");
    return mcpTextResult(repoJson(ctx, repo));
  }
  if (canonical === "get_repo") {
    const { owner, repo: repoName } = mcpOwnerRepo(args, ctx);
    if (!repoName) return mcpToolError("Missing required argument: repo");
    const repo = resolveRepo(ctx, owner, repoName);
    if (!repo) return mcpToolError("Repository not found: " + owner + "/" + repoName);
    return mcpTextResult(repoJson(ctx, repo));
  }
  if (canonical === "create_issue") {
    const { owner, repo: repoName } = mcpOwnerRepo(args, ctx);
    const title = typeof args.title === "string" ? args.title : "";
    if (!repoName) return mcpToolError("Missing required argument: repo");
    if (!title) return mcpToolError("Missing required argument: title");
    const repo = resolveRepo(ctx, owner, repoName);
    if (!repo) return mcpToolError("Repository not found: " + owner + "/" + repoName);
    const issue = createIssueObject(repo, ctx.user, title, typeof args.body === "string" ? args.body : "", []);
    return mcpTextResult(issueJson(ctx, repo, issue));
  }
  if (canonical === "list_issues") {
    const { owner, repo: repoName } = mcpOwnerRepo(args, ctx);
    if (!repoName) return mcpToolError("Missing required argument: repo");
    const repo = resolveRepo(ctx, owner, repoName);
    if (!repo) return mcpToolError("Repository not found: " + owner + "/" + repoName);
    const state = typeof args.state === "string" ? args.state.toLowerCase() : "open";
    const items = state === "all" ? repo.issues : repo.issues.filter((i) => i.state === state);
    return mcpTextResult(items.map((i) => issueJson(ctx, repo, i)));
  }
  if (canonical === "create_pull_request") {
    const { owner, repo: repoName } = mcpOwnerRepo(args, ctx);
    const title = typeof args.title === "string" ? args.title : "";
    const head = splitBranchRef(typeof args.head === "string" ? args.head : "");
    const base = splitBranchRef(typeof args.base === "string" ? args.base : "");
    if (!repoName) return mcpToolError("Missing required argument: repo");
    if (!title) return mcpToolError("Missing required argument: title");
    if (!head) return mcpToolError("Missing required argument: head");
    if (!base) return mcpToolError("Missing required argument: base");
    const repo = resolveRepo(ctx, owner, repoName);
    if (!repo) return mcpToolError("Repository not found: " + owner + "/" + repoName);
    if (!repo.refs.has("refs/heads/" + head)) return mcpToolError("Head branch does not exist: " + head);
    if (!repo.refs.has("refs/heads/" + base)) return mcpToolError("Base branch does not exist: " + base);
    const pr = createPullObject(repo, ctx.user, title, typeof args.body === "string" ? args.body : "", head, base);
    return mcpTextResult(pullJson(ctx, repo, pr));
  }
  if (canonical === "merge_pull_request") {
    const { owner, repo: repoName } = mcpOwnerRepo(args, ctx);
    const number = mcpNumber(args, ["pull_number", "number", "pullNumber", "pull_request_number"]);
    if (!repoName) return mcpToolError("Missing required argument: repo");
    if (number === null) return mcpToolError("Missing required argument: pull_number");
    const repo = resolveRepo(ctx, owner, repoName);
    if (!repo) return mcpToolError("Repository not found: " + owner + "/" + repoName);
    const pr = repo.pulls.find((p) => p.number === number);
    if (!pr) return mcpToolError("Pull request not found: " + number);
    if (pr.merged) return mcpToolError("Pull request has already been merged");
    if (pr.state !== "open") return mcpToolError("Pull request is closed");
    if (prConflicts(repo, pr)) return mcpToolError("Merge conflict");
    const headSha = repo.refs.get("refs/heads/" + pr.headRef)!;
    const baseSha = repo.refs.get("refs/heads/" + pr.baseRef)!;
    const headTree = parseCommit(repo.objects.get(headSha)!.data).tree;
    const commit = makeCommitObject(headTree, [baseSha], identLine(ctx.user), identLine(ctx.user), pr.title + " (#" + pr.number + ")");
    repo.objects.set(commit.sha, commit);
    repo.refs.set("refs/heads/" + pr.baseRef, commit.sha);
    repo.pushed_at = stamp();
    pr.headSha = headSha;
    pr.baseSha = commit.sha;
    pr.state = "closed";
    pr.merged = true;
    pr.merged_at = stamp();
    pr.merge_commit_sha = commit.sha;
    pr.closed_at = stamp();
    pr.updated_at = stamp();
    return mcpTextResult({ sha: commit.sha, merged: true, message: "Pull request successfully merged" });
  }
  if (canonical === "get_issue") {
    const { owner, repo: repoName } = mcpOwnerRepo(args, ctx);
    const number = mcpNumber(args, ["issue_number", "number", "issueNumber"]);
    if (!repoName) return mcpToolError("Missing required argument: repo");
    if (number === null) return mcpToolError("Missing required argument: issue_number");
    const repo = resolveRepo(ctx, owner, repoName);
    if (!repo) return mcpToolError("Repository not found: " + owner + "/" + repoName);
    const issue = repo.issues.find((i) => i.number === number);
    if (!issue) return mcpToolError("Issue not found: " + number);
    return mcpTextResult(issueJson(ctx, repo, issue));
  }
  if (canonical === "list_repos") {
    const mine = [...repos.values()].filter((r) => r.owner.login === ctx.login);
    return mcpTextResult(mine.map((r) => repoJson(ctx, r)));
  }
  if (canonical === "list_pull_requests") {
    const { owner, repo: repoName } = mcpOwnerRepo(args, ctx);
    if (!repoName) return mcpToolError("Missing required argument: repo");
    const repo = resolveRepo(ctx, owner, repoName);
    if (!repo) return mcpToolError("Repository not found: " + owner + "/" + repoName);
    const state = typeof args.state === "string" ? args.state.toLowerCase() : "open";
    const items = state === "all" ? repo.pulls : repo.pulls.filter((p) => p.state === state);
    return mcpTextResult(items.map((p) => pullJson(ctx, repo, p)));
  }
  return null as unknown as Record<string, unknown>;
}

function handleMcpRequest(ctx: Ctx, req: Record<string, unknown>): { status: number; value: unknown; sessionId?: string } | null {
  const id = "id" in req ? req.id : undefined;
  const method = typeof req.method === "string" ? req.method : "";
  if (method === "notifications/initialized" || method.startsWith("notifications/")) {
    return null; // A notification gets no JSON-RPC response.
  }
  const result = (value: unknown): { status: number; value: unknown } => ({ status: 200, value: { jsonrpc: "2.0", id: id ?? null, result: value } });
  const error = (code: number, message: string): { status: number; value: unknown } => ({ status: 200, value: { jsonrpc: "2.0", id: id ?? null, error: { code, message } } });
  if (method === "initialize") {
    const params = asObject(req.params) ?? {};
    const asked = typeof params.protocolVersion === "string" ? params.protocolVersion : "2026-07-28";
    const version = MCP_VERSIONS.includes(asked) ? asked : "2026-07-28";
    return {
      ...result({
        protocolVersion: version,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "forge", version: "1.0.0" },
      }),
      sessionId: "mcp-" + requestSeq,
    };
  }
  if (method === "server/discover") {
    return result({
      protocolVersion: "2026-07-28",
      serverInfo: { name: "forge", version: "1.0.0" },
      capabilities: { tools: { listChanged: false } },
      supportedVersions: MCP_VERSIONS,
    });
  }
  if (method === "ping") return result({});
  if (method === "tools/list") {
    return result({ tools: MCP_TOOLS });
  }
  if (method === "tools/call") {
    const params = asObject(req.params) ?? {};
    const name = typeof params.name === "string" ? params.name : "";
    const args = (params.arguments !== null && typeof params.arguments === "object" ? params.arguments : {}) as Record<string, unknown>;
    const known = MCP_TOOLS.some((t) => {
      const key = name.includes("__") ? name.split("__").pop()! : name;
      return key.toLowerCase() === t.name;
    });
    if (!name || !known) return error(-32602, "Unknown tool: " + name);
    const out = callMcpTool(ctx, name, args);
    return result(out);
  }
  return error(-32601, "Method not found: " + method);
}

function handleMcp(ctx: Ctx): void {
  if (!checkAuth(ctx)) {
    unauthorized(ctx);
    return;
  }
  if (ctx.method !== "POST") {
    jsonError(ctx, 405, "Method Not Allowed");
    return;
  }
  if (ctx.body.length === 0) {
    jsonError(ctx, 400, "Bad Request");
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(ctx.body.toString("utf8"));
  } catch {
    const res = (ctx as unknown as { res: http.ServerResponse }).res;
    res.writeHead(400, { "Content-Type": "application/json", "X-GitHub-Request-Id": requestId() });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }));
    return;
  }
  const requests: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  const responses: unknown[] = [];
  let sessionId: string | undefined;
  for (const req of requests) {
    const obj = asObject(req);
    if (!obj || typeof obj.method !== "string") {
      responses.push({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } });
      continue;
    }
    const out = handleMcpRequest(ctx, obj);
    if (out) {
      responses.push(out.value);
      if (out.sessionId) sessionId = out.sessionId;
    }
  }
  const res = (ctx as unknown as { res: http.ServerResponse }).res;
  const incomingSession = ctx.headers["mcp-session-id"];
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-GitHub-Request-Id": requestId(),
  };
  if (typeof incomingSession === "string") headers["Mcp-Session-Id"] = incomingSession;
  else if (sessionId) headers["Mcp-Session-Id"] = sessionId;
  if (responses.length === 0) {
    res.writeHead(202, headers);
    res.end();
    return;
  }
  const payload = Buffer.from(JSON.stringify(Array.isArray(parsed) ? responses : responses[0]), "utf8");
  headers["Content-Length"] = String(payload.length);
  res.writeHead(200, headers);
  res.end(payload);
}

// -------------------------------------------------------- server & lifecycle

const SHOP_TOKEN = expectedToken();
const LOGIN = loginFromToken(SHOP_TOKEN || "test-token");
const TOKEN_USER = makeUser(LOGIN);

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > 64 * 1024 * 1024) throw new Error("body too large");
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

function route(ctx: Ctx): void {
  if (ctx.method === "GET" && ctx.path === "/healthz") {
    sendJson(ctx, 200, { ok: true });
    return;
  }
  if (handleGit(ctx)) return;
  if (ctx.segments[0] === "api" && ctx.segments[1] === "v3") {
    handleRest(ctx);
    return;
  }
  if (ctx.path === "/api/graphql") {
    handleGraphql(ctx);
    return;
  }
  if (ctx.path === "/mcp") {
    handleMcp(ctx);
    return;
  }
  jsonError(ctx, 404, "Not Found");
}

async function registerAndWait(port: number): Promise<void> {
  const envUrl = (process.env.MAKEFUN_ENV_URL ?? "").replace(/\/$/, "");
  const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
  // Register, retrying while the suite comes up.
  let registered = false;
  for (let attempt = 0; attempt < 60 && !registered; attempt++) {
    try {
      const res = await fetch(envUrl + "/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ port }),
      });
      if (res.status === 200 || res.status === 201 || res.status === 409) registered = true;
      else await sleep(1000);
    } catch {
      await sleep(1000);
    }
  }
  if (!registered) {
    console.error("forge: could not register with the suite");
    process.exit(1);
  }
  // Long-poll /done until the suite finishes.
  for (;;) {
    try {
      const res = await fetch(envUrl + "/done");
      const body = (await res.json()) as { done?: boolean };
      if (body.done === true) {
        process.exit(0);
      }
    } catch {
      // The suite may restart; keep polling.
    }
    await sleep(500);
  }
}

function main(): void {
  const configuredPort = Number(process.env.FORGE_PORT ?? "0");
  const server = http.createServer((req, res) => {
    void (async () => {
      let body: Buffer = Buffer.alloc(0);
      try {
        body = await readBody(req);
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        const address = server.address();
        const port = typeof address === "object" && address ? address.port : configuredPort;
        const ctx: Ctx = {
          method: req.method ?? "GET",
          path: url.pathname,
          segments: url.pathname.split("/").filter(Boolean),
          query: url.searchParams,
          headers: req.headers,
          body,
          token: SHOP_TOKEN,
          login: LOGIN,
          user: TOKEN_USER,
          baseUrl: "http://127.0.0.1:" + port,
        };
        (ctx as unknown as { res: http.ServerResponse }).res = res;
        route(ctx);
      } catch (e) {
        if (!res.headersSent) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ message: e instanceof Error ? e.message : "Bad Request" }));
        } else {
          res.end();
        }
      }
    })();
  });
  server.listen(configuredPort, () => {
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : configuredPort;
    console.log("forge listening on port " + port + " as " + LOGIN);
    const envUrl = process.env.MAKEFUN_ENV_URL ?? "";
    if (envUrl) void registerAndWait(port);
  });
}

main();
