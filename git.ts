// git.ts — the forge's git layer, written from the git object model and the
// smart-HTTP protocol: SHA-1 addressed objects, trees/commits/tags, packfiles
// (plain objects plus OFS/REF delta resolution), pkt-lines, reachability and
// ancestry walks, tree merges and line diffs. Node builtins only.

import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

export type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
export const ZERO_OID = '0000000000000000000000000000000000000000';
export const TYPE_TO_NUM: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
export const NUM_TO_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

export interface GitObject {
  type: ObjType;
  data: Buffer;
}

export function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

export function hashObject(type: ObjType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, data]));
}

/** The in-memory object database of one repository. */
export class ObjectStore {
  readonly objects = new Map<string, GitObject>();

  has(oid: string): boolean {
    return this.objects.has(oid);
  }

  get(oid: string): GitObject | undefined {
    return this.objects.get(oid);
  }

  /** Store raw content; returns its oid. Storing the same content twice is a no-op. */
  put(type: ObjType, data: Buffer): string {
    const oid = hashObject(type, data);
    if (!this.objects.has(oid)) this.objects.set(oid, { type, data });
    return oid;
  }

  putKnown(oid: string, type: ObjType, data: Buffer): void {
    if (!this.objects.has(oid)) this.objects.set(oid, { type, data });
  }
}

/* ------------------------------------------------------------------ trees */

export interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

export function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space);
    entries.push({
      mode: data.toString('utf8', offset, space),
      name: data.toString('utf8', space + 1, nul),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

/** Git orders tree entries by name, with directory names compared as if they ended in '/'. */
function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

export function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const ka = treeSortKey(a);
    const kb = treeSortKey(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

/* ---------------------------------------------------------------- commits */

export interface CommitInfo {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

export function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const header = split === -1 ? text : text.slice(0, split);
  const message = split === -1 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of header.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

export function buildCommit(info: CommitInfo): Buffer {
  const lines = [`tree ${info.tree}`];
  for (const parent of info.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${info.author}`);
  lines.push(`committer ${info.committer}`);
  return Buffer.from(`${lines.join('\n')}\n\n${info.message}`, 'utf8');
}

/** Split an ident line ("Name <email> 1700000000 +0000") into its parts. */
export function parseIdent(ident: string): { name: string; email: string; date: string } {
  const match = /^(.*?) <(.*?)> (\d+) ([+-]\d{4})$/.exec(ident.trim());
  if (!match) return { name: ident, email: '', date: new Date(0).toISOString() };
  return {
    name: match[1],
    email: match[2],
    date: new Date(Number(match[3]) * 1000).toISOString(),
  };
}

export interface TagInfo {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

export function parseTag(data: Buffer): TagInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const header = split === -1 ? text : text.slice(0, split);
  const out: TagInfo = { object: '', type: '', tag: '', tagger: '', message: split === -1 ? '' : text.slice(split + 2) };
  for (const line of header.split('\n')) {
    if (line.startsWith('object ')) out.object = line.slice(7).trim();
    else if (line.startsWith('type ')) out.type = line.slice(5).trim();
    else if (line.startsWith('tag ')) out.tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) out.tagger = line.slice(7);
  }
  return out;
}

/* ------------------------------------------------------------- reachability */

/** Follow tag objects until a commit (or another type) is reached. */
export function peelToCommit(store: ObjectStore, oid: string): string | null {
  let current = oid;
  for (let hops = 0; hops < 32; hops += 1) {
    const obj = store.get(current);
    if (!obj) return null;
    if (obj.type === 'commit') return current;
    if (obj.type === 'tag') {
      current = parseTag(obj.data).object;
      continue;
    }
    return null;
  }
  return null;
}

/**
 * Every object reachable from the given tips. When a commit is in
 * `stopParentsOf`, the commit itself (and its trees) count as reachable but
 * its parents are not walked — the shallow-boundary rule a fetch applies to
 * the client's own shallow list.
 */
export function collectReachable(
  store: ObjectStore,
  tips: Iterable<string>,
  stopParentsOf?: ReadonlySet<string>,
): Set<string> {
  const seen = new Set<string>();
  const stack: string[] = [...tips];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = store.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const commit = parseCommit(obj.data);
      stack.push(commit.tree);
      if (!stopParentsOf || !stopParentsOf.has(oid)) stack.push(...commit.parents);
    } else if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) stack.push(entry.oid);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    }
  }
  return seen;
}

/** True when `ancestor` is reachable from `descendant` by parent walks (tags peeled). */
export function isAncestor(store: ObjectStore, ancestor: string, descendant: string): boolean {
  const target = peelToCommit(store, ancestor) ?? ancestor;
  const start = peelToCommit(store, descendant) ?? descendant;
  if (target === start) return true;
  const seen = new Set<string>();
  const stack = [start];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (oid === target) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = store.get(oid);
    if (obj && obj.type === 'commit') stack.push(...parseCommit(obj.data).parents);
  }
  return false;
}

/** A best common ancestor of two commits, or null when they share no history. */
export function mergeBase(store: ObjectStore, a: string, b: string): string | null {
  const fromA = new Set<string>();
  const stackA = [a];
  while (stackA.length > 0) {
    const oid = stackA.pop() as string;
    if (fromA.has(oid)) continue;
    fromA.add(oid);
    const obj = store.get(oid);
    if (obj && obj.type === 'commit') stackA.push(...parseCommit(obj.data).parents);
  }
  const seen = new Set<string>();
  const queue = [b];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (fromA.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = store.get(oid);
    if (obj && obj.type === 'commit') queue.push(...parseCommit(obj.data).parents);
  }
  return null;
}

/** Commits reachable from `tip`, newest first (breadth-first over parents). */
export function listCommits(store: ObjectStore, tip: string): string[] {
  const order: string[] = [];
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    const obj = store.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    seen.add(oid);
    order.push(oid);
    queue.push(...parseCommit(obj.data).parents);
  }
  return order;
}

/* ------------------------------------------------------------ tree flattening */

export interface FileEntry {
  mode: string;
  oid: string;
}

/** Flatten a tree (recursively) into path → blob entry. Empty tree → empty map. */
export function flattenTree(store: ObjectStore, treeOid: string): Map<string, FileEntry> {
  const out = new Map<string, FileEntry>();
  const walk = (oid: string, prefix: string): void => {
    const obj = store.get(oid);
    if (!obj || obj.type !== 'tree') return;
    for (const entry of parseTree(obj.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, { mode: entry.mode, oid: entry.oid });
    }
  };
  if (treeOid !== ZERO_OID && store.has(treeOid)) walk(treeOid, '');
  return out;
}

/** The empty tree's oid (4b825dc…) — computed, not stored, until something references it. */
export const EMPTY_TREE_OID = hashObject('tree', Buffer.alloc(0));

/** Build (and store) nested trees for a flat path → blob map; returns the root tree oid. */
export function buildTreeFromFiles(store: ObjectStore, files: Map<string, FileEntry>): string {
  interface Dir {
    files: Map<string, FileEntry>;
    dirs: Map<string, Dir>;
  }
  const root: Dir = { files: new Map(), dirs: new Map() };
  for (const [path, entry] of files) {
    const parts = path.split('/');
    let dir = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      let next = dir.dirs.get(parts[i]);
      if (!next) {
        next = { files: new Map(), dirs: new Map() };
        dir.dirs.set(parts[i], next);
      }
      dir = next;
    }
    dir.files.set(parts[parts.length - 1], entry);
  }
  const emit = (dir: Dir): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of dir.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, sub] of dir.dirs) entries.push({ mode: '40000', name, oid: emit(sub) });
    return store.put('tree', buildTree(entries));
  };
  return emit(root);
}

/* ------------------------------------------------------------------ merging */

/**
 * Three-way merge of two flattened trees against their common base.
 * Returns the merged file map, or the first conflicting path.
 */
export function mergeFileMaps(
  base: Map<string, FileEntry>,
  ours: Map<string, FileEntry>,
  theirs: Map<string, FileEntry>,
): { files: Map<string, FileEntry> } | { conflict: string } {
  const merged = new Map<string, FileEntry>();
  const paths = new Set<string>([...base.keys(), ...ours.keys(), ...theirs.keys()]);
  const same = (x?: FileEntry, y?: FileEntry): boolean =>
    x === undefined && y === undefined ? true : x !== undefined && y !== undefined && x.oid === y.oid && x.mode === y.mode;
  for (const path of paths) {
    const b = base.get(path);
    const o = ours.get(path);
    const t = theirs.get(path);
    if (same(o, t)) {
      if (o) merged.set(path, o);
    } else if (same(b, o)) {
      if (t) merged.set(path, t);
    } else if (same(b, t)) {
      if (o) merged.set(path, o);
    } else {
      return { conflict: path };
    }
  }
  return { files: merged };
}

/* --------------------------------------------------------------------- diff */

export interface FileDiff {
  filename: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
  changes: number;
}

function splitLines(text: string): string[] {
  if (text === '') return [];
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/** Line-level diff counts via multiset intersection of lines. */
export function diffFileMaps(
  store: ObjectStore,
  before: Map<string, FileEntry>,
  after: Map<string, FileEntry>,
): FileDiff[] {
  const diffs: FileDiff[] = [];
  const paths = new Set<string>([...before.keys(), ...after.keys()]);
  for (const path of [...paths].sort()) {
    const b = before.get(path);
    const a = after.get(path);
    if (b && a && b.oid === a.oid) continue;
    const oldText = b ? (store.get(b.oid)?.data.toString('utf8') ?? '') : '';
    const newText = a ? (store.get(a.oid)?.data.toString('utf8') ?? '') : '';
    const oldLines = splitLines(oldText);
    const newLines = splitLines(newText);
    const counts = new Map<string, number>();
    for (const line of oldLines) counts.set(line, (counts.get(line) ?? 0) + 1);
    let common = 0;
    for (const line of newLines) {
      const left = counts.get(line) ?? 0;
      if (left > 0) {
        common += 1;
        counts.set(line, left - 1);
      }
    }
    const additions = newLines.length - common;
    const deletions = oldLines.length - common;
    diffs.push({
      filename: path,
      status: !b ? 'added' : !a ? 'removed' : 'modified',
      additions,
      deletions,
      changes: additions + deletions,
    });
  }
  return diffs;
}

/* ---------------------------------------------------------------- pkt-lines */

export function pktLine(payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const size = body.length + 4;
  if (size > 0xffff) throw new Error(`pkt-line payload too large: ${body.length}`);
  return Buffer.concat([Buffer.from(size.toString(16).padStart(4, '0'), 'ascii'), body]);
}

export const PKT_FLUSH = Buffer.from('0000', 'ascii');
export const PKT_DELIM = Buffer.from('0001', 'ascii');
export const PKT_RESPONSE_END = Buffer.from('0002', 'ascii');

export interface ParsedPackets {
  packets: Buffer[];
  rest: Buffer;
  sawFlush: boolean;
}

/** Parse pkt-lines until the first flush packet (or end of input); the remainder is returned raw. */
export function parsePktLines(buffer: Buffer): ParsedPackets {
  const packets: Buffer[] = [];
  let offset = 0;
  let sawFlush = false;
  while (offset + 4 <= buffer.length) {
    const sizeText = buffer.toString('ascii', offset, offset + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(sizeText)) throw new Error(`invalid pkt-line header at ${offset}`);
    const size = parseInt(sizeText, 16);
    if (size === 0) {
      offset += 4;
      sawFlush = true;
      break;
    }
    if (size === 1 || size === 2) {
      packets.push(Buffer.from([size]));
      offset += 4;
      continue;
    }
    if (size < 4 || offset + size > buffer.length) throw new Error(`truncated pkt-line at ${offset}`);
    packets.push(buffer.subarray(offset + 4, offset + size));
    offset += size;
  }
  return { packets, rest: buffer.subarray(offset), sawFlush };
}

/* --------------------------------------------------------------- packfiles */

export function encodePackObjectHeader(type: ObjType, size: number): Buffer {
  let value = size;
  const first = ((TYPE_TO_NUM[type] & 0x07) << 4) | (value & 0x0f);
  value = Math.floor(value / 16);
  const bytes = [first | (value > 0 ? 0x80 : 0)];
  while (value > 0) {
    const byte = value & 0x7f;
    value = Math.floor(value / 128);
    bytes.push(byte | (value > 0 ? 0x80 : 0));
  }
  return Buffer.from(bytes);
}

export function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset];
      offset += 1;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if ((byte & 0x80) === 0) return value;
    }
  };
  const sourceSize = readVarint();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const targetSize = readVarint();
  const out: Buffer[] = [];
  let produced = 0;
  while (offset < delta.length) {
    const op = delta[offset];
    offset += 1;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) {
          copyOffset += delta[offset] * 2 ** (8 * bit);
          offset += 1;
        }
      }
      for (let bit = 0; bit < 3; bit += 1) {
        if (op & (0x10 << bit)) {
          copySize += delta[offset] * 2 ** (8 * bit);
          offset += 1;
        }
      }
      if (copySize === 0) copySize = 0x10000;
      out.push(base.subarray(copyOffset, copyOffset + copySize));
      produced += copySize;
    } else if (op !== 0) {
      out.push(delta.subarray(offset, offset + op));
      produced += op;
      offset += op;
    } else {
      throw new Error('delta opcode 0 is reserved');
    }
  }
  const result = Buffer.concat(out);
  if (produced !== targetSize || result.length !== targetSize) throw new Error('delta result size mismatch');
  return result;
}

/**
 * Inflate one deflate stream at the start of `buffer`, returning the data and
 * the exact number of input bytes consumed. Node's zlib does not report the
 * consumed length, so it is found by binary search: a shorter prefix truncates
 * the stream's final block and fails, a longer one succeeds with the same
 * output (trailing bytes are ignored), so the shortest succeeding prefix is
 * the stream's true end.
 */
export function inflateExact(buffer: Buffer): { data: Buffer; consumed: number } {
  const succeeds = (length: number): boolean => {
    try {
      inflateSync(buffer.subarray(0, length));
      return true;
    } catch {
      return false;
    }
  };
  let hi = Math.min(buffer.length, 128);
  while (!succeeds(hi)) {
    if (hi >= buffer.length) throw new Error('corrupt deflate stream in pack');
    hi = Math.min(buffer.length, hi * 4);
  }
  let lo = 1;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (succeeds(mid)) hi = mid;
    else lo = mid + 1;
  }
  return { data: inflateSync(buffer.subarray(0, lo)), consumed: lo };
}

export interface PackEntry {
  oid: string;
  type: ObjType;
  data: Buffer;
}

/**
 * Parse a packfile into resolved objects. `resolveExternal` supplies base
 * objects for REF deltas whose base is not in the pack (thin packs).
 */
export function readPack(pack: Buffer, resolveExternal?: (oid: string) => GitObject | undefined): PackEntry[] {
  if (pack.length < 12 + 20 || pack.toString('ascii', 0, 4) !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const trailer = pack.subarray(pack.length - 20);
  const digest = createHash('sha1').update(pack.subarray(0, pack.length - 20)).digest();
  if (!digest.equals(trailer)) throw new Error('pack checksum mismatch');

  interface RawEntry {
    typeNum: number;
    data: Buffer;
    offset: number;
    baseOid?: string;
    baseOffset?: number;
  }
  const raw: RawEntry[] = [];
  let offset = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = offset;
    let byte = pack[offset];
    offset += 1;
    const typeNum = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = pack[offset];
      offset += 1;
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    let baseOid: string | undefined;
    let baseOffset: number | undefined;
    if (typeNum === 6) {
      // OFS_DELTA: negative offset encoded in a variable-length form.
      byte = pack[offset];
      offset += 1;
      let back = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[offset];
        offset += 1;
        back = (back + 1) * 128 + (byte & 0x7f);
      }
      baseOffset = entryOffset - back;
    } else if (typeNum === 7) {
      baseOid = pack.toString('hex', offset, offset + 20);
      offset += 20;
    }
    const inflated = inflateExact(pack.subarray(offset, pack.length - 20));
    if (inflated.data.length !== size) throw new Error('pack entry size mismatch');
    offset += inflated.consumed;
    raw.push({ typeNum, data: inflated.data, offset: entryOffset, baseOid, baseOffset });
  }

  const byOffset = new Map<number, PackEntry>();
  const byOid = new Map<string, PackEntry>();
  const resolveAt = (index: number): PackEntry => {
    const entry = raw[index];
    if (entry.typeNum !== 6 && entry.typeNum !== 7) {
      const type = NUM_TO_TYPE[entry.typeNum];
      if (!type) throw new Error(`unknown pack object type ${entry.typeNum}`);
      const resolved: PackEntry = { oid: hashObject(type, entry.data), type, data: entry.data };
      byOffset.set(entry.offset, resolved);
      byOid.set(resolved.oid, resolved);
      return resolved;
    }
    let base: PackEntry | undefined;
    if (entry.typeNum === 6) {
      base = byOffset.get(entry.baseOffset as number);
      if (!base) {
        const baseIndex = raw.findIndex((candidate) => candidate.offset === entry.baseOffset);
        if (baseIndex === -1) throw new Error('ofs-delta base not in pack');
        base = resolveAt(baseIndex);
      }
    } else {
      base = byOid.get(entry.baseOid as string);
      if (!base && resolveExternal) {
        const external = resolveExternal(entry.baseOid as string);
        if (external) base = { oid: entry.baseOid as string, type: external.type, data: external.data };
      }
      if (!base) {
        const baseIndex = raw.findIndex(
          (candidate) => candidate.typeNum !== 6 && candidate.typeNum !== 7 && hashObject(NUM_TO_TYPE[candidate.typeNum], candidate.data) === entry.baseOid,
        );
        if (baseIndex !== -1) base = resolveAt(baseIndex);
      }
      if (!base) throw new Error('ref-delta base not available');
    }
    const data = applyDelta(base.data, entry.data);
    const resolved: PackEntry = { oid: hashObject(base.type, data), type: base.type, data };
    byOffset.set(entry.offset, resolved);
    byOid.set(resolved.oid, resolved);
    return resolved;
  };
  return raw.map((_, index) => resolveAt(index));
}

/** Serialize objects into a version-2 packfile of plain (non-delta) objects. */
export function writePack(objects: GitObject[]): Buffer {
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  const parts: Buffer[] = [header];
  for (const obj of objects) {
    parts.push(encodePackObjectHeader(obj.type, obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}
