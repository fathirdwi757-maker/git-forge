// githttp.ts — git smart HTTP: info/refs advertisement (protocol v0 and v2),
// protocol-v2 ls-refs and fetch (with shallow/deepen semantics), a v0 fetch
// fallback, and receive-pack pushes with report-status. The wire format here
// is the one real git and the contest's own client speak: pkt-lines, sideband
// packets for pack data, and SHA-1 checksummed packfiles.

import {
  PKT_DELIM,
  PKT_FLUSH,
  ZERO_OID,
  collectReachable,
  isAncestor,
  parseCommit,
  parsePktLines,
  parseTag,
  pktLine,
  readPack,
  writePack,
  type GitObject,
} from './git.ts';
import { Repo } from './forge.ts';

const AGENT = 'git-forge/1.0.0';

/* ------------------------------------------------------------ advertisement */

interface RefLine {
  oid: string;
  name: string;
  peeled?: string;
}

/** HEAD first, then refs in name order, annotated tags followed by their peeled line. */
function sortedRefLines(repo: Repo): RefLine[] {
  const lines: RefLine[] = [];
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    const oid = repo.refs.get(name) as string;
    lines.push({ oid, name });
    const obj = repo.store.get(oid);
    if (obj && obj.type === 'tag') {
      let target = parseTag(obj.data).object;
      let hops = 0;
      while (hops < 32) {
        const targetObj = repo.store.get(target);
        if (!targetObj || targetObj.type !== 'tag') break;
        target = parseTag(targetObj.data).object;
        hops += 1;
      }
      const targetObj = repo.store.get(target);
      if (targetObj && targetObj.type === 'commit' && target !== oid) {
        lines.push({ oid: target, name: `${name}^{}` });
      }
    }
  }
  return lines;
}

export function advertise(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack', protocolV2: boolean): Buffer {
  if (service === 'git-upload-pack' && protocolV2) {
    const parts = [
      pktLine('version 2\n'),
      pktLine(`agent=${AGENT}\n`),
      pktLine('ls-refs=unborn\n'),
      pktLine('fetch=shallow\n'),
      pktLine('object-format=sha1\n'),
      PKT_FLUSH,
    ];
    return Buffer.concat(parts);
  }
  const caps =
    service === 'git-upload-pack'
      ? `multi_ack_detailed side-band-64k ofs-delta shallow deepen-since deepen-not object-format=sha1 symref=HEAD:${repo.headRef()} agent=${AGENT}`
      : `report-status delete-refs side-band-64k ofs-delta object-format=sha1 agent=${AGENT}`;
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const lines = sortedRefLines(repo);
  const headTip = repo.refs.get(repo.headRef());
  if (service === 'git-upload-pack') {
    if (lines.length === 0) {
      parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}`));
    } else {
      const first = `${headTip ?? ZERO_OID} HEAD\0${caps}`;
      parts.push(pktLine(first));
      for (const line of lines) parts.push(pktLine(`${line.oid} ${line.name}`));
    }
  } else {
    if (lines.length === 0) {
      parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}`));
    } else {
      let first = true;
      for (const line of lines) {
        parts.push(pktLine(first ? `${line.oid} ${line.name}\0${caps}` : `${line.oid} ${line.name}`));
        first = false;
      }
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/* ----------------------------------------------------------------- ls-refs */

export function lsRefs(repo: Repo, body: Buffer): Buffer {
  const { packets } = parsePktLines(body);
  const args: string[] = [];
  let pastDelim = false;
  for (const packet of packets) {
    if (packet.length === 1 && packet[0] === 1) {
      pastDelim = true;
      continue;
    }
    const line = packet.toString('utf8').replace(/\n$/, '');
    if (!pastDelim) continue; // command + agent lines
    args.push(line);
  }
  const wantPeel = args.includes('peel');
  const wantSymrefs = args.includes('symrefs');
  const wantUnborn = args.includes('unborn');
  const prefixes = args.filter((arg) => arg.startsWith('ref-prefix ')).map((arg) => arg.slice('ref-prefix '.length));
  const matches = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));

  const out: Buffer[] = [];
  const headTip = repo.refs.get(repo.headRef());
  if (matches('HEAD')) {
    if (headTip) {
      out.push(pktLine(`${headTip} HEAD${wantSymrefs ? ` symref-target:${repo.headRef()}` : ''}`));
    } else if (wantUnborn) {
      out.push(pktLine(`unborn HEAD${wantSymrefs ? ` symref-target:${repo.headRef()}` : ''}`));
    }
  }
  for (const line of sortedRefLines(repo)) {
    if (line.name.endsWith('^{}')) continue; // v2 carries peeling as an attribute
    if (!matches(line.name)) continue;
    let text = `${line.oid} ${line.name}`;
    if (wantPeel) {
      const obj = repo.store.get(line.oid);
      if (obj && obj.type === 'tag') {
        let target = parseTag(obj.data).object;
        let hops = 0;
        while (hops < 32) {
          const targetObj = repo.store.get(target);
          if (!targetObj || targetObj.type !== 'tag') break;
          target = parseTag(targetObj.data).object;
          hops += 1;
        }
        text += ` peeled:${target}`;
      }
    }
    out.push(pktLine(text));
  }
  out.push(PKT_FLUSH);
  return Buffer.concat(out);
}

/* ------------------------------------------------------------------- fetch */

interface FetchRequest {
  wants: string[];
  haves: string[];
  shallow: string[];
  deepen?: number;
  deepenRelative: boolean;
  deepenSince?: number;
  deepenNot: string[];
  done: boolean;
}

function commitTimestamp(repo: Repo, oid: string): number {
  const obj = repo.store.get(oid);
  if (!obj || obj.type !== 'commit') return 0;
  const match = / (\d+) [+-]\d{4}/.exec(parseCommit(obj.data).committer);
  return match ? Number(match[1]) : 0;
}

interface FetchSelection {
  objects: GitObject[];
  shallow: string[];
  unshallow: string[];
  commonHaves: string[];
  nothingToSend: boolean;
}

function selectFetchObjects(repo: Repo, request: FetchRequest): FetchSelection {
  const store = repo.store;
  const clientShallow = new Set(request.shallow);
  const clientHas = collectReachable(store, request.haves, clientShallow);
  const commonHaves = request.haves.filter((have) => store.has(have));

  // Commits reachable from deepen-not tips are excluded from the walk.
  const notCommits = new Set<string>();  if (request.deepenNot.length > 0) {
    const stack = [...request.deepenNot];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (notCommits.has(oid)) continue;
      const obj = store.get(oid);
      if (!obj) continue;
      if (obj.type === 'commit') {
        notCommits.add(oid);
        stack.push(...parseCommit(obj.data).parents);
      } else if (obj.type === 'tag') {
        stack.push(parseTag(obj.data).object);
      }
    }
  }

  // deepen-relative deepens from the client's current shallow depth: the
  // boundary commits sit at some distance from the wants, and the new limit
  // is that depth plus the requested increment.
  let depthLimit = request.deepen; // commits at distance < limit are included
  if (request.deepen !== undefined && request.deepenRelative && request.shallow.length > 0) {
    const distance = new Map<string, number>();
    const bfs: Array<[string, number]> = request.wants.map((want) => [want, 0]);
    while (bfs.length > 0) {
      const [oid, dist] = bfs.shift() as [string, number];
      const obj = store.get(oid);
      if (!obj) continue;
      if (obj.type === 'tag') {
        bfs.push([parseTag(obj.data).object, dist]);
        continue;
      }
      if (obj.type !== 'commit') continue;
      const previous = distance.get(oid);
      if (previous !== undefined && previous <= dist) continue;
      distance.set(oid, dist);
      for (const parent of parseCommit(obj.data).parents) bfs.push([parent, dist + 1]);
    }
    let maxShallowDist = 0;
    for (const oid of request.shallow) {
      const dist = distance.get(oid);
      if (dist !== undefined && dist > maxShallowDist) maxShallowDist = dist;
    }
    depthLimit = request.deepen + maxShallowDist + 1;
  }
  const included = new Set<string>();
  const boundary = new Set<string>();
  const commitDist = new Map<string, number>();
  const queue: Array<[string, number]> = request.wants.map((want) => [want, 0]);
  const addTreeObjects = (treeOid: string): void => {
    for (const oid of collectReachable(store, [treeOid])) included.add(oid);
  };

  while (queue.length > 0) {
    const [oid, dist] = queue.shift() as [string, number];
    const obj = store.get(oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      if (!included.has(oid)) {
        included.add(oid);
        queue.push([parseTag(obj.data).object, dist]);
      }
      continue;
    }
    if (obj.type === 'tree' || obj.type === 'blob') {
      for (const sub of collectReachable(store, [oid])) included.add(sub);
      continue;
    }
    // commit
    if (notCommits.has(oid)) continue;
    const previous = commitDist.get(oid);
    if (previous !== undefined && previous <= dist) continue;
    if (depthLimit !== undefined && dist >= depthLimit) continue;
    commitDist.set(oid, dist);
    included.add(oid);
    const commit = parseCommit(obj.data);
    addTreeObjects(commit.tree);
    const sinceCut = request.deepenSince !== undefined && commitTimestamp(repo, oid) < request.deepenSince;
    for (const parent of commit.parents) {
      if (sinceCut) {
        boundary.add(oid);
      } else if (depthLimit === undefined) {
        queue.push([parent, dist + 1]);
      } else if (dist + 1 < depthLimit) {
        queue.push([parent, dist + 1]);
      } else if (store.has(parent)) {
        boundary.add(oid);
      }
    }
  }

  const send: GitObject[] = [];
  for (const oid of included) {
    if (clientHas.has(oid)) continue;
    const obj = store.get(oid);
    if (obj) send.push(obj);
  }
  const shallow = [...boundary].filter((oid) => store.has(oid));
  const unshallow: string[] = [];
  for (const oid of clientShallow) {
    if (included.has(oid) && !boundary.has(oid)) unshallow.push(oid);
  }
  return { objects: send, shallow, unshallow, commonHaves, nothingToSend: send.length === 0 };
}

function sidebandPackets(pack: Buffer): Buffer[] {
  const packets: Buffer[] = [];
  // A pkt-line is at most 65520 bytes including its 4-byte header, and one
  // byte of the payload is the sideband channel, leaving 65515 for pack data.
  const CHUNK = 65515;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    packets.push(pktLine(Buffer.concat([Buffer.from([1]), pack.subarray(offset, offset + CHUNK)])));
  }
  return packets;
}

export function fetchV2(repo: Repo, body: Buffer): Buffer {
  const { packets } = parsePktLines(body);
  const request: FetchRequest = { wants: [], haves: [], shallow: [], deepenNot: [], deepenRelative: false, done: false };
  // Fetch arguments arrive in both sections: git puts shallow/deepen and the
  // capability-style args before the delimiter, want/have/done after it.
  for (const packet of packets) {
    if (packet.length === 1 && (packet[0] === 1 || packet[0] === 2)) continue;
    const line = packet.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('command=') || line.startsWith('agent=') || line.startsWith('object-format=')) continue;
    const splitAt = line.indexOf(' ');
    const key = splitAt === -1 ? line : line.slice(0, splitAt);
    const value = splitAt === -1 ? '' : line.slice(splitAt + 1);
    if (key === 'want') request.wants.push(value.slice(0, 40));
    else if (key === 'have') request.haves.push(value.slice(0, 40));
    else if (key === 'shallow') request.shallow.push(value.slice(0, 40));
    else if (key === 'deepen') request.deepen = Number(value);
    else if (key === 'deepen-relative') request.deepenRelative = true;
    else if (key === 'deepen-since') request.deepenSince = Number(value);
    else if (key === 'deepen-not') request.deepenNot.push(repo.refs.get(value) ?? value);
    else if (key === 'done') request.done = true;
  }
  const selection = selectFetchObjects(repo, request);
  const shallowLines = [
    ...selection.shallow.map((oid) => `shallow ${oid}`),
    ...selection.unshallow.map((oid) => `unshallow ${oid}`),
  ];
  const packSection = (): Buffer[] => {
    const parts: Buffer[] = [];
    if (shallowLines.length > 0) {
      parts.push(Buffer.concat([pktLine('shallow-info\n'), ...shallowLines.map((line) => pktLine(`${line}\n`))]), PKT_DELIM);
    }
    const pack = writePack(selection.objects);
    parts.push(pktLine('packfile\n'), ...sidebandPackets(pack), PKT_FLUSH);
    return parts;
  };
  if (request.done) {
    // Single-round fetch: shallow-info (when the boundary moved), then the
    // packfile section — an empty pack when there is nothing to send.
    return Buffer.concat(packSection());
  }
  const conclusive = selection.commonHaves.length > 0 || selection.nothingToSend || request.haves.length === 0;
  const ackLines = selection.commonHaves.length > 0 ? selection.commonHaves.map((oid) => `ACK ${oid}`) : ['NAK'];
  if (conclusive) ackLines.push('ready');
  const ackSection = Buffer.concat([pktLine('acknowledgments\n'), ...ackLines.map((line) => pktLine(`${line}\n`))]);
  if (!conclusive) return Buffer.concat([ackSection, PKT_FLUSH]);
  // Negotiation concluded without an explicit `done`: git expects the
  // packfile sections to follow the ready acknowledgment in this response.
  return Buffer.concat([ackSection, PKT_DELIM, ...packSection()]);
}

export function fetchV0(repo: Repo, body: Buffer): Buffer {
  // v0 request: want lines up to a flush, then have lines up to "done".
  const packets: Buffer[] = [];
  let offset = 0;
  const rawLines: string[] = [];
  let phase: 'want' | 'have' = 'want';
  const request: FetchRequest = { wants: [], haves: [], shallow: [], deepenNot: [], deepenRelative: false, done: false };
  while (offset + 4 <= body.length) {
    const size = parseInt(body.toString('ascii', offset, offset + 4), 16);
    if (Number.isNaN(size)) break;
    if (size === 0) {
      offset += 4;
      if (phase === 'want') phase = 'have';
      continue;
    }
    if (size < 4) break;
    const line = body.toString('utf8', offset + 4, offset + size).replace(/\n$/, '');
    rawLines.push(line);
    offset += size;
    if (phase === 'want') {
      if (line.startsWith('want ')) request.wants.push(line.slice(5, 45));
      else if (line.startsWith('shallow ')) request.shallow.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) request.deepen = Number(line.slice(7).trim());
      else if (line.startsWith('deepen-since ')) request.deepenSince = Number(line.slice(13).trim());
      else if (line.startsWith('deepen-not ')) {
        const ref = line.slice(11).trim();
        const oid = repo.refs.get(ref);
        request.deepenNot.push(oid ?? ref);
      }
    } else {
      if (line.startsWith('have ')) request.haves.push(line.slice(5, 45));
      else if (line === 'done') request.done = true;
    }
  }
  void packets;
  void rawLines;
  const selection = selectFetchObjects(repo, request);
  const parts: Buffer[] = [];
  if (selection.commonHaves.length === 0) {
    parts.push(pktLine('NAK\n'));
  } else {
    selection.commonHaves.forEach((oid, index) => {
      const suffix = index === selection.commonHaves.length - 1 ? '' : ' common';
      parts.push(pktLine(`ACK ${oid}${suffix}\n`));
    });
  }
  for (const oid of selection.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of selection.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  if (!selection.nothingToSend) {
    const pack = writePack(selection.objects);
    parts.push(...sidebandPackets(pack));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** upload-pack POST dispatcher: v2 commands, or a v0 negotiation body. */
export function uploadPack(repo: Repo, body: Buffer, protocolV2: boolean): Buffer {
  if (protocolV2) {
    const { packets } = parsePktLines(body);
    const first = packets.find((packet) => packet.toString('utf8').startsWith('command='));
    const command = first ? first.toString('utf8').trim() : '';
    if (command === 'command=ls-refs') return lsRefs(repo, body);
    if (command === 'command=fetch') return fetchV2(repo, body);
    throw new Error(`unsupported protocol v2 command: ${command || '(none)'}`);
  }
  return fetchV0(repo, body);
}

/* ------------------------------------------------------------- receive-pack */

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

export function receivePack(repo: Repo, body: Buffer): Buffer {
  const { packets, rest } = parsePktLines(body);
  const commands: PushCommand[] = [];
  let capabilities = '';
  packets.forEach((packet, index) => {
    let line = packet.toString('utf8').replace(/\n$/, '');
    if (index === 0) {
      const nul = line.indexOf('\0');
      if (nul !== -1) {
        capabilities = line.slice(nul + 1);
        line = line.slice(0, nul);
      }
    }
    const parts = line.split(' ');
    if (parts.length >= 3) commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
  });
  const caps = new Set(capabilities.split(' ').filter((cap) => cap !== ''));
  const reportStatus = caps.has('report-status');
  const sideBand = caps.has('side-band-64k');

  let unpackError: string | null = null;
  if (rest.length > 0) {
    try {
      const entries = readPack(rest, (oid) => repo.store.get(oid));
      for (const entry of entries) repo.store.putKnown(entry.oid, entry.type, entry.data);
    } catch (err) {
      unpackError = err instanceof Error ? err.message : String(err);
    }
  }

  const results: Array<{ ref: string; ok: boolean; reason?: string }> = [];
  for (const command of commands) {
    const fail = (reason: string): void => {
      results.push({ ref: command.ref, ok: false, reason });
    };
    const succeed = (): void => {
      results.push({ ref: command.ref, ok: true });
    };
    if (unpackError) {
      fail('unpack failed');
      continue;
    }
    const current = repo.refs.get(command.ref);
    if (command.newOid === ZERO_OID) {
      // delete
      if (!current) fail('reference not found');
      else if (command.ref === repo.headRef()) fail('deletion of the current branch prohibited');
      else if (current !== command.oldOid) fail('stale info');
      else {
        repo.refs.delete(command.ref);
        succeed();
      }
      continue;
    }
    if (!repo.store.has(command.newOid)) {
      fail('missing object');
      continue;
    }
    if (command.oldOid === ZERO_OID) {
      // create
      if (current) fail('reference already exists');
      else {
        repo.refs.set(command.ref, command.newOid);
        succeed();
      }
      continue;
    }
    // update
    if (!current) {
      fail('reference not found');
      continue;
    }
    if (current !== command.oldOid) {
      fail('stale info');
      continue;
    }
    if (current === command.newOid) {
      succeed();
      continue;
    }
    if (command.ref.startsWith('refs/tags/')) {
      repo.refs.set(command.ref, command.newOid);
      succeed();
      continue;
    }
    if (isAncestor(repo.store, current, command.newOid)) {
      repo.refs.set(command.ref, command.newOid);
      succeed();
    } else {
      fail('non-fast-forward');
    }
  }

  if (!reportStatus) return Buffer.alloc(0);
  const reportParts: Buffer[] = [pktLine(unpackError ? `unpack ${unpackError}\n` : 'unpack ok\n')];
  for (const result of results) {
    reportParts.push(pktLine(result.ok ? `ok ${result.ref}\n` : `ng ${result.ref} ${result.reason ?? 'failed'}\n`));
  }
  reportParts.push(PKT_FLUSH);
  const report = Buffer.concat(reportParts);
  if (!sideBand) return report;
  const wrapped: Buffer[] = [];
  const CHUNK = 65515;
  for (let offset = 0; offset < report.length; offset += CHUNK) {
    wrapped.push(pktLine(Buffer.concat([Buffer.from([1]), report.subarray(offset, offset + CHUNK)])));
  }
  wrapped.push(PKT_FLUSH);
  return Buffer.concat(wrapped);
}
