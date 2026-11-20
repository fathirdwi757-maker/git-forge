// web.ts — the reply shape every surface module returns to app.ts, plus the
// JSON body parsing they share. Keeping it in one place means the protocol
// rules (JSON everywhere, a message on errors) hold on every route.

export interface Reply {
  status: number;
  json?: unknown;
  raw?: Buffer;
  contentType?: string;
  headers?: Record<string, string>;
}

export function jsonReply(status: number, value: unknown, headers?: Record<string, string>): Reply {
  return { status, json: value, headers };
}

export function errorReply(status: number, message: string): Reply {
  return { status, json: { message } };
}

export function parseJsonBody(raw: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (raw.length === 0) return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(raw.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

export function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

export function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

export function pagination(query: URLSearchParams): { page: number; perPage: number } {
  const perPageRaw = Number(query.get('per_page') ?? '30');
  const pageRaw = Number(query.get('page') ?? '1');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.floor(perPageRaw)) : 30;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.floor(pageRaw) : 1;
  return { page, perPage };
}

export function pageSlice<T>(items: T[], page: number, perPage: number): T[] {
  return items.slice((page - 1) * perPage, page * perPage);
}

/** A GitHub-style Link header for a paginated list, or undefined on a single page. */
export function linkHeader(baseUrl: string, page: number, perPage: number, total: number): string | undefined {
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  if (lastPage <= 1) return undefined;
  const parts: string[] = [];
  const url = (p: number): string => `${baseUrl}?per_page=${perPage}&page=${p}`;
  if (page < lastPage) {
    parts.push(`<${url(page + 1)}>; rel="next"`, `<${url(lastPage)}>; rel="last"`);
  }
  if (page > 1) {
    parts.push(`<${url(page - 1)}>; rel="prev"`, `<${url(1)}>; rel="first"`);
  }
  return parts.join(', ');
}
