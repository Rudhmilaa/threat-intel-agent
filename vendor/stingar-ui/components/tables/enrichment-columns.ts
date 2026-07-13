/** Read C2 / payload / playbook display values from session hp_data.enrichment. */

export type SessionEnrichment = {
  c2?: { value?: string; stage?: string };
  c2s?: Array<{ ip?: string; domain?: string; url?: string; stage?: string }>;
  payloads?:
    | { sha256?: string; family?: string; kind?: string; status?: string; attempted_url?: string }
    | Array<{ sha256?: string; family?: string; kind?: string; status?: string; attempted_url?: string }>;
  playbook?: { name?: string; exact_key?: string; canonical?: string };
  playbook_hash?: string;
  scanner_lite?: Record<string, unknown>;
};

export type C2Entry = { value: string; stage?: string };
export type PayloadEntry = {
  sha256: string;
  family?: string;
  kind?: string;
  status?: string;
  attempted_url?: string;
};
export type PlaybookInfo = { name?: string; exact_key?: string; canonical?: string };

function hpData(row: Record<string, unknown>): Record<string, unknown> {
  return (row.hpData ?? row.hp_data ?? {}) as Record<string, unknown>;
}

function enrichment(row: Record<string, unknown>): SessionEnrichment {
  const hp = hpData(row);
  return ((hp.enrichment ?? {}) as SessionEnrichment) || {};
}

function normalizePayloadEntry(entry: Record<string, unknown>): PayloadEntry {
  const payload: PayloadEntry = { sha256: String(entry.sha256) };
  for (const key of ["family", "kind", "status", "attempted_url"] as const) {
    if (entry[key]) payload[key] = String(entry[key]);
  }
  return payload;
}

function formatPayloadValue(entry: PayloadEntry): string {
  const parts: string[] = [truncateHash(entry.sha256)];
  if (entry.family) parts.push(entry.family);
  if (entry.kind) parts.push(entry.kind);
  if (entry.status) parts.push(entry.status);
  return parts.join(" · ");
}

function truncateHash(hash: string, max = 16): string {
  if (hash.length <= max) return hash;
  return `${hash.slice(0, max)}…`;
}

/** Normalize c2-engine MVP stamps and legacy hp_data fields into a single view. */
export function sessionEnrichmentView(row: Record<string, unknown>): {
  c2: C2Entry[];
  payloads: PayloadEntry[];
  playbook?: PlaybookInfo;
} {
  const enc = enrichment(row);
  const hp = hpData(row);

  const c2: C2Entry[] = [];
  if (enc.c2?.value) {
    c2.push({ value: String(enc.c2.value), stage: enc.c2.stage });
  }
  if (Array.isArray(enc.c2s)) {
    for (const entry of enc.c2s) {
      const value = entry.url || entry.domain || entry.ip;
      if (value) c2.push({ value: String(value), stage: entry.stage });
    }
  }
  if (c2.length === 0) {
    const iocs = hp.iocs_c2_hosts as string[] | undefined;
    if (Array.isArray(iocs)) {
      for (const host of iocs) {
        if (host) c2.push({ value: String(host) });
      }
    }
  }
  if (c2.length === 0) {
    const c2Host = (row.c2_host ?? row.c2Host) as string | string[] | undefined;
    const hosts = Array.isArray(c2Host) ? c2Host : c2Host ? [c2Host] : [];
    for (const host of hosts) {
      if (host) c2.push({ value: String(host) });
    }
  }

  const payloads: PayloadEntry[] = [];
  const rawPayloads = enc.payloads;
  if (Array.isArray(rawPayloads)) {
    for (const entry of rawPayloads) {
      if (entry?.sha256) payloads.push(normalizePayloadEntry(entry));
    }
  } else if (rawPayloads?.sha256) {
    payloads.push(normalizePayloadEntry(rawPayloads));
  }
  if (payloads.length === 0) {
    const refs = hp.payload_refs as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(refs)) {
      for (const ref of refs) {
        if (ref?.sha256) payloads.push(normalizePayloadEntry(ref));
      }
    }
  }

  let playbook: PlaybookInfo | undefined;
  if (enc.playbook?.name || enc.playbook?.exact_key || enc.playbook?.canonical) {
    playbook = {
      name: enc.playbook.name,
      exact_key: enc.playbook.exact_key,
      canonical: enc.playbook.canonical,
    };
  } else if (enc.playbook_hash) {
    playbook = { exact_key: String(enc.playbook_hash) };
  } else if (hp.playbook_hash || hp.playbook_canonical) {
    playbook = {
      exact_key: hp.playbook_hash ? String(hp.playbook_hash) : undefined,
      canonical: hp.playbook_canonical ? String(hp.playbook_canonical) : undefined,
    };
  }

  return { c2, payloads, playbook };
}

export function hasAttackIntel(row: Record<string, unknown>): boolean {
  const view = sessionEnrichmentView(row);
  return (
    view.c2.length > 0 ||
    view.payloads.length > 0 ||
    Boolean(view.playbook?.name || view.playbook?.exact_key || view.playbook?.canonical)
  );
}

export function c2Display(row: Record<string, unknown>): string {
  const { c2 } = sessionEnrichmentView(row);
  if (c2.length === 0) return "—";
  const first = c2[0];
  return first.stage ? `${first.value} (${first.stage})` : first.value;
}

export function payloadDisplay(row: Record<string, unknown>): string {
  const { payloads } = sessionEnrichmentView(row);
  if (payloads.length === 0) return "—";
  const hash = payloads[0].sha256;
  return hash.length > 12 ? `${hash.slice(0, 7)}…` : hash;
}

export function payloadTooltip(row: Record<string, unknown>): string {
  const { payloads } = sessionEnrichmentView(row);
  if (payloads.length === 0) return "";
  return payloads
    .map((p) => {
      const parts = [p.sha256];
      if (p.family) parts.push(`family: ${p.family}`);
      if (p.kind) parts.push(`kind: ${p.kind}`);
      if (p.status) parts.push(`status: ${p.status}`);
      if (p.attempted_url) parts.push(`url: ${p.attempted_url}`);
      return parts.join("\n");
    })
    .join("\n\n");
}

export function payloadDetailValue(entry: PayloadEntry): string {
  return formatPayloadValue(entry);
}

export function playbookDisplay(row: Record<string, unknown>): string {
  const { playbook } = sessionEnrichmentView(row);
  if (playbook?.name) return playbook.name;
  if (playbook?.canonical) {
    const line = playbook.canonical.split("\n")[0];
    return line.length > 24 ? `${line.slice(0, 21)}…` : line;
  }
  if (playbook?.exact_key) {
    const key = playbook.exact_key;
    return key.length > 12 ? `${key.slice(0, 7)}…` : key;
  }
  return "—";
}

export function playbookTooltip(row: Record<string, unknown>): string {
  const { playbook } = sessionEnrichmentView(row);
  if (!playbook) return "";
  const parts: string[] = [];
  if (playbook.name) parts.push(`Name: ${playbook.name}`);
  if (playbook.canonical) parts.push(`Steps:\n${playbook.canonical}`);
  if (playbook.exact_key) parts.push(`Key: ${playbook.exact_key}`);
  return parts.join("\n");
}
