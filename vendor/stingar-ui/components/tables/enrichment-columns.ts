/** Read C2 / payload / playbook display values from session hp_data.enrichment. */

export type SessionEnrichment = {
  c2?: { value?: string; stage?: string };
  payloads?: { sha256?: string; family?: string };
  playbook?: { name?: string; exact_key?: string };
  scanner_lite?: Record<string, unknown>;
};

function enrichment(row: Record<string, unknown>): SessionEnrichment {
  const hp = (row.hpData ?? row.hp_data ?? {}) as Record<string, unknown>;
  return ((hp.enrichment ?? {}) as SessionEnrichment) || {};
}

export function c2Display(row: Record<string, unknown>): string {
  const c2 = enrichment(row).c2;
  if (!c2?.value) return "—";
  return c2.stage ? `${c2.value} (${c2.stage})` : String(c2.value);
}

export function payloadDisplay(row: Record<string, unknown>): string {
  const payloads = enrichment(row).payloads;
  if (!payloads?.sha256) return "—";
  const hash = payloads.sha256;
  return hash.length > 12 ? `${hash.slice(0, 7)}…` : hash;
}

export function payloadTooltip(row: Record<string, unknown>): string {
  const payloads = enrichment(row).payloads;
  if (!payloads?.sha256) return "";
  const parts = [payloads.sha256];
  if (payloads.family) parts.push(`family: ${payloads.family}`);
  return parts.join("\n");
}

export function playbookDisplay(row: Record<string, unknown>): string {
  const playbook = enrichment(row).playbook;
  if (playbook?.name) return playbook.name;
  if (playbook?.exact_key) {
    const key = playbook.exact_key;
    return key.length > 12 ? `${key.slice(0, 7)}…` : key;
  }
  return "—";
}

export function playbookTooltip(row: Record<string, unknown>): string {
  const playbook = enrichment(row).playbook;
  if (!playbook) return "";
  const parts: string[] = [];
  if (playbook.name) parts.push(`Name: ${playbook.name}`);
  if (playbook.exact_key) parts.push(`Key: ${playbook.exact_key}`);
  return parts.join("\n");
}
