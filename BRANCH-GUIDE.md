# Which folder is which?

This repo uses **two local folders** (git worktrees) so you can open each version in its own Cursor window.

| Folder | Git branch | What it is |
|---|---|---|
| `Desktop/threat-intel-agent` | `threat-enrich-agent` | **Full system** — hybrid STINGAR, central sync, `main.py` agent |
| `Desktop/threat-intel-agent-lite` | `scanner-enrichment-lite` | **Lite system** — `scanner_lite/`, API cascade, ASN batches |

## GitLab branches

- Full: https://gitlab.oit.duke.edu/codeplus2026/ai_tools/-/tree/threat-enrich-agent
- Lite: https://gitlab.oit.duke.edu/codeplus2026/ai_tools/-/tree/scanner-enrichment-lite

## Open in Cursor

- Full → **File → Open Folder** → `threat-intel-agent`
- Lite → **File → Open Folder** → `threat-intel-agent-lite` → start at `scanner_lite/server.py`

## Recreate worktree (if deleted)

```bash
cd ~/Desktop/threat-intel-agent
git checkout threat-enrich-agent
git worktree add ../threat-intel-agent-lite scanner-enrichment-lite
```
