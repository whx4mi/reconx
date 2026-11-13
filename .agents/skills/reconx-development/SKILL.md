---
name: reconx-development
description: Continue development, debugging, and testing of this ReconX repository, including its host profiles, web pipelines, Gemini triage, and Kali installation workflow. Use when the user asks Codex to resume work on ReconX; not for performing a scan against an unrelated target.
---

# ReconX development

Work in the Git checkout containing `app.py`, not in `/opt/reconx/app`. The latter is the installed runtime and `update.sh` replaces it. At the start of a task, inspect `git status --short --branch`, the relevant code and tests, and the current user request. Preserve local changes and do not assume this skill contains the full history of earlier Codex chats.

## Project map

- `app.py`: Flask/Socket.IO UI, SQLite scan/finding persistence, tool catalog, pipelines, execution and operator checkpoints.
- `host_profiles.py`: persistent host identity, runs, assets, services, findings attribution, checklist and rule-based recommendations. The UI lives in `templates/index.html` and `templates/host.html`. Read `HOST_PROFILES.md` before changing this flow.
- `ai_pipeline.py` and `gemini_client.py`: Gemini-guided triage. Read `AI_PIPELINE.md` before changing model decisions, scope or approvals.
- `web_intelligence.py` and `login_testing.py`: adaptive web discovery, forms and login testing. Read `ADAPTIVE_WEB.md` when working there.
- `install.sh`: initial installation. `update.sh`: validated replacement of `/opt/reconx/app`, preserving `/opt/reconx/results` and making a backup. The installed app is not a development checkout.

## Invariants

- ReconX is intended for the operator's authorized lab and explicitly scoped assessments. Do not treat a discovered host, endpoint or model suggestion as permission to test it.
- AI suggestions are untrusted until the server validates their catalog, target and approval. Keep operator approval for active actions; do not turn a recommendation into automatic exploitation or brute force.
- Keep data isolated by host. A scan may pivot to another host, so do not attribute all its findings to its initial target. A completed tool run is not proof that a checklist item was tested.
- Preserve the SQLite results directory and old scans during migrations. Never commit results, credentials, wordlists containing secrets or `.env` files. Gemini credentials belong in environment variables on the runtime VM.
- Do not commit, push, deploy, reinstall or change the Kali service unless the user asks for that action. If a task needs live testing, confirm the target and authorized scope first.

## Verification and handoff

Run focused tests for changes, then `python3 -m unittest discover -s tests -q` from the checkout when dependencies are available. For shell changes use `bash -n install.sh update.sh`; for frontend changes check JavaScript syntax and, if possible, the browser behavior. Report exactly what was verified and what still requires a Kali integration test.

If the user asks broadly to “continue”, first summarize the repository's current state and propose the next bounded improvement based on the live code and their priorities. Ask which improvement to implement only when that choice would materially change the work; do not infer a new pentest target or authorization from this skill.
