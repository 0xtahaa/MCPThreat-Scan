# MCPThreat-Scan

Static **zero-execution** security scanner for MCP server source code (Python). The scanned
code is never executed — it is only read as text/AST and analyzed with Semgrep rules plus a
hardened, optional AI review (layer 2).

MCP servers connect AI agents to real access (email, databases, APIs). According to an
independent study, existing scanners have a false-positive rate of about 78 %. The goal of
this project: demonstrably higher accuracy, measured against its own open benchmark.

## Covered OWASP MCP categories (deliberately not all 10)

| Category | What is checked |
|---|---|
| Header Leak | Request headers in error messages |
| Hardcoded Secret | Hardcoded API keys/tokens in source code |
| Unscoped Environment Access | Unscoped `os.environ` access per tool call |
| Tool Poisoning | Suspicious instruction patterns in tool docstrings (layer 1: Semgrep candidate; layer 2: optional AI review) + rug-pull detection via version comparison |
| Supply Chain | Compares `requirements.txt` against the OSV vulnerability database via `pip-audit` |
| Command Injection | `eval`/`exec`/`os.system`/`subprocess` with unchecked input |
| Missing Audit Logging | Missing logging calls on security-relevant actions |
| Capability Mismatch | Handler calls network/email without the name or docstring mentioning it (keyword heuristic, candidate only; does not detect deliberately deceptive descriptions) |
| Typosquatting / Shadow Server | Declared server name closely resembles a known server from `known_mcp_servers.json` (candidate, not a hard statement) |

Deliberately **not** in the MVP: precise scope measurement (needs runtime tracing),
prompt-injection content filter, server operations monitoring, shadow-server discovery.

## Current accuracy (benchmark, layer 1 — Semgrep + supply-chain OSV check)

Generated via `python -m benchmark.evaluate` (from the repo root) against `benchmark/`:

| Category | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| Capability Mismatch | 2 | 0 | 0 | 100 % | 100 % |
| Command Injection | 2 | 0 | 0 | 100 % | 100 % |
| Hardcoded Secret | 2 | 0 | 0 | 100 % | 100 % |
| Header Leak | 2 | 0 | 0 | 100 % | 100 % |
| Missing Audit Logging | 6 | 0 | 0 | 100 % | 100 % |
| Supply Chain | 2 | 0 | 0 | 100 % | 100 % |
| Tool Poisoning | 6 | 1 | 2 | 86 % | 75 % |
| Typosquatting / Shadow Server | 2 | 0 | 0 | 100 % | 100 % |
| Unscoped Environment Access | 5 | 0 | 0 | 100 % | 100 % |
| **Total** | **29** | **1** | **2** | **97 %** | **94 %** |

Tool Poisoning is deliberately weaker: the Semgrep rule only delivers *candidates* (see
[tool_poisoning.yaml](src/mcpthreat_scan/resources/rules/tool_poisoning.yaml)); the actual
confirmation only happens in layer 2 (`--ai-review`), which is not measured here. The two
false negatives are rug-pull cases from `benchmark/rugpull/` — see
[Known limitations](#known-limitations--open-issues).

## Installation

Requirements: Python 3.12+, Git.

```bash
git clone https://github.com/0xtahaa/MCPThreat-Scan.git
cd MCPThreat-Scan
python -m venv .venv
```

Windows: `.venv\Scripts\activate` · macOS/Linux: `source .venv/bin/activate`

```bash
pip install -r requirements.txt
```

The project uses the `src` layout; so that `python -m mcpthreat_scan…` and `pytest` can find the
package, install it once in editable mode (dependencies come from `requirements.txt`):

```bash
pip install -e .
```

For the optional layer-2 AI review (`--ai-review`), store an `OPENAI_API_KEY` in a local
`.env` file (see `.gitignore` — it is never committed).

## Usage

**Scan a single file or a folder:**

```bash
python -m mcpthreat_scan.cli.main scan path/to/mcp_server.py
```

```bash
python -m mcpthreat_scan.cli.main scan path/to/project/ --format json
```

With the layer-2 AI review for tool-poisoning candidates (requires `OPENAI_API_KEY`; if the key
is missing, the scan does not abort and the candidate stays unconfirmed):

```bash
python -m mcpthreat_scan.cli.main scan path/to/mcp_server.py --ai-review
```

**Compare two versions of the same file for rug pulls** (tool name/parameters/docstring/
hidden behavior):

```bash
python -m mcpthreat_scan.cli.main diff server_v1.py server_v2.py
```

**Example against the benchmark fixtures:**

```bash
python -m mcpthreat_scan.cli.main scan benchmark/vulnerable/command_injection.py
```

```
benchmark\vulnerable\command_injection.py:
  Line 9 [Command Injection] ERROR: Command Injection: A function parameter flows unchecked into a
  shell command or eval/exec. ...

Summary: 8 of 9 OWASP MCP categories without findings.
Categories with findings: Command Injection
```

**Output format and CI threshold:** `--format text|json|sarif`; `--fail-on ERROR|WARNING|INFO` returns
exit code 1 as soon as a finding is at least that severe (without the flag the exit code stays 0).

**Interactive interface (Textual):**

```bash
python -m mcpthreat_scan.cli.main tui
```

The TUI (Autorea look: dark, restrained green) offers: **Start New Scan** (select and validate a
target, confirm, watch the phases, read the summary), **Compare Versions** (two files or two folders:
changed files, tool-definition changes, new and resolved findings), **View Findings** (severity
filter, detail panel with rule, evidence and recommendation), **Trusted Servers & Exclusions**
(trusted servers and ignore rules with scope and source; remove/revoke asks first) and
**Settings & Help**. Reports can be exported as JSON or SARIF with `E` (same renderers as
`--format json|sarif`). Shortcuts are shown on each screen; on the main menu: `S` scan, `D` compare,
`?` help, `Q` quit. Screenshots: `docs/tui/`. A running scan cannot be cancelled safely (Semgrep runs
as one external process).

Each finding in JSON and SARIF output now also carries `rule_id` and `evidence` (the flagged source
line or description; never set for hardcoded secrets).

## Project structure

```
src/mcpthreat_scan/
  cli/         Command-line interface (argparse: scan, diff, tui) — parsing only, delegates to core
  tui/         Interactive terminal interface (Textual)
  core/        Orchestration (run_scan, run_diff), categories/severities, shared exceptions
  analyzers/   Semgrep (layer 1), AI review (layer 2, OpenAI), supply chain (pip-audit/OSV),
               typosquat, capability post-filter — one task per analyzer, no analyzer chains
  diff/        AST extraction of tool functions (never executed) and rug-pull comparison
  policy/      .mcpscannerignore and reputation/whitelist
  reporting/   Renderers for text, JSON and SARIF
  resources/   Semgrep rules (rules/, one file per OWASP MCP category), known_mcp_servers.json
benchmark/   Test cases with known results (vulnerable/, clean/, rugpull/) + expected_results.json
             + evaluate.py (precision/recall; uses the core API, not part of the installable package)
tests/       Unit tests (pytest)
```

## Known limitations / open issues

- **`policy/reputation.py` is not used by the scan.** The whitelist/fingerprint mechanism (meant to
  skip costly re-review for established, unchanged servers) is not wired into the scan pipeline;
  only the TUI management (`list_reviewed`, `revoke_review`) and the tests call it.
- **`benchmark/rugpull/` does not feed into `benchmark/evaluate.py`.** The precision/recall
  measurement uses only the `scan` path; rug-pull detection runs through the separate `diff` path
  and is therefore not measured automatically.
- **Tool Poisoning has the weakest hit rate** (86 % precision / 75 % recall in layer 1) — this is
  expected without `--ai-review`, since the Semgrep rule deliberately only delivers candidates.
- Two tests (`test_ai_review.py`, real OpenAI call) are skipped without `OPENAI_API_KEY`. Tests
  with an OSV query via `pip-audit` (`test_dependency_check.py`) need network access and may fail
  without it — an external dependency, not a code error.

## Running the tests

```bash
pytest
```

```bash
python -m benchmark.evaluate
```

## License

No license has been chosen yet.
