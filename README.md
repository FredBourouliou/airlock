# Airlock

**An inspection gateway that quarantines prompt injection and data exfiltration
before it reaches a tool-using AI agent.**

An AI agent that reads email, browses the web and calls tools will, sooner or
later, read something written to hijack it — an email, a web page, a document
crafted to make it exfiltrate data or take an action it was never asked to.
Airlock sits between the agent and its tools as an **MCP gateway**: every tool
call the agent makes and every piece of content that comes back passes through a
sealed inspection step. Anything that looks like an injection or an unauthorized
data egress is **quarantined** — the agent gets a neutral placeholder and carries
on, uncontaminated.

## How it works

```
                 ┌──────────────────── AIRLOCK ────────────────────┐
   AI agent ───► │  OUTBOUND: inspect the tool call it wants to make │ ───► tools
 (MCP client)    │  INBOUND:  inspect the content coming back        │ ◄─── (MCP servers)
                 │                                                   │
                 │   1. deterministic rules   (authoritative)        │
                 │   2. local-LLM classifier  (optional, Ollama)     │
                 │   →  ALLOW · FLAG · BLOCK + reason, hash-chained   │
                 └───────────────────────────────────────────────────┘
```

- **Deterministic rules** — the core, standard-library only, and *authoritative*:
  instruction override, exfiltration instructions, external-recipient sends,
  high-volume PII egress, system/tool-role spoofing. A `BLOCK` here is final.
- **Local-LLM classifier (optional)** — a second opinion from a model running on
  your own machine via [Ollama](https://ollama.com), to catch subtly phrased
  injections that evade the signatures. **No API, no cost.** It can only *add*
  findings, never override a deterministic block.
- **Quarantine** — blocked inbound content never reaches the agent; it receives a
  neutral placeholder and continues safely.
- **Audit trail** — every decision is recorded with its rule and reason, chained
  so the log is tamper-evident, and streamed live to the console.

## Status

Early work in progress.

- [x] Deterministic inspection engine + tests (`src/airlock/rules.py`)
- [x] Interception gateway + mock tool servers (`src/airlock/gateway.py`, `tools.py`)
- [x] Local-LLM classifier layer via Ollama (`src/airlock/classifier.py`)
- [x] Hash-chained audit log (`src/airlock/audit.py`)
- [ ] Live SOC-style web console
- [ ] Demo scenarios (email · web · shopping)

The gateway is an MCP-*shaped* interception layer (tools have an MCP-like
name/description/call surface); exposing it over the real MCP wire protocol is a
thin adapter, kept as the `mcp` optional extra. The core has **no runtime
dependencies** — engine, gateway, audit and the Ollama client are all standard
library.

## Known limitations

Airlock fails closed, so these bias toward over-blocking, never toward letting an
attack through:

- Homoglyph defence folds a curated set of common Cyrillic/Greek look-alikes, not
  a full [UTS&nbsp;#39](https://www.unicode.org/reports/tr39/) confusables skeleton.
- Internationalised (non-ASCII) email addresses are treated as untrusted, because
  the allowlist check requires a strict ASCII address; IDNA validation is not done.
- The deterministic rules are signatures, not a proof. The local-LLM layer exists
  precisely to catch phrasings the signatures miss.

## Develop

```bash
uv sync --extra dev
uv run pytest
```

## License

MIT — see [LICENSE](LICENSE).
