# WebGuard AI Copilot

## Capabilities

The AI Copilot provides advisory workflows through authenticated API endpoints:

- `process_review`: summarizes registered targets, audit states, finding severity counts and known module readiness.
- `audit_summary`: summarizes the newest audit in the user's scope, or the audit identified by `audit_id`.
- `finding_triage`: prioritizes up to 50 open findings in the user's authorized workspace.
- `remediation_plan`: produces a defensive remediation sequence for those findings.
- `general`: answers general WebGuard process questions.

The Copilot does not execute scans, navigate to targets, start jobs, modify scopes, mutate findings or change user roles. Its responses are advisory and require human review. The LLM has no tool/function execution capability. A remote provider outage falls back to deterministic local rules for the selected task.

## Modes

- **Local rules (default):** no external AI provider or API key is required. Process review, audit summary, finding triage and remediation guidance use local deterministic rules. General open-ended answers are limited until an external model is configured.
- **Groq mode:** WebGuard uses Groq’s OpenAI-compatible Chat Completions API when a backend API key and model are configured. The default model is `openai/gpt-oss-120b`. The model ID is operator-configurable and must remain available in Groq.

## Backend configuration

Set these values in the backend's environment (or the server-side `.env` file for local development):

```dotenv
WEBGUARD_AI_PROVIDER_NAME=Groq
WEBGUARD_AI_BASE_URL=https://api.groq.com/openai/v1
WEBGUARD_AI_API_KEY=replace-with-your-groq-api-key
WEBGUARD_AI_MODEL=openai/gpt-oss-120b
WEBGUARD_AI_TIMEOUT_SECONDS=20
WEBGUARD_AI_MAX_OUTPUT_TOKENS=1200
WEBGUARD_AI_RATE_LIMIT_REQUESTS=10
```

Create an API key in the [Groq Console](https://console.groq.com/keys) and paste it only into the backend environment. Official references: [Chat Completions API](https://console.groq.com/docs/api-reference) and [supported models](https://console.groq.com/docs/models). The base URL `https://api.groq.com/openai/v1` is Groq’s OpenAI-compatible endpoint. The default model is `openai/gpt-oss-120b`; check Groq’s supported-models page before changing it or deploying. Use a model compatible with Chat Completions. `WEBGUARD_AI_BASE_URL` is an operator-controlled server setting, never accepted from a browser request. In production, an enabled provider must use HTTPS and cannot be configured with a literal private/reserved IP or an obvious local hostname. Restrict backend egress at the infrastructure layer to the provider destinations you approve. Never put the key into `VITE_*` settings, client code, source control, API responses or logs.

If no key is set, `GET /api/ai/status` reports `local_rules`; the interface remains useful without connecting externally. Restart the API after changing environment settings.

## Data sent to a remote model

Only the minimum context needed for the selected task is included. The implementation omits evidence JSON and raw target URLs; finding descriptions are truncated, and common credential/token patterns are redacted before external submission. Even so, redaction is best-effort and cannot guarantee removal of every secret or personal detail. Review your provider's retention, training, residency and contractual terms before enabling remote mode. For sensitive deployments, keep local mode enabled or use a separately reviewed private provider endpoint.

Questions and findings are untrusted data. System instructions tell the model not to follow embedded instructions, invent evidence or claim actions. This is a defense-in-depth measure, not a guarantee against prompt injection or model mistakes.

## API

`GET /api/ai/status` (authenticated) returns capability and provider mode status without secrets.

`POST /api/ai/assist` (authenticated) request example:

```json
{
  "task": "process_review",
  "question": "Prioriza las mejoras de esta semana"
}
```

The supported `task` values are `process_review`, `audit_summary`, `finding_triage`, `remediation_plan`, and `general`. `audit_id` is optional for `audit_summary`. The request question is limited to 3,000 characters. The endpoint is rate-limited per user per process; enforce an additional shared gateway/WAF limit before multi-worker or public deployment.

All successful responses use the standard `{"data": ...}` envelope and include mode, provider/model identifier, timestamp and an advisory disclaimer. AI usage is recorded in the audit-event table without recording the full question or model answer.

## Operational limits

- Model output is bounded by timeout, a configured token limit and a 512 KiB response limit.
- The request does not enable browsing, tools, file access or target execution.
- No generated recommendation should automatically change an authorization record or trigger security testing.
- Validate model/provider costs and usage limits before public release.
- Local fallback uses rules, not a generative model; the UI and API identify that mode honestly.
- This module is not a substitute for secure worker design, review, monitoring, privacy/legal assessment or human approval.
