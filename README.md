# Volc Agent Launchpad

A minimal Agent platform for three-day middleware hackathons. It provides Agent
CRUD, a browser Playground, persistent workspaces, and Codex CLI backed by the
Volcengine Ark Responses API.

Run it locally with Docker, Colima, or rootless Podman, or deploy it to
Volcengine ECS.

> [!WARNING]
> This is a single-user proof of concept. Agent Effect Gateway protects
> persistent workspace integrity through staging, deterministic policy,
> digest-bound approval, commit/rollback, and HMAC-chained evidence. It does not
> provide universal egress enforcement, tenant isolation, or production identity. The
> local Human/Agent principal model exists for attribution and revocation evidence. Do not
> use production data or credentials. See [SECURITY.md](SECURITY.md).

## Screenshots

### Agent Playground

![Agent Playground showing lifecycle controls, starter prompts, and the Codex Runtime](docs/assets/playground.jpg)

### Create an Agent

![Create Agent form with name, description, and workspace instructions](docs/assets/create-agent.jpg)

## Features

- React and TypeScript Web UI
- Agent create, edit, start, stop, delete, and multi-turn chat
- Fastify control plane with asynchronous Run state
- Persistent Agent workspaces and Codex sessions
- Disposable Docker, Colima, or Podman container for each local turn
- Agent Effect Gateway with disposable workspace and Codex-session staging
- Deterministic file-effect policy with all-or-nothing commit/rollback
- Exact digest-bound approval for deployment and operational files
- Protected external HTTP actions with host allowlist, SSRF/data checks,
  digest-bound approval, deterministic idempotency keys, and response receipts
- Per-Agent principals and time-limited Run capabilities derived by the control plane
- Versioned per-Agent policy profiles with relaxed, balanced, and strict templates
- Configurable security-module registry with locked kernel modules, health state,
  schema-generated controls, and most-restrictive policy hooks
- Dedicated six-page Security Center for posture, correlated Agent/Session/Run
  activity, approvals, policy simulation, module configuration, and architecture
- Queryable Runtime trace plus HMAC-chained security evidence
- Docker and Terraform deployment paths for Volcengine ECS

## Requirements

- Node.js 22+
- npm 10+
- Docker, Colima, or Podman
- A Volcengine Ark API key and endpoint that supports the Responses API

Codex CLI is included in the Runtime image and is not required on the host.

## Local browser SOP

### 1. Check the local tools

Install Node.js 22+ and one supported container engine, then verify them:

```bash
node --version
npm --version
docker --version        # Docker Desktop, Docker Engine, or Colima
podman --version        # Use this instead when running Podman
```

Only one container engine is required. Codex CLI is already included in the
Runtime image.

### 2. Clone the repository

```bash
git clone <repository-url> volc-agent-launchpad
cd volc-agent-launchpad
```

Skip this step when already working from the repository root.

### 3. Start the POC

```bash
ARK_API_KEY=your-ark-api-key \
ARK_MODEL=ep-your-endpoint-id \
npm run poc
```

The first run installs Node.js dependencies and builds the Runtime image. The
script automatically selects Docker, Colima, or Podman.

### 4. Open the browser

Visit <http://localhost:3000>, or open it from the terminal:

```bash
open http://localhost:3000       # macOS
xdg-open http://localhost:3000   # Linux desktop
```

In the Web UI:

1. Select **Create Agent**.
2. Enter a name, description, and workspace instructions.
3. Select **Create Agent** again.
4. Enter a task in the Playground, for example:

   ```text
   Create a TypeScript hello-world CLI, add a test, and run it.
   ```

The Agent can write files, run commands, and continue the same Codex session in
later messages.

### P1 external HTTP demo

Start the local ticket target in a second terminal:

```bash
npm run demo:mock
```

Enable only the loopback host for this demo when starting the POC:

```bash
AEG_HTTP_ALLOWLIST=127.0.0.1 \
AEG_HTTP_ALLOW_PRIVATE_NETWORKS=true \
ARK_API_KEY=your-ark-api-key \
ARK_MODEL=ep-your-endpoint-id \
npm run poc
```

Ask the Agent:

```text
Create a high-priority demo ticket titled "Review Agent deployment" through
the AEG external action gateway at http://127.0.0.1:3999/tickets. Do not modify
source files and do not call the endpoint directly.
```

The Run pauses before the `POST`. The approval card displays the canonical URL,
body preview, rule and request digest. After approval, AEG sends the request and
shows the HTTP status and response hash. Keep private-network access disabled
outside this loopback demonstration.

### Local SingGuard-NSFA analyzer

AEG can run the official SingGuard-NSFA 0.8B GGUF model locally as an Intake
analyzer. On Apple Silicon, install llama.cpp and download the Q4_K_M model:

```bash
brew install llama.cpp
mkdir -p ~/.volc-agent-launchpad/models/singguard-nsfa
curl -L --fail \
  --output ~/.volc-agent-launchpad/models/singguard-nsfa/Sing-Guard-0.8B-Q4_K_M.gguf \
  https://huggingface.co/inclusionAI/SingGuard-NSFA-0.8B-GGUF/resolve/main/Sing-Guard-0.8B-Q4_K_M.gguf
npm run guardrail:singguard
```

The local OpenAI-compatible endpoint listens on `127.0.0.1:18080`. In Security
Center → Modules → Guardrail Model, select `singguard`, leave endpoint and model
empty to use the environment defaults, and save. Enable Guardrail Model in the
Agent's Policy Profile. SingGuard receives XML-escaped text inside the official
`<untrusted_input>` boundary and returns NSFA risk tags; raw reasoning is not
stored in the security ledger.

### 5. Stop and resume

Press `Ctrl+C` in the startup terminal. The script removes temporary Runtime
containers but keeps Agent workspaces and conversations.

- macOS state: `~/.volc-agent-launchpad/`
- Linux state: `.local/`
- Custom location: set `LOCAL_POC_DATA_ROOT`

Run the same `npm run poc` command to continue later.

### Select a specific container engine

Force Podman when multiple engines are installed:

```bash
CONTAINER_ENGINE=podman \
ARK_API_KEY=your-ark-api-key \
ARK_MODEL=ep-your-endpoint-id \
npm run poc
```

Colima uses `CONTAINER_ENGINE=docker` because it exposes the Docker CLI.

For a clean Linux host, follow the
[rootless Podman setup](docs/LOCAL_POC.md#rootless-podman-on-linux).

## Docker Compose

Create and edit the configuration:

```bash
./scripts/bootstrap-local.sh
```

Required values in `.env`:

```dotenv
ARK_API_KEY=your-ark-api-key
ARK_MODEL=ep-your-endpoint-id
APP_AUTH_TOKEN=replace-with-at-least-24-random-characters
```

Start the application:

```bash
docker compose up --build
```

Open <http://localhost:3000>. Stop it without deleting Agent data:

```bash
docker compose down
```

## Development

```bash
npm install
cp .env.example .env
npm install --global @openai/codex@0.111.0
npm run dev
```

- Web UI: <http://localhost:5173>
- API: <http://localhost:3000>

Use local paths in `.env` when running outside Docker:

```dotenv
APP_DATA_DIR=.data
AGENT_WORKSPACE_ROOT=workspaces
CODEX_HOME=codex-home
```

## Deployment

- [Existing Linux ECS with Docker](docs/DEPLOYMENT.md#existing-linux-ecs)
- [Complete Volcengine environment with Terraform](docs/DEPLOYMENT.md#terraform-deployment)
- [Local Docker, Colima, and Podman details](docs/LOCAL_POC.md)

The existing-ECS script deploys from the current source tree:

```bash
cp .env.example .env.production
./scripts/deploy-existing-ecs.sh .env.production
```

The Terraform path provisions VPC, subnet, security group, ECS, and EIP:

```bash
cp deploy/volcengine/terraform.tfvars.example \
  deploy/volcengine/terraform.tfvars
./scripts/deploy-volcengine.sh
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `ARK_API_KEY` | Required | Ark model API key. |
| `ARK_MODEL` | Required | Responses-capable endpoint or model ID. |
| `ARK_BASE_URL` | Beijing v3 endpoint | Ark OpenAI-compatible API URL. |
| `SINGGUARD_BASE_URL` | `http://127.0.0.1:18080/v1` | Optional local SingGuard-NSFA endpoint. |
| `SINGGUARD_MODEL` | `singguard-nsfa-0.8b` | Model alias exposed by llama.cpp. |
| `APP_AUTH_TOKEN` | Empty on loopback | Shared demo token; use 24+ random characters remotely. |
| `AUDIT_HMAC_KEY` | Generated locally | Optional 32+ character audit-chain key. |
| `AEG_HTTP_ALLOWLIST` | Empty | Comma-separated exact hosts or `*.example.com` for P1. |
| `AEG_HTTP_ALLOW_PRIVATE_NETWORKS` | `false` | Permit loopback/private HTTP only for controlled demos. |
| `AEG_HTTP_TIMEOUT_MS` | `5000` | External request timeout. |
| `AEG_HTTP_MAX_RESPONSE_BYTES` | `65536` | Maximum response evidence captured. |
| `RUNTIME_PROVIDER` | `local-process` | `container` for disposable local Runtime containers. |
| `CODEX_SANDBOX_MODE` | `workspace-write` | Codex inner sandbox mode. |
| `CODEX_TIMEOUT_MS` | `600000` | Maximum duration of one turn. |
| `LOCAL_POC_DATA_ROOT` | Platform-specific | Local metadata, workspace, and session directory. |

See [.env.example](.env.example) for all Runtime and resource-limit options.

Policy and module configuration can also be managed through the Security Center.
Every change is recorded in the signed ledger. A policy version change expires
pending approvals bound to the previous version.

```http
GET   /api/agents/:agentId/policy
PUT   /api/agents/:agentId/policy
POST  /api/agents/:agentId/policy/template
POST  /api/agents/:agentId/policy/simulate
GET   /api/security/modules
PATCH /api/security/modules/:moduleId
```

## How it works

```mermaid
flowchart LR
    UI["React Web UI"] --> API["Fastify control plane"]
    API --> Store["JSON metadata and real Agent workspaces"]
    API --> AEG["Agent Effect Gateway"]
    AEG --> Stage["Disposable workspace + Codex Home"]
    AEG --> Http["Protected HTTP executor"]
    Stage --> Runtime{"Runtime provider"}
    Runtime -->|Local POC| Container["Disposable Docker / Colima / Podman container"]
    Runtime -->|ECS profile| Codex["Codex CLI in application container"]
    Container --> Ark["Volcengine Ark Responses API"]
    Codex --> Ark
    Http --> Target["Allowlisted service"]
```

The first turn uses `codex exec`; later turns resume the last committed Codex
thread. The Runtime sees only a staged copy. AEG measures the resulting diff,
applies deterministic policy, and commits or discards the complete manifest.
External actions use a reserved JSON outbox; state-changing HTTP methods wait
for approval and are sent by the control plane rather than the Runtime.
Deleting an Agent archives its workspace under `workspaces/.deleted/`.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component and extension
boundaries.

## Validation

```bash
npm run check
terraform fmt -check -recursive deploy/volcengine
docker compose config
```

## Documentation

- [Hackathon submission guide](docs/SUBMISSION.md)
- [Reproducible demo casebook](docs/CASEBOOK.md)
- [Three-minute recording script](docs/DEMO.md)
- [Validation evidence](docs/VALIDATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Interactive one-page architecture](apps/web/public/diagrams/aeg-architecture.html)
- [Local POC](docs/LOCAL_POC.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Hackathon extension guide](docs/HACKATHON_EXTENSION_GUIDE.md)
- [Security policy](SECURITY.md)
- [Agent Effect Gateway design and demo](docs/AEG_SECURITY.md)
- [Security module integration](docs/SECURITY_MODULES.md)
- [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE)
