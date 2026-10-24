# Contributing to Mini SIEM Platform

Thank you for your interest in contributing to the **Mini SIEM Platform**! As an open-source, multi-tenant security information and event management system built for high throughput and real-time detection, our goal is to build robust, scalable, and reliable security operations tooling.

Whether you are fixing a bug, adding detection rules, improving ingestion throughput, optimizing database queries, enhancing the Next.js frontend, or refining documentation, your contributions are welcome.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Project Architecture](#project-architecture)
- [Prerequisites & Development Environment](#prerequisites--development-environment)
- [Local Setup & Running the Stack](#local-setup--running-the-stack)
- [Branching & Git Workflow](#branching--git-workflow)
- [Commit Message Conventions](#commit-message-conventions)
- [Component Development Guidelines](#component-development-guidelines)
  - [Backend (Rust)](#backend-rust)
  - [Log Forwarder Agent (Go)](#log-forwarder-agent-go)
  - [Frontend (Next.js & TypeScript)](#frontend-nextjs--typescript)
  - [Detection Rules & Signatures](#detection-rules--signatures)
  - [Infrastructure & Kubernetes](#infrastructure--kubernetes)
- [Testing & Quality Assurance](#testing--quality-assurance)
  - [Reliability & Chaos Drills](#reliability--chaos-drills)
  - [Synthetic Log & Alert Ingestion](#synthetic-log--alert-ingestion)
- [Security & Multi-Tenant Isolation Guidelines](#security--multi-tenant-isolation-guidelines)
- [Pull Request Checklist](#pull-request-checklist)
- [Reporting Issues & Security Vulnerabilities](#reporting-issues--security-vulnerabilities)
- [License Notice](#license-notice)

---

## Code of Conduct

We are committed to providing a friendly, welcoming, and harassment-free environment for all contributors regardless of background, gender, sexual orientation, disability, race, religion, or level of experience.

- **Be respectful and constructive**: Give and receive feedback with empathy and professional courtesy.
- **Focus on what is best for the project**: Prioritize architectural stability, security, tenant isolation, and code readability.
- **Maintain zero tolerance for discrimination**: Harassment, derogatory comments, and exclusionary behavior will not be tolerated.

---

## Project Architecture

Mini SIEM is a polyglot monorepo containing multiple decoupled services:

```text
mini-siem-project/
├── k8s/                     # Kubernetes manifests & production deployment configs
├── mini_siem_dds.pdf        # Detailed Design Specification
├── mini_siem_srs.pdf        # Software Requirements Specification
├── README.md                # Project overview and high-level docs
├── CHANGELOG.md             # Version history adhering to Keep a Changelog
├── CONTRIBUTING.md          # Contribution guidelines (this file)
├── LICENSE                  # MIT License
└── mini-siem/
    ├── agent/               # Log forwarder and syslog daemon (Go)
    ├── backend/             # SIEM core API, detection engine, & workers (Rust)
    ├── frontend/            # SOC analyst portal & UI (Next.js 16, React 19, Tailwind)
    ├── infrastructure/      # Terraform, Kubernetes HPA, and provisioning
    ├── observability/       # OpenTelemetry Collector & Grafana Tempo configs
    ├── scripts/             # Python & Bash simulation, benchmark, & drill scripts
    └── docker-compose.yml   # Multi-service local development orchestration
```

### Core Technologies

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Backend** | Rust (Actix-web, Tokio, SQLx, Redis) | Log ingestion, detection rule evaluation, multi-tenancy, alerting |
| **Agent** | Go (`fsnotify`, net/syslog) | Edge file tailing, syslog collection, HTTP batch shipping |
| **Frontend** | TypeScript, Next.js 16, React 19, Tailwind v4 | Analyst dashboard, onboarding, rules, cases, cost tracking |
| **Event Bus** | Apache Kafka (KRaft mode) | High-throughput buffered event streaming partitioned by tenant |
| **Storage** | PostgreSQL 18 & Elasticsearch 9.3 | Relational metadata / state (Postgres) and indexed logs (Elastic) |
| **Cache & State** | Redis 8 & In-Memory DashMap | L1/L2 caching, rate limiting, and sliding-window deduplication |
| **Telemetry** | OpenTelemetry, Tempo, Grafana | Distributed tracing, pipeline lag tracking, metrics collection |

---

## Prerequisites & Development Environment

Ensure your development machine has the following tools installed:

- **Operating System**: Linux (preferred), macOS, or Windows Subsystem for Linux (WSL2)
- **Container Runtime**: Docker (Engine 24+) & Docker Compose v2
- **Rust Toolchain**: Rust 1.75+ (stable) with `cargo`, `rustfmt`, and `clippy`
- **Go Toolchain**: Go 1.21+
- **Node.js**: Node.js 18.x or 20.x+ and `npm`
- **Python**: Python 3.10+ with `requests` library (`pip install requests`)
- **Git**: 2.30+

---

## Local Setup & Running the Stack

### 1. Clone the Repository

```bash
git clone https://github.com/MriBoyd/mini-siem-project.git
cd mini-siem-project/mini-siem
```

### 2. Launch Local Infrastructure

Start the background data plane services (PostgreSQL, Redis, Kafka, Elasticsearch, OpenTelemetry Collector, Tempo):

```bash
docker compose up -d postgres redis kafka elasticsearch otel-collector tempo
```

Initialize Kafka topics and Elasticsearch index templates:

```bash
docker compose up -d kafka-setup es-setup
```

Verify that all containers are healthy:

```bash
docker compose ps
```

### 3. Launch Backend (Rust)

In a new terminal:

```bash
cd backend

# Create local environment file if needed
cp .env.example .env   # or configure your environment variables

# Run the Actix-web server
cargo run
```

The backend server defaults to binding on `http://127.0.0.1:8080`.

### 4. Launch Edge Log Forwarder (Go)

In a new terminal:

```bash
cd agent
go run .
```

The agent will listen for syslog packets on UDP port `514` (configurable in `config.json`) and tail monitored log paths.

### 5. Launch SOC Frontend (Next.js)

In a new terminal:

```bash
cd frontend
npm install
npm run dev
```

Navigate to `http://localhost:3000` to interact with the web console.

---

## Branching & Git Workflow

We follow a standard feature branch workflow:

1. **Fork or create a branch** from `main`:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b <branch-type>/<short-description>
   ```

2. **Branch naming conventions**:
   - `feat/` for new features (e.g., `feat/suricata-log-parser`)
   - `fix/` for bug fixes (e.g., `fix/kafka-lag-offset-overflow`)
   - `perf/` for performance optimizations (e.g., `perf/dashmap-rule-eval`)
   - `refactor/` for code restructuring (e.g., `refactor/extract-rule-evaluator`)
   - `docs/` for documentation updates (e.g., `docs/api-guide`)
   - `test/` for unit, integration, or drill tests (e.g., `test/alert-dedup-cases`)

3. **Keep branches synchronized**:
   Rebase against upstream `main` regularly to avoid divergence:
   ```bash
   git fetch origin
   git rebase origin/main
   ```

---

## Commit Message Conventions

We enforce [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Each commit message must follow this structure:

```text
<type>(<scope>): <short imperative summary>

[optional body explaining context and rationale]

[optional footer: closes #123, BREAKING CHANGE: ...]
```

### Allowed Types

- `feat`: A new user- or system-facing feature
- `fix`: A bug fix
- `perf`: A code change that improves throughput or reduces latency/memory
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `docs`: Documentation only changes
- `test`: Adding or correcting tests
- `chore`: Maintenance tasks, dependency updates, tooling

### Recommended Scopes

`backend`, `agent`, `frontend`, `rules`, `detection`, `auth`, `queue`, `compliance`, `costs`, `cases`, `packs`, `observability`, `k8s`, `deps`

### Examples

- `feat(detection): add sliding-window correlation rule evaluator`
- `fix(queue): resolve partition consumer pause deadlock on full buffer`
- `perf(backend): replace Arc<Mutex> with ArcSwap for compiled rule table`
- `docs(readme): update local deployment and docker compose instructions`

---

## Component Development Guidelines

### Backend (Rust)

- **Code Quality**:
  - Format with `cargo fmt --check` before committing.
  - Lint with `cargo clippy --all-targets -- -D warnings`.
- **Error Handling**:
  - Use `thiserror` for domain-specific error types.
  - Use `anyhow::Result` only for top-level application boundaries or script runners.
  - Never call `unwrap()` or `expect()` on user-controlled input or production network paths.
- **Concurrency & Async**:
  - Built on Tokio and Actix-web. Never execute blocking synchronous code (such as file I/O or heavy computation) directly on async runtime threads; use `tokio::task::spawn_blocking` where necessary.
  - Protect shared in-memory state with lock-free structures (`ArcSwap`, `DashMap`, or atomic primitives) instead of coarse `Mutex` locks to sustain 50,000+ logs/sec.
- **Multi-Tenant Scoping**:
  - **Every single SQL query and Redis key must be scoped by `tenant_id`**.
  - Never allow cross-tenant data leaks. Audit functions must verify permissions against the active `Claims` struct extracted from the JWT token.
- **Running Backend Tests**:
  ```bash
  cd mini-siem/backend
  cargo test
  ```

### Log Forwarder Agent (Go)

- **Idiomatic Go**:
  - Format using `gofmt -s -w .` and check with `go vet ./...`.
  - Ensure zero goroutine leaks: all background loops must terminate cleanly when a `context.Context` is canceled.
- **Batching & Buffering**:
  - The agent buffers incoming logs in memory before batch-shipping to the backend. Ensure bounded buffer capacity to prevent out-of-memory (OOM) crashes on constrained edge hosts.
- **Running Agent Tests**:
  ```bash
  cd mini-siem/agent
  go test -race -v ./...
  ```

### Frontend (Next.js & TypeScript)

- **Framework & Libraries**:
  - Built with Next.js 16 (App Router), React 19, Tailwind CSS v4, and Radix UI / Shadcn primitives.
  - Refer to `mini-siem/frontend/AGENTS.md` for Next.js 16 guidelines and breaking API changes.
- **TypeScript Strictness**:
  - Strict mode is enabled. Do not use `any` unless absolutely unavoidable; declare proper interfaces and types in `src/types/`.
- **State & Data Fetching**:
  - Use TanStack React Query (`@tanstack/react-query`) for server state management, caching, and optimistic updates.
  - Use `sonner` for toast notifications.
- **Running Frontend Linting & Build**:
  ```bash
  cd mini-siem/frontend
  npm run lint
  npm run build
  ```

### Detection Rules & Signatures

When creating new detection rules:
1. Adhere to **Elastic Common Schema (ECS)** field mappings (`@timestamp`, `event.action`, `source.ip`, `user.name`, `host.name`).
2. Add both positive (event triggers alert) and negative (event does not trigger alert) test fixtures in `mini-siem/backend/tests/`.
3. Keep rule evaluation complexity low. Prefer hash-based lookups and pre-compiled regex / Aho-Corasick automata over dynamic evaluation during log ingestion.

### Infrastructure & Kubernetes

- Ensure all Kubernetes manifests in `k8s/` and `mini-siem/infrastructure/kubernetes/` specify explicit resource requests and limits (`cpu`, `memory`).
- Validate YAML formatting and ensure secrets are never checked into git manifests.

---

## Testing & Quality Assurance

### Reliability & Chaos Drills

The platform includes automated drill runners to validate fault tolerance, consumer lag recovery, and Kafka message replays:

```bash
# Navigate to the scripts directory
cd mini-siem/scripts

# Run both replay and chaos drills against local backend
python3 reliability_drill.py --url http://localhost:8080 --token <YOUR_JWT_TOKEN>

# Run replay drill only
python3 reliability_drill.py --skip-chaos --url http://localhost:8080 --token <YOUR_JWT_TOKEN>
```

### Synthetic Log & Alert Ingestion

You can generate realistic security events and simulated attacks using the included utilities:

```bash
# Send a single test alert
python3 send_alert.py --url http://localhost:8080 --api-key <YOUR_API_KEY>

# Send 50 alerts in batch mode
python3 send_alert.py --url http://localhost:8080 --count 50 --batch

# Generate mock failed-login bursts
python3 ../agent/mock_logs.py
```

---

## Security & Multi-Tenant Isolation Guidelines

Security is paramount in Mini SIEM. When contributing code, follow these principles:

1. **Strict Tenant Segregation**:
   - Every log ingested, stored, or queried must carry a validated `tenant_id`.
   - Redis keys must follow the convention `{tenant_id}:<key_name>`.
   - Elasticsearch indices or filters must restrict documents to the requesting tenant.
2. **Secrets & Credentials**:
   - Never commit API keys, private keys, `.env` files, or passwords to git.
   - Use environment variables for all secrets (`AUDIT_SIGNING_KEY`, `JWT_SECRET`, `DATABASE_URL`).
3. **Input Sanitization**:
   - Validate and sanitize all external inputs to guard against SQL injection, command injection, and SSRF attacks via webhook dispatchers.
4. **Rate Limiting**:
   - Ensure new API routes have appropriate rate limiting middleware attached to prevent resource exhaustion.

---

## Pull Request Checklist

Before submitting your Pull Request, ensure that:

- [ ] Your code compiles cleanly without warnings (`cargo check`, `go build`, `npm run build`).
- [ ] You have formatted your code (`cargo fmt`, `gofmt`, `npm run lint`).
- [ ] All unit and integration tests pass (`cargo test`, `go test ./...`).
- [ ] Any new API endpoints or configuration parameters are documented in `README.md` or API documentation.
- [ ] If you modified features, you have updated `CHANGELOG.md` under the `[Unreleased]` section.
- [ ] Tenant boundaries are strictly preserved in database queries, caches, and queues.
- [ ] No sensitive credentials, secrets, or temporary debugging tokens are committed.
- [ ] Your commit messages follow the [Conventional Commits](#commit-message-conventions) standard.

---

## Reporting Issues & Security Vulnerabilities

### Submitting Bug Reports

- Open an issue on GitHub describing the bug, including steps to reproduce, expected vs. actual behavior, environment details (OS, Docker version, Rust/Go version), and relevant backend logs.

### Security Vulnerabilities (Responsible Disclosure)

If you discover a security vulnerability (such as a multi-tenant data leak, authentication bypass, or remote code execution flaw), **please do NOT open a public GitHub issue**.

Instead, privately disclose the vulnerability to the project maintainer:

- **Security Contact**: Dagim Woldemareyam
- **Email**: `mriboyd1240@gmail.com`

Please include:
- A detailed description of the vulnerability
- Proof of Concept (PoC) or reproducible steps
- Potential impact and affected components

We appreciate your cooperation in allowing us to address the issue before public disclosure.

---

## License Notice

By contributing to the **Mini SIEM Platform**, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
