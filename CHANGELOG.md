# Changelog

All notable changes to the **Mini SIEM Platform** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- **Distributed Agent Management**: Remote configuration pushing and heartbeat tracking for edge Go agents via mTLS.
- **Automated Playbooks**: Pluggable SOAR action runners (IP containment, webhook escalation, Slack/PagerDuty incident dispatch).
- **Vector Search / Anomaly Detection**: Hybrid semantic similarity search over indexed security logs using vector embeddings.
- **Rule Verification Sandbox**: In-browser rule sandbox allowing security engineers to test custom generic and correlation rules against synthetic event traces before production deployment.

---

## [0.3.0] - 2026-04-01

### Added
- **Multi-Tenant Architecture**:
  - Full tenant isolation across core storage and ingestion pipelines (`ddde86b`).
  - Tenant-keyed Kafka partitioning ensuring strict in-order processing per tenant while preventing cross-tenant head-of-line blocking (`14c8488`).
  - Tenant-scoped API limits, ingest event throttling, rule mutation limits, and WebSocket connection quotas (`8c1b4da`).
  - Multi-tenant aggregation for system statistics and telemetry in PostgreSQL and Redis (`113c5da`).
- **Incident & Case Management**:
  - Case management backend with complete CRUD lifecycle (`NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`) and timeline event auditing (`4ca5786`).
  - Frontend case management module at `/cases` with priority tagging, owner assignment, and alert association.
- **Detection Packs**:
  - Modular security detection packs API (`/api/packs`) supporting import, enable/disable, and versioning of pre-packaged threat rulesets (`a9878cf`).
  - UI management page at `/packs` for browsing MITRE ATT&CK aligned rule packs (e.g., Ransomware, Exfiltration, Lateral Movement).
- **Tenant Compliance & Auditing**:
  - Compliance policy engine (`/api/compliance`) enabling tenants to define and audit log retention, encryption, and access policies (`a986a5e`).
  - Cryptographically verifiable audit logging with HMAC-SHA256 signature verification (`AUDIT_SIGNING_KEY`) for tamper-evident compliance logs (`80a0b5f`).
- **Data Cost Tracking & Forecasting**:
  - Cost governance engine calculating storage, ingestion, and retention expenditure per tenant (`29c93ee`).
  - Interactive cost analysis dashboard at `/cost` providing budget threshold warnings and quota forecasting.
- **Reliability & Chaos Drills**:
  - Reliability drill engine (`mini-siem/scripts/reliability_drill.py` and `/api/reliability` backend handler) supporting automated chaos testing and Kafka replay drills (`fb1de60`).
  - API endpoints for reporting reliability drill status, pass/fail thresholds, and recovery lag metrics.
- **High-Performance Threat Detection (Aho-Corasick)**:
  - Multi-pattern string matching engine utilizing `aho-corasick` for sub-millisecond IOC (Indicators of Compromise) and malware signature matching against log streams (`a16ea7a`).
- **Observability & Distributed Tracing**:
  - Native OpenTelemetry instrumentation (`opentelemetry`, `tracing-opentelemetry`) exporting traces and spans to OpenTelemetry Collector and Grafana Tempo (`8ba7850`, `9db8643`).
  - Kafka consumer lag monitoring task sampling partition lag periodically with configurable alert watermarks (`d114eb2`, `705947f`).
- **Resilient Execution & Lifecycle**:
  - Background `TaskRegistry` coordinating graceful shutdown across Kafka consumers, worker pools, batch writers, and Redis syncer tasks (`0ddefbf`).
  - Detection worker pool scaling with configurable worker count (`DETECTION_WORKERS`) and partition routing (`048236a`).
- **Frontend Enhancements**:
  - Revamped health monitoring dashboard and onboarding wizard for new tenants (`74df6a6`).
  - Live reliability test view with drill progress tracking.

### Changed
- **Direct Kafka Ingestion**: Bypassed local in-memory ingest channel in favor of direct, zero-copy publishing to Kafka queues with bounded timeout and non-blocking backpressure push (`e01b3e2`, `91f0ba9`).
- **Shared Ingest Producer Task**: Refactored backend `AppState` to share an asynchronous high-throughput Kafka producer task across Actix HTTP worker threads (`b3fbdf8`).
- **Elasticsearch Client Lifecycle**: Migrated Elasticsearch connection handling to a dynamic watch pattern supporting zero-downtime cluster reconnection and dynamic index reconfiguration (`c434783`, `9a047fb`).
- **Tenant ID Standardization**: Unified tenant identity extraction and normalization across user registration, login, and token refresh endpoints (`ad2ce67`).

### Fixed
- Fixed missing `Serialize` derive on authentication handler response structures (`5713e98`).
- Resolved claims extraction ambiguity in rules handler functions (`8f5a1e7`).
- Cleaned up redundant imports and dead code in log and cost handlers (`b3cafcf`).
- Fixed dropped log tracking metrics to accurately reflect queue backpressure events (`c8751f1`).

### Security
- **Hardened Token Management**: Implemented HMAC-SHA256 hashed refresh tokens with database persistence to prevent token replay attacks (`fbf1f9d`).
- **JWKS & Claims Verification**: Added JWKS key caching, explicit token audience/issuer validation, and tenant mismatch prevention (`10c1c4e`).
- **WebSocket Ticket Authentication**: Replaced raw query token passing with short-lived single-use WebSocket ticket tokens (`7dcba47`).
- **CORS Configuration**: Restrictive CORS middleware enforcing environment-specified origin whitelists (`CORS_ALLOWED_ORIGINS`) (`375adcc`).

---

## [0.2.0] - 2026-03-24

### Added
- **Elasticsearch Log Storage & Search**:
  - Direct log stream indexing into Elasticsearch with dedicated `@timestamp` mapping and index template support (`17f6566`, `6bc2ab1`).
  - Health check polling and automatic DLQ (Dead Letter Queue) routing for logs rejected by Elasticsearch (`2ac0473`, `1dca1fa`).
  - `/api/logs/recent` query endpoint retrieving indexed security events with pagination and filtering (`5bdffc9`).
- **Log Normalization (ECS)**:
  - Built-in Elastic Common Schema (ECS) normalization engine transforming heterogeneous syslog, auth, and application events into structured format (`42ba902`).
- **Advanced Rule Engine**:
  - Generic rule engine evaluating dynamic nested boolean expressions (`AND`, `OR`, `NOT`, regex, numerical thresholds) over JSON payloads (`1090530`).
  - Stateful correlation engine evaluating multi-stage events over sliding time windows (e.g., 5 failed logins followed by successful login) (`a10ae6b`).
  - Precompiled rule representation (`CompiledRule`) with `SmallVec` optimizations for fast candidate matching (`6f07061`, `1a3c999`).
  - `ArcSwap` based lock-free concurrent rule table swap allowing zero-downtime rule updates while evaluating logs (`ea8facb`).
- **High-Throughput Caching Architecture**:
  - Dual-layer cache architecture: L1 in-memory `DashMap` cache combined with L2 Redis cache (`93244e2`, `5f63e45`).
  - L1 stale entry eviction, hot key refresh maintenance, and batch counter increments (`9df2884`).
  - Asynchronous Redis-to-PostgreSQL periodic stats syncer maintaining the `system_stats` table (`d008a0c`).
- **Database Batching & Deduplication**:
  - Alert batching processor (`DbBatcher`) accumulating alert writes for PostgreSQL with exponential flush interval and fallback flush mechanisms (`d9f74dc`).
  - Sliding-window alert deduplication preventing notification storms from recurring security incidents (`65b7575`).
- **Backpressure & Flow Control**:
  - Hybrid backpressure engine monitoring channel fullness, pausing Kafka consumers when internal queues saturate, and automatically resuming when capacity frees up (`26e7eac`, `74da3bc`).
- **Real-Time Streaming**:
  - WebSocket hub broadcasting live alerts and coalesced dashboard counters to active SOC analyst browser sessions (`b7b4c18`, `b2f13b8`, `02c43e1`).

### Changed
- Decoupled log persistence from PostgreSQL: hot raw logs are indexed in Elasticsearch while PostgreSQL strictly persists relational state (users, rules, alerts, cases, packs) (`8bc7008`, `341f2c3`).
- Refactored rule indexing from flat lists to type-partitioned hash maps indexed by `LogTag` (`c058d4e`, `0176c7a`, `abd5f2e`).
- Streamlined Redis caching for log and alert statistics with atomic counter decrements and pipeline operations (`677eef0`, `718f053`).

### Fixed
- Fixed PostgreSQL `events_count` field mismatch between Rust entity struct and `INT4` column (`6d242ff`).
- Updated API endpoint routes removing legacy `/v1` prefix across dashboard and rule controllers (`99d1685`).
- Corrected error status propagation in the Elasticsearch client to prevent silent indexing failures (`d50a082`).

---

## [0.1.0] - 2026-03-18

### Added
- **Core Rust Backend**:
  - Built with Actix-web, Tokio, SQLx, and Redis.
  - Ingestion endpoint accepting single and batch log payloads (`/api/logs`).
  - Alert management endpoints (`/api/alerts`) with filtering by severity, status, and time range.
  - Rule management endpoints (`/api/rules`) supporting CRUD operations on basic threshold and brute force rules (`e0fa63a`).
  - JWT authentication with secure password hashing (`argon2`), user registration, login, and RBAC (`e990c31`, `4d7d361`).
  - Rate limiting middleware per client IP (`4862f5e`).
- **Go Log Shipper / Agent**:
  - Lightweight Go agent for tailing system log files (`/var/log/auth.log`, `syslog`) using `fsnotify` (`agent-go`).
  - Built-in UDP/TCP Syslog collector server.
  - In-memory event buffering with batched HTTP shipping and configurable flush timeouts.
- **Next.js SOC Frontend**:
  - Next.js and React web dashboard with Tailwind CSS styling and Radix UI components.
  - Real-time dashboard stats showing log velocity, alert counts, and system status (`390fa55`).
  - Authentication views for login and session management.
- **Data & Streaming Infrastructure**:
  - Apache Kafka in KRaft mode (Zookeeper removed) for event queuing (`59bc0a7`).
  - PostgreSQL 18 with migrations for schema definitions.
  - Redis 8 for fast state lookups and counter management.
  - Docker Compose configuration orchestrating backend, databases, and message brokers (`d855e50`).
- **Testing & Simulation**:
  - Python mock log generator simulating failed SSH login attacks (`b0bb006`).
  - Alert sending helper script for ingestion testing (`mini-siem/scripts/send_alert.py`) (`d855e50`).

### Security
- Added secure environment variable parsing, ignoring plain `.env` files from version control to prevent secret leakage (`ebba739`, `fc7ca2a`).
- Enforced JWT validation middleware across all sensitive endpoints including `auth::me` (`7bf4ae9`).

---

[Unreleased]: https://github.com/MriBoyd/mini-siem-project/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/MriBoyd/mini-siem-project/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/MriBoyd/mini-siem-project/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MriBoyd/mini-siem-project/releases/tag/v0.1.0
