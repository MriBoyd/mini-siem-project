# Mini SIEM Platform

A production-style, multi-tenant SIEM platform built with **Rust, Go, TypeScript, Next.js, PostgreSQL, Kafka, Redis, Elasticsearch, Docker, Kubernetes, OpenTelemetry, and Terraform**.

This project demonstrates a scalable security ingestion and detection pipeline capable of processing **50,000+ logs/second** through Kafka, evaluating **1,000+ logs in real time**, and triggering alerts through webhooks with **sub-500ms end-to-end latency**. It also includes dead-letter handling, observability, tenant-aware rate limiting, and Kubernetes-based autoscaling.

---

## Overview

Mini SIEM is designed to help security teams ingest, enrich, detect, and visualize security events across multiple tenants.

It includes:

- A **Go-based Log Forwarder / agent** for collecting and shipping logs
- A **Rust-based backend** for ingest, detection, alerting, and tenant isolation
- A **Next.js frontend** for onboarding, investigation, and monitoring
- **Kafka** for high-throughput event streaming and tenant-partitioned processing
- **PostgreSQL** for application and security data
- **Redis** for caching, rate limiting, and queue support
- **Elasticsearch** for searchable log indexing
- **OpenTelemetry** for traces and metrics
- **Docker / Kubernetes** for local and production deployment
- **Terraform** for infrastructure provisioning

---

## Key Features

### Multi-Tenant Ingestion
- Supports tenant-isolated event ingestion
- Kafka partitions are keyed by tenant to preserve ordering and throughput
- Tenant-aware rate limits help protect platform stability

### High-Throughput Detection Pipeline
- Processes **50,000+ logs per second**
- Rust-based detection workers evaluate events in near real time
- Alerts are generated from configurable detection rules and curated packs

### Alerting and Response
- Alerts can trigger webhook notifications
- Critical alerts can automatically drive response actions
- Alert lifecycle tracking includes severity, status, timestamps, and event context

### Reliability and Recovery
- Dead-letter queues capture failed processing
- Replay and chaos drills help validate resilience
- Kafka lag monitoring and queue backpressure help prevent overload

### Observability
- OpenTelemetry tracing across backend services
- Grafana dashboards for tenant throughput and processing lag
- Monitoring for service health, queue lag, and system behavior

### Scalable Deployment
- Runs on Kubernetes with HPA-based autoscaling
- Designed for production-like load testing
- Achieved **99.95% uptime during load testing**

---

## Architecture

### Components

#### 1. Log Forwarder / Agent
Written in **Go**, the agent collects logs from local files and syslog sources and forwards them to the SIEM backend in batches.

#### 2. Backend
Written in **Rust**, the backend handles:
- authentication
- ingestion
- detection
- alerting
- tenant limits
- queue management
- reliability workflows
- monitoring / telemetry
- Elasticsearch indexing

#### 3. Frontend
Written in **TypeScript** and **Next.js**, the UI provides:
- onboarding
- health checks
- alert visibility
- rule / detection views
- readiness workflows

#### 4. Data Plane
- **Kafka**: event streaming and buffering
- **PostgreSQL**: persistent relational data
- **Redis**: caching, rate limiting, coordination
- **Elasticsearch**: indexed log search

#### 5. Observability Stack
- **OpenTelemetry Collector**
- tracing backend
- Grafana dashboards
- service metrics and lag monitoring

---

## Tech Stack

- **Backend:** Rust
- **Agent:** Go
- **Frontend:** TypeScript, Next.js
- **Database:** PostgreSQL
- **Streaming:** Kafka
- **Cache / Coordination:** Redis
- **Search:** Elasticsearch
- **Infrastructure:** Docker, Kubernetes, Terraform
- **Observability:** OpenTelemetry, Grafana

---

## Example Capabilities

- Ingest security logs from endpoints and syslog sources
- Partition events by tenant for isolation and scale
- Evaluate detection rules in real time
- Generate alerts with severity and lifecycle tracking
- Push critical alerts to webhooks
- Capture failures in dead-letter queues
- Monitor throughput and processing lag per tenant
- Auto-scale workers based on load

---

## Repository Structure

```text
mini-siem/
├── agent/          # Go log forwarder / syslog collector
├── backend/        # Rust SIEM backend
├── frontend/       # Next.js UI
├── scripts/        # Utility scripts for drills and alert generation
├── docker-compose.yml
└── observability/  # Collector / dashboard configuration
```

---

## Getting Started

### Prerequisites
- Docker
- Docker Compose
- Rust toolchain
- Go 1.21+
- Node.js 18+
- Kubernetes cluster for production deployment
- Terraform for infrastructure provisioning

### Local Development

1. Clone the repository

```bash
git clone https://github.com/MriBoyd/mini-siem-project.git
cd mini-siem-project/mini-siem
```

2. Start dependencies

```bash
docker compose up -d postgres redis kafka elasticsearch otel-collector tempo
```

3. Initialize Kafka topics and Elasticsearch index

```bash
docker compose up -d kafka-setup es-setup
```

4. Run the backend

```bash
cd backend
cargo run
```

5. Run the agent

```bash
cd ../agent
go run .
```

6. Run the frontend

```bash
cd ../frontend
npm install
npm run dev
```

---

## Docker Compose Services

The local stack includes:

- **PostgreSQL** on `localhost:5432`
- **Redis** on `localhost:6379`
- **Kafka** on `localhost:9092`
- **Elasticsearch** on `localhost:9200`
- **OpenTelemetry Collector** on `localhost:4317` / `4318`
- **Tempo** on `localhost:3200`

---

## Configuration

### Backend Environment Variables

The backend reads configuration from environment variables. Common settings include:

- `DATABASE_URL`
- `REDIS_URL`
- `KAFKA_BROKERS`
- `SLACK_WEBHOOK`
- `API_BIND`
- `METRICS_BIND`
- `CORS_ALLOWED_ORIGINS`
- `DETECTION_WORKERS`
- `DETECTION_MAILBOX_SIZE`
- `DETECTION_PARTITION_KEY`
- `KAFKA_LAG_SAMPLE_INTERVAL_SECS`
- `KAFKA_LAG_WATERMARK_TIMEOUT_MS`
- `KAFKA_PAUSE_ON_FULL`
- `KAFKA_PAUSE_TIMEOUT_MS`
- `RATE_LIMIT_PER_IP`
- `RATE_LIMIT_WINDOW_MS`
- `RATE_LIMIT_SAMPLE_RATE`
- `TENANT_API_REQUESTS_PER_MINUTE`
- `TENANT_INGEST_EVENTS_PER_MINUTE`
- `TENANT_RULE_MUTATIONS_PER_MINUTE`
- `TENANT_WS_CONNECTIONS_PER_MINUTE`
- `TENANT_AUDIT_QUERIES_PER_MINUTE`
- `ELASTICSEARCH_HOST`
- `ELASTICSEARCH_INDEX`
- `METRICS_MAX_TENANT_LABELS`
- `OTEL_SERVICE_NAME`
- `AUDIT_SIGNING_KEY`

### Agent Configuration

The Go agent uses a JSON configuration file containing:

- SIEM backend URL
- API key
- syslog enablement
- syslog port
- batch size
- flush interval
- monitored file paths

Example:

```json
{
  "siem_server": "http://localhost:8080",
  "api_key": "YOUR_EDGE_API_KEY",
  "enable_syslog": true,
  "syslog_port": 514,
  "batch_size": 100,
  "flush_interval": 5000000000,
  "files": [
    {
      "path": "/var/log/auth.log"
    }
  ]
}
```

---

## Detection and Alerting

Mini SIEM supports rule-based detections and curated security packs.

### Detection Examples
- brute force login attempts
- suspicious file rename bursts
- insider risk activity
- large data exfiltration patterns
- off-hours access anomalies

### Alert Model
Alerts include:
- alert ID
- tenant ID
- rule ID / rule name
- severity
- description
- source IP
- event context
- first / last seen timestamps
- status
- event count

### Alert Severities
- CRITICAL
- HIGH
- MEDIUM
- LOW
- INFO

### Alert Statuses
- NEW
- INVESTIGATING
- RESOLVED
- FALSE_POSITIVE

---

## Reliability Features

- Kafka replay drill support
- Chaos drill support
- Dead-letter queue handling
- Backpressure and pause controls
- Retry-safe ingestion design
- Health and readiness monitoring

Run a reliability drill with:

```bash
python3 scripts/reliability_drill.py --url http://localhost:8080 --token YOUR_JWT
```

Skip individual drills:

```bash
python3 scripts/reliability_drill.py --skip-chaos
python3 scripts/reliability_drill.py --skip-replay
```

---

## Alert Injection Script

You can generate synthetic alerts for testing with:

```bash
python3 scripts/send_alert.py --url http://localhost:8080 --api-key YOUR_API_KEY
```

Batch mode:

```bash
python3 scripts/send_alert.py --count 10 --batch
```

---

## Observability

Mini SIEM uses OpenTelemetry for:
- traces
- service attribution
- backend instrumentation
- exporter integration

It also supports:
- Grafana dashboards
- tenant throughput monitoring
- processing lag visibility
- queue health checks
- system health endpoints

---

## Deployment

### Docker
Use Docker Compose for local development and dependency orchestration.

### Kubernetes
The platform is designed for Kubernetes deployment with:
- horizontal pod autoscaling
- scalable ingestion workers
- stateless service deployment
- observability integration

### Terraform
Terraform can be used to provision:
- compute
- network
- managed databases
- Kafka / streaming infrastructure
- observability resources

---

## Security Considerations

- Tenant isolation is enforced in event processing and metrics labeling
- Rate limiting protects API, ingest, and websocket endpoints
- Signing keys are required in production
- Sensitive data should be stored in environment variables or secret managers
- Kafka dead-letter queues capture malformed or failed messages for analysis

---

## Performance Goals

This platform was built to demonstrate:
- **50,000+ logs/sec** ingest throughput
- **1,000+ logs** evaluated in real time
- **< 500ms** end-to-end alert latency
- **99.95% uptime** during load testing

Actual performance depends on infrastructure, tenant mix, rule complexity, and deployment configuration.

---

## License

No license has been specified yet.

---

## Acknowledgments

Built as a mini security operations platform to showcase:
- multi-tenant event processing
- high-throughput streaming architecture
- real-time detection
- cloud-native deployment
- observability-first engineering
```
