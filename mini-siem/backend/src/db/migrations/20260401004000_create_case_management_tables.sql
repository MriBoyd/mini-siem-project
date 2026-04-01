-- Case management primitives for tying alerts to outcomes.

CREATE TABLE IF NOT EXISTS case_playbooks (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'INFO',
    sla_minutes INTEGER NOT NULL DEFAULT 60,
    escalate_after_minutes INTEGER NOT NULL DEFAULT 120,
    steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    primary_alert_id UUID NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'INFO',
    status TEXT NOT NULL DEFAULT 'NEW',
    owner_user_id TEXT,
    owner_email TEXT,
    playbook_id UUID,
    sla_due_at TIMESTAMPTZ,
    escalation_at TIMESTAMPTZ,
    escalated_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    outcome TEXT,
    postmortem_summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_cases_playbook FOREIGN KEY (playbook_id) REFERENCES case_playbooks (id) ON DELETE SET NULL,
    CONSTRAINT uq_cases_tenant_primary_alert UNIQUE (tenant_id, primary_alert_id)
);

CREATE TABLE IF NOT EXISTS case_alert_links (
    case_id UUID NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
    alert_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, alert_id),
    CONSTRAINT uq_case_alert_links_tenant_alert UNIQUE (tenant_id, alert_id)
);

CREATE TABLE IF NOT EXISTS case_timeline_events (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases (id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    actor_user_id TEXT,
    actor_email TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_status_created
    ON cases (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_owner
    ON cases (tenant_id, owner_email, owner_user_id);

CREATE INDEX IF NOT EXISTS idx_case_timeline_case_created
    ON case_timeline_events (case_id, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_case_playbooks_tenant_enabled
    ON case_playbooks (tenant_id, is_enabled, created_at DESC);