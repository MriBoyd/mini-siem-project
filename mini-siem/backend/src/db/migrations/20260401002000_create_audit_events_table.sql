-- Signed, tenant-scoped audit trail for privileged actions.

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    actor_user_id TEXT NOT NULL,
    actor_email TEXT NOT NULL,
    actor_roles TEXT[] NOT NULL DEFAULT '{}'::text[],
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    target_tenant_id TEXT,
    request_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_hash TEXT,
    event_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created_at
    ON audit_events (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_target
    ON audit_events (tenant_id, target_tenant_id, created_at DESC);