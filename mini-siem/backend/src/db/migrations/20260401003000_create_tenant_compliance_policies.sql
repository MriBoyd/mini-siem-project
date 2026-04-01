-- Per-tenant compliance policy, key rotation policy, and legal hold controls.

CREATE TABLE IF NOT EXISTS tenant_compliance_policies (
    tenant_id TEXT PRIMARY KEY,
    retention_days INTEGER NOT NULL DEFAULT 365,
    legal_hold BOOLEAN NOT NULL DEFAULT false,
    legal_hold_reason TEXT,
    legal_hold_until TIMESTAMPTZ,
    access_review_interval_days INTEGER NOT NULL DEFAULT 90,
    key_rotation_interval_days INTEGER NOT NULL DEFAULT 90,
    last_key_rotation_at TIMESTAMPTZ,
    evidence_export_enabled BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_compliance_policies_legal_hold
    ON tenant_compliance_policies (legal_hold, legal_hold_until);