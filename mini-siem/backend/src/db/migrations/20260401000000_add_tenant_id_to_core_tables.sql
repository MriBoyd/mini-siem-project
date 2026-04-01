-- Add tenant_id to core multi-tenant tables and backfill existing rows.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

-- Drop global uniqueness that would leak/forbid duplicate identities across tenants.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'users_email_key'
    ) THEN
        ALTER TABLE users DROP CONSTRAINT users_email_key;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'detection_rules_name_key'
    ) THEN
        ALTER TABLE detection_rules DROP CONSTRAINT detection_rules_name_key;
    END IF;
END $$;

-- Tenant-scoped uniqueness and lookup indexes.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email ON users (tenant_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_tenant_name ON detection_rules (tenant_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_tenant_id_id ON alerts (tenant_id, id);

-- Tenant-scoped access paths.
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_source_ip_status ON alerts (tenant_id, source_ip, status);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_last_seen ON alerts (tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_rules_tenant_enabled ON detection_rules (tenant_id, is_enabled);
