-- Make system_stats tenant-aware so dashboard fallback remains isolated.

ALTER TABLE system_stats
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

-- Convert the singleton primary key model into tenant-scoped uniqueness.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'system_stats_pkey'
    ) THEN
        ALTER TABLE system_stats DROP CONSTRAINT system_stats_pkey;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_system_stats_tenant_id ON system_stats (tenant_id);

-- Backfill existing singleton row.
UPDATE system_stats SET tenant_id = 'default' WHERE tenant_id = 'default';
