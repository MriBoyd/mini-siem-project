-- Tenant-scoped data-cost controls and budgets.

CREATE TABLE IF NOT EXISTS tenant_data_cost_policies (
    tenant_id TEXT PRIMARY KEY,
    daily_ingest_bytes_budget BIGINT NOT NULL DEFAULT 25000000000,
    hot_storage_bytes_budget BIGINT NOT NULL DEFAULT 10000000000,
    warm_storage_bytes_budget BIGINT NOT NULL DEFAULT 10000000000,
    cold_storage_bytes_budget BIGINT NOT NULL DEFAULT 5000000000,
    sampling_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    low_value_sampling_percent INTEGER NOT NULL DEFAULT 25,
    high_value_sampling_percent INTEGER NOT NULL DEFAULT 100,
    drop_low_value_when_over_budget BOOLEAN NOT NULL DEFAULT TRUE,
    schema_drop_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_budgets JSONB NOT NULL DEFAULT '{}'::jsonb,
    integration_budgets JSONB NOT NULL DEFAULT '{}'::jsonb,
    team_budgets JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_data_cost_policies_updated_at
    ON tenant_data_cost_policies (updated_at DESC);