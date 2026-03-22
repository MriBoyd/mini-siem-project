-- Create a small table to persist aggregated SIEM stats periodically
CREATE TABLE IF NOT EXISTS system_stats (
    id INTEGER PRIMARY KEY DEFAULT 1,
    total_logs BIGINT NOT NULL DEFAULT 0,
    total_alerts BIGINT NOT NULL DEFAULT 0,
    active_alerts BIGINT NOT NULL DEFAULT 0,
    critical_alerts BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ensure a singleton row exists
INSERT INTO system_stats (id) VALUES (1) ON CONFLICT DO NOTHING;
