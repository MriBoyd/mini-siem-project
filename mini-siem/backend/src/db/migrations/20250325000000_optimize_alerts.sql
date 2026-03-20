-- Optimize alert lookup by source_ip and status
CREATE INDEX IF NOT EXISTS idx_alerts_ip_status ON alerts(source_ip, status);

-- Add index on rule_id for faster rule management/stats
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
