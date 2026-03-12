-- Create alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    events JSONB NOT NULL DEFAULT '[]',
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'NEW',
    events_count INTEGER NOT NULL DEFAULT 1,
    assigned_to VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for fast queries
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_first_seen ON alerts(first_seen);
CREATE INDEX idx_alerts_last_seen ON alerts(last_seen);

-- Create logs table (optional - for storing all logs)
CREATE TABLE IF NOT EXISTS logs (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(255) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    target_user VARCHAR(255),
    service VARCHAR(255),
    message TEXT NOT NULL,
    severity VARCHAR(50) NOT NULL,
    metadata JSONB DEFAULT '{}',
    received_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_logs_source_ip ON logs(source_ip);
CREATE INDEX idx_logs_timestamp ON logs(timestamp);
CREATE INDEX idx_logs_event_type ON logs(event_type);