-- Create detection rules table
CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    rule_type TEXT NOT NULL, -- e.g. 'brute_force', 'port_scan', 'malware'
    severity TEXT NOT NULL DEFAULT 'Medium', -- Low, Medium, High, Critical
    threshold INTEGER, -- For threshold-based rules
    window_seconds INTEGER, -- For window-based rules
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trigger to update updated_at
CREATE TRIGGER update_detection_rules_updated_at
BEFORE UPDATE ON detection_rules
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Seed some default rules
INSERT INTO detection_rules (name, description, rule_type, severity, threshold, window_seconds)
VALUES 
('SSH Brute Force', 'Detect multiple failed SSH logins from a single IP', 'brute_force', 'High', 5, 300),
('Port Scan Detection', 'Detect multiple connection attempts to different ports', 'port_scan', 'Medium', 20, 60),
('Malware C2 Communication', 'Detect communication with known malware C2 servers', 'malware', 'Critical', NULL, NULL)
ON CONFLICT (name) DO NOTHING;
