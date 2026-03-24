-- Add condition column to detection rules for dynamic DSL evaluation
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS condition JSONB;

-- Add generic rules as a valid rule_type
-- (Comment only, as rule_type is TEXT)

-- Example of a generic rule
-- INSERT INTO detection_rules (name, description, rule_type, severity, condition)
-- VALUES ('Suspicious PowerShell', 'Detect suspicious powershell execution', 'generic', 'High', '{"all": [{"field": "message", "op": "contains", "value": "powershell -e"}]}');
