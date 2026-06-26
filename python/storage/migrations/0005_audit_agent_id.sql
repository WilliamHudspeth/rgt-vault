-- ASVS 7.1.4: audit log entries must include sufficient metadata for
-- a detailed investigation timeline. Adding agent_id so every event
-- records the identity of the actor that triggered it.
ALTER TABLE audit_logs ADD COLUMN agent_id TEXT;
