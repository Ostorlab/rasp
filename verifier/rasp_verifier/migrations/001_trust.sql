CREATE TABLE IF NOT EXISTS rasp_records (
    tenant_id text NOT NULL, app_id text NOT NULL, kind text NOT NULL,
    record_id text NOT NULL, value jsonb NOT NULL,
    PRIMARY KEY (tenant_id, app_id, kind, record_id)
);
CREATE TABLE IF NOT EXISTS rasp_challenges (
    tenant_id text NOT NULL, app_id text NOT NULL, nonce text NOT NULL,
    purpose text NOT NULL, install_id text NOT NULL, expires_at double precision NOT NULL,
    PRIMARY KEY (tenant_id, app_id, nonce)
);
CREATE INDEX IF NOT EXISTS rasp_challenges_expiry ON rasp_challenges (expires_at);
CREATE TABLE IF NOT EXISTS rasp_counters (
    tenant_id text NOT NULL, app_id text NOT NULL, key_id text NOT NULL,
    counter bigint NOT NULL CHECK (counter > 0),
    PRIMARY KEY (tenant_id, app_id, key_id)
);
ALTER TABLE rasp_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE rasp_records FORCE ROW LEVEL SECURITY;
ALTER TABLE rasp_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE rasp_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE rasp_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE rasp_counters FORCE ROW LEVEL SECURITY;
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['rasp_records', 'rasp_challenges', 'rasp_counters'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = table_name AND policyname = 'application_scope') THEN
            EXECUTE format('CREATE POLICY application_scope ON %I USING (tenant_id = current_setting(''rasp.tenant_id'', true) AND app_id = current_setting(''rasp.app_id'', true)) WITH CHECK (tenant_id = current_setting(''rasp.tenant_id'', true) AND app_id = current_setting(''rasp.app_id'', true))', table_name);
        END IF;
    END LOOP;
END $$;
