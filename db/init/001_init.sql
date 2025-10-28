CREATE TABLE IF NOT EXISTS auth_attempts (
    id SERIAL PRIMARY KEY,
    src_ip INET NOT NULL,                    -- because IPs aren't just text, you animal
    src_port INTEGER CHECK (src_port >= 0),  -- ports shouldn't be negative
    username TEXT,
    password TEXT,
    client_banner TEXT,
    fulltext TEXT,                           -- the full glorious dumpster fire
    ts TIMESTAMPTZ DEFAULT NOW()
);

-- optional
CREATE INDEX IF NOT EXISTS idx_auth_src_ip ON auth_attempts (src_ip);
CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_attempts (ts);
