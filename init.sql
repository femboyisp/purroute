-- init.sql
CREATE TABLE IF NOT EXISTS public.global (
    id SERIAL PRIMARY KEY,
    total_connections BIGINT,
    succeeded_connections BIGINT,
    failed_connections BIGINT,
    total_bytes_in BIGINT,
    total_bytes_out BIGINT
);

-- Insert an initial record
INSERT INTO
    public.global (
        id,
        total_connections,
        succeeded_connections,
        failed_connections,
        total_bytes_in,
        total_bytes_out
    )
VALUES
    (1, 0, 0, 0, 0, 0) ON CONFLICT (id) DO NOTHING;

-- Create accounts table
CREATE TABLE IF NOT EXISTS public.accounts (
    account BIGINT PRIMARY KEY,
    proxy INT,
    feedback TEXT,
    registered TIMESTAMP
);

-- Create user_stats table
CREATE TABLE IF NOT EXISTS public.user_stats (
    account BIGINT PRIMARY KEY,
    total_connections BIGINT,
    succeeded_connections BIGINT,
    failed_connections BIGINT,
    total_bytes_in BIGINT,
    total_bytes_out BIGINT,
    FOREIGN KEY (account) REFERENCES public.accounts (account)
);
