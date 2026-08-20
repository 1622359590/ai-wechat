CREATE TABLE devices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    credential_fingerprint bytea NOT NULL UNIQUE,
    credential_version smallint NOT NULL DEFAULT 1 CHECK (credential_version = 1),
    label text NOT NULL DEFAULT '' CHECK (char_length(label) <= 120),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    auth_expires_at timestamptz NULL,
    last_authenticated_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (octet_length(credential_fingerprint) = 32)
);

CREATE TABLE device_admin_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    action text NOT NULL CHECK (action IN ('created', 'enabled', 'disabled', 'expiry_changed')),
    actor_type text NOT NULL CHECK (actor_type IN ('migration', 'local_cli')),
    reason_code text NOT NULL CHECK (reason_code IN ('legacy_import', 'manual_add', 'manual_enable', 'manual_disable', 'manual_expiry')),
    created_at timestamptz NOT NULL
);
