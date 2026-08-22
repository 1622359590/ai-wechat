CREATE TABLE admin_users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username text NOT NULL CHECK (char_length(username) BETWEEN 3 AND 64),
    username_normalized text NOT NULL UNIQUE
        CHECK (char_length(username_normalized) BETWEEN 3 AND 64)
        CHECK (username_normalized = lower(username_normalized))
        CHECK (username_normalized ~ '^[a-z0-9._-]+$'),
    password_hash text NOT NULL CHECK (char_length(password_hash) BETWEEN 1 AND 1024),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    password_version bigint NOT NULL DEFAULT 1 CHECK (password_version > 0),
    last_login_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE admin_sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
    admin_user_id uuid NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    password_version bigint NOT NULL CHECK (password_version > 0),
    created_at timestamptz NOT NULL,
    last_used_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    CHECK (last_used_at >= created_at),
    CHECK (expires_at > created_at)
);

CREATE INDEX admin_sessions_user_id_idx ON admin_sessions (admin_user_id);
CREATE INDEX admin_sessions_expires_at_idx ON admin_sessions (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE admin_security_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    admin_user_id uuid NOT NULL REFERENCES admin_users(id),
    action text NOT NULL CHECK (action IN ('account_created', 'password_changed', 'password_reset')),
    actor_type text NOT NULL CHECK (actor_type IN ('local_cli', 'admin_web')),
    created_at timestamptz NOT NULL
);

ALTER TABLE device_admin_events
    ADD COLUMN admin_user_id uuid NULL REFERENCES admin_users(id);

ALTER TABLE device_admin_events
    DROP CONSTRAINT device_admin_events_actor_type_check;

ALTER TABLE device_admin_events
    ADD CONSTRAINT device_admin_events_actor_type_check
        CHECK (actor_type IN ('migration', 'local_cli', 'admin_web'));

ALTER TABLE device_admin_events
    ADD CONSTRAINT device_admin_events_actor_identity_check
        CHECK (
            (actor_type = 'admin_web' AND admin_user_id IS NOT NULL)
            OR (actor_type <> 'admin_web' AND admin_user_id IS NULL)
        );
