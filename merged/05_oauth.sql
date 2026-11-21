-- ============================================================================
-- OAuth 2.0 sessions for the login server (login-server/login_server.py).
--
--   psql -U postgres -d erms -f 05_oauth.sql      (safe to run again)
--
-- One row = one sign-in session.  token_id is public: it is the loginId the
-- login server gives the AM, and the am_keys endpoint only stores keys pushed
-- with the token_id of a live session of that user.  The tokens themselves are
-- never stored, only their SHA-256 (hex), so a copy of this table cannot be
-- used to sign in.
--
-- A session is live while revoked_at IS NULL AND session_expires_at > now().
-- When a user's last live session ends (revoke, sign-out, expiry, see
-- oauth_end_sessions), login_status goes to 0 and the hook removes the keys.
-- ============================================================================
BEGIN;

CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_id            VARCHAR(64)  PRIMARY KEY,          -- = loginId sent to the AM
    access_hash         CHAR(64)     NOT NULL UNIQUE,      -- sha256 hex of the access token
    refresh_hash        CHAR(64)     UNIQUE,               -- sha256 hex of the refresh token (NULL: none)
    tenant_id           BIGINT       NOT NULL,
    user_id             BIGINT       NOT NULL,
    client_id           VARCHAR(64)  NOT NULL DEFAULT 'erms_web',
    scope               VARCHAR(128) NOT NULL DEFAULT 'read write',
    access_expires_at   TIMESTAMPTZ  NOT NULL,
    session_expires_at  TIMESTAMPTZ  NOT NULL,             -- refresh token expiry (or = access expiry)
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    refreshed_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revoke_reason       VARCHAR(32),                       -- revoked / signed_out / expired
    CONSTRAINT fk_oauth_tokens_user
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES user_accounts (tenant_id, user_id) ON DELETE CASCADE,
    CONSTRAINT ck_oauth_tokens_expiry CHECK (session_expires_at >= access_expires_at)
);
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_live_user
    ON oauth_tokens (user_id) WHERE revoked_at IS NULL;

-- Ends sessions; signs out (login_status = 0, keys removed by the hook) every
-- user of those sessions who has no other live session.  Returns how many
-- users were signed out.
CREATE OR REPLACE FUNCTION oauth_end_sessions(p_token_ids text[], p_reason text)
RETURNS integer LANGUAGE plpgsql AS $$
DECLARE
    n integer;
BEGIN
    UPDATE oauth_tokens
       SET revoked_at = now(), revoke_reason = p_reason
     WHERE token_id = ANY (p_token_ids) AND revoked_at IS NULL;

    UPDATE user_accounts u
       SET login_status = 0
     WHERE u.login_status = 1
       AND u.user_id IN (SELECT t.user_id FROM oauth_tokens t WHERE t.token_id = ANY (p_token_ids))
       AND NOT EXISTS (SELECT 1 FROM oauth_tokens t
                        WHERE t.user_id = u.user_id AND t.revoked_at IS NULL
                          AND t.session_expires_at > now());
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END $$;

-- Ends every session past its expiry (the login server runs this every 30 s).
CREATE OR REPLACE FUNCTION oauth_sweep()
RETURNS integer LANGUAGE sql AS $$
    SELECT oauth_end_sessions(
        ARRAY(SELECT token_id FROM oauth_tokens
               WHERE revoked_at IS NULL AND session_expires_at <= now()),
        'expired');
$$;

COMMIT;
