-- ============================================================================
-- Merged schema: the client's Secure-ERMS schema (their schema diagram), plus the
-- two things our runtime security flow needs.
--
--   psql -U postgres -d erms -f 01_schema.sql        (fresh database)
--
-- Tier 1  APPLICATION-WIDE METADATA (defined once, shared by all tenants)
--   roles                            was app_role
--   protected_type_catalog           was app_asset  (an asset = a type A01..A04)
--   role_protected_type_permissions  was role_asset_map
-- Tier 2  TENANT-SPECIFIC BUSINESS DATA
--   tenants                          was tenant
--   departments                      new
--   employees                        new (holds the user's role)
--   user_accounts                    was tenant_user (+ login_status, below)
--   compensation, bank_accounts      new
-- Tier 3  TENANT-SPECIFIC SECURITY DATA
--   asset_owner_assignments          new
--   user_asset_map                   ours: the AM keys of a logged-in user
--
-- The PostgreSQL hooks (execMain.c, nodeModifyTable.c) find these tables by
-- name, in a schema that has user_asset_map.
-- ============================================================================

-- The client's schema, unchanged: 10 tables, roles and protected types seeded
\ir ../secure_erms/pack/baseline_schema.sql

BEGIN;

-- Login state for the hooks. user_accounts.status is the account's state
-- (PENDING_FIRST_LOGIN / ACTIVE / DISABLED) and stays as the client defined
-- it; login_status is the old tenant_user.status: 1 = logged in, 0 = not.
--   UPDATE user_accounts SET login_status = 1 ...   login  (keys fetched)
--   UPDATE user_accounts SET login_status = 0 ...   logout (keys removed)
ALTER TABLE user_accounts
  ADD COLUMN login_status smallint NOT NULL DEFAULT 0
    CONSTRAINT ck_user_account_login_status CHECK (login_status IN (0, 1));

-- Tenant-consistent key for user_asset_map's foreign key (the schema's rule:
-- tenant-owned FKs use (tenant_id, referenced_id)).
ALTER TABLE user_accounts
  ADD CONSTRAINT uq_user_account_tenant_pair UNIQUE (tenant_id, user_id);

-- Tier 3, ours. One row per protected type the user's role may use, filled
-- at login; asset_key is the 32-byte key AM returns for that type, base64
-- (44 characters). It exists only while the user is logged in.
CREATE TABLE user_asset_map (
    tenant_id  BIGINT      NOT NULL,
    user_id    BIGINT      NOT NULL,
    type_id    VARCHAR(10) NOT NULL REFERENCES protected_type_catalog (type_id),
    asset_key  CHAR(44)
        CONSTRAINT ck_user_asset_key_32_bytes CHECK (asset_key ~ '^[A-Za-z0-9+/]{43}=$'),
    CONSTRAINT pk_user_asset_map PRIMARY KEY (user_id, type_id),
    CONSTRAINT fk_user_asset_same_tenant_user
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES user_accounts (tenant_id, user_id) ON DELETE CASCADE
);
CREATE INDEX ix_user_asset_map_tenant ON user_asset_map (tenant_id);

-- The protected columns (protected_type_catalog: A01-A04) hold ciphertext.
-- When AM pushes a user's asset keys (am_keys), each value of that tenant is
-- encrypted with the tenant's key for its type: AES-256-CBC, random 16-byte
-- IV, stored as base64(IV || ciphertext). Values of up to 31 bytes fit in
-- VARCHAR(64). The salary check cannot apply to ciphertext.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
ALTER TABLE compensation DROP CONSTRAINT ck_compensation_nonnegative;
ALTER TABLE employees
  ALTER COLUMN date_of_birth TYPE VARCHAR(64) USING to_char(date_of_birth, 'YYYY-MM-DD'),
  ALTER COLUMN ssn           TYPE VARCHAR(64);
ALTER TABLE compensation
  ALTER COLUMN base_salary   TYPE VARCHAR(64) USING base_salary::text;
ALTER TABLE bank_accounts
  ALTER COLUMN account_number TYPE VARCHAR(64);

COMMIT;
