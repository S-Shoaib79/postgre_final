-- ============================================================================
-- Tier 1: application-wide metadata, defined ONE time (was role_asset_data.sql)
--
--   psql -U postgres -d erms -f 02_metadata.sql
--
-- Safe to re-run: rows are matched by name / id and updated. When this
-- script's transaction commits, PostgreSQL sends the whole matrix to AM:
-- each role with the protected type ids it may use (permissions stay here).
-- ============================================================================
BEGIN;

-- The six fixed roles (Requirements Rev 2.0, USR-03)
INSERT INTO roles (role_name, description) VALUES
    ('TENANT_ADMIN',    'Restricted tenant bootstrap and approved recovery'),
    ('HR_ADMIN',        'HR administration'),
    ('HR_MANAGER',      'HR management'),
    ('DEPT_MANAGER',    'Department management'),
    ('PAYROLL_OFFICER', 'Payroll processing'),
    ('EMPLOYEE',        'Employee self-service')
ON CONFLICT (role_name) DO UPDATE SET description = EXCLUDED.description;

-- The four protected types = the assets (Requirements section 11)
INSERT INTO protected_type_catalog
    (type_id, type_name, table_name, column_name, java_class, description)
VALUES
    ('A01', 'DateOfBirth',   'employees',     'date_of_birth',  'DateOfBirth',   'Protected employee date of birth'),
    ('A02', 'SSN',           'employees',     'ssn',            'SSN',           'Protected employee SSN'),
    ('A03', 'Salary',        'compensation',  'base_salary',    'Salary',        'Protected base salary'),
    ('A04', 'AccountNumber', 'bank_accounts', 'account_number', 'AccountNumber', 'Protected bank account number')
ON CONFLICT (type_id) DO UPDATE
SET type_name = EXCLUDED.type_name, table_name = EXCLUDED.table_name,
    column_name = EXCLUDED.column_name, java_class = EXCLUDED.java_class,
    description = EXCLUDED.description;

-- The matrix: Requirements section 10 "Protected column" table.
-- R = select, I = insert, U = update; DELETE is never granted.
-- TENANT_ADMIN has no protected-field permission. "limited" / "own" scopes
-- are row rules (RLS), not part of this matrix.
INSERT INTO role_protected_type_permissions
    (role_id, type_id, can_select, can_insert, can_update, can_delete)
SELECT r.role_id, g.type_id, g.s, g.i, g.u, false
FROM (VALUES
  --  role               type   S      I      U
  ('HR_ADMIN',         'A01', true,  true,  true ),   -- DoB: RIU
  ('HR_MANAGER',       'A01', true,  false, false),   -- DoB: R
  ('DEPT_MANAGER',     'A01', true,  false, false),   -- DoB: R limited
  ('EMPLOYEE',         'A01', true,  false, false),   -- DoB: R own
  ('HR_ADMIN',         'A02', true,  true,  true ),   -- SSN: RIU
  ('HR_MANAGER',       'A02', true,  false, false),   -- SSN: R
  ('PAYROLL_OFFICER',  'A02', true,  false, false),   -- SSN: R
  ('HR_MANAGER',       'A03', true,  false, false),   -- Salary: R tenant
  ('PAYROLL_OFFICER',  'A03', true,  true,  true ),   -- Salary: RIU
  ('EMPLOYEE',         'A03', true,  false, false),   -- Salary: R own
  ('PAYROLL_OFFICER',  'A04', true,  true,  true ),   -- Account: RIU
  ('EMPLOYEE',         'A04', true,  true,  true )    -- Account: RIU own
) AS g (role_name, type_id, s, i, u)
JOIN roles r ON r.role_name = g.role_name
ON CONFLICT (role_id, type_id) DO UPDATE
SET can_select = EXCLUDED.can_select, can_insert = EXCLUDED.can_insert,
    can_update = EXCLUDED.can_update, can_delete = EXCLUDED.can_delete;

COMMIT;
