-- ============================================================================
-- Tiers 2 and 3: tenant-specific data (synthetic demo data, LAB ONLY).
--
--   psql -U postgres -d erms -f 03_tenant_data.sql      (after 02_metadata.sql)
--
-- Two tenants, each with departments, employees, user accounts, salaries,
-- bank accounts and asset owners. When each transaction commits PostgreSQL
-- sends the tenants and then the users to AM (users with their role and
-- display name, using the tenant's own API key from am_client.conf).
-- Every user starts logged out (login_status 0): user_asset_map fills at login.
--
--   tenant 1001 ACME    tenant 1002 GLOBEX
-- ============================================================================

-- Tenants (tier 2) -> sent to AM
BEGIN;
INSERT INTO tenants (tenant_id, org_code, org_name, contact_phone) VALUES
    (1001, 'ACME',   'Acme Corporation', '+1-555-0100'),
    (1002, 'GLOBEX', 'Globex Limited',   '+1-555-0200');
COMMIT;

BEGIN;
INSERT INTO departments (department_id, tenant_id, name) VALUES
    (2101, 1001, 'Human Resources'),
    (2102, 1001, 'Finance'),
    (2103, 1001, 'Engineering'),
    (2201, 1002, 'Human Resources'),
    (2202, 1002, 'Operations');

-- Employees hold the role (tier 2). The TENANT_ADMIN has no department
-- (allowed by the schema for the bootstrap admin).
INSERT INTO employees (employee_id, tenant_id, department_id, role_id,
                       first_name, last_name, date_of_birth, ssn, hire_date)
SELECT v.id, v.tenant, v.dept, r.role_id, v.first, v.last, v.dob, v.ssn, v.hired
FROM (VALUES
  (3101, 1001, NULL::bigint, 'TENANT_ADMIN',    'Tara',  'Admin',   DATE '1980-02-11', 'SYNTH-3101', DATE '2019-01-07'),
  (3102, 1001, 2101,         'HR_ADMIN',        'Hugo',  'Reyes',   DATE '1984-06-23', 'SYNTH-3102', DATE '2019-03-04'),
  (3103, 1001, 2101,         'HR_MANAGER',      'Hana',  'Kim',     DATE '1987-09-30', 'SYNTH-3103', DATE '2020-05-18'),
  (3104, 1001, 2103,         'DEPT_MANAGER',    'Dan',   'Okafor',  DATE '1982-12-01', 'SYNTH-3104', DATE '2018-11-12'),
  (3105, 1001, 2102,         'PAYROLL_OFFICER', 'Pete',  'Novak',   DATE '1990-04-14', 'SYNTH-3105', DATE '2021-02-01'),
  (3106, 1001, 2103,         'EMPLOYEE',        'Alice', 'Sharma',  DATE '1993-07-08', 'SYNTH-3106', DATE '2022-08-29'),
  (3107, 1001, 2103,         'EMPLOYEE',        'Bob',   'Lee',     DATE '1995-01-19', 'SYNTH-3107', DATE '2024-10-14'),
  (3201, 1002, NULL::bigint, 'TENANT_ADMIN',    'Gina',  'Morales', DATE '1979-03-27', 'SYNTH-3201', DATE '2020-01-06'),
  (3202, 1002, 2201,         'HR_ADMIN',        'Greg',  'Walsh',   DATE '1986-10-05', 'SYNTH-3202', DATE '2020-02-03'),
  (3203, 1002, 2202,         'EMPLOYEE',        'Carol', 'Nguyen',  DATE '1992-05-16', 'SYNTH-3203', DATE '2023-04-24')
) AS v (id, tenant, dept, role, first, last, dob, ssn, hired)
JOIN roles r ON r.role_name = v.role;
COMMIT;

-- User accounts, one per employee (tier 2) -> sent to AM.
-- Bob has not done his first login yet: PENDING_FIRST_LOGIN.
BEGIN;
INSERT INTO user_accounts (user_id, tenant_id, employee_id, username, password_hash,
                           status, must_change_password, activated_on) VALUES
    (4101, 1001, 3101, 'tara.admin',   'NOT-A-REAL-HASH', 'ACTIVE',              false, now()),
    (4102, 1001, 3102, 'hugo.reyes',   'NOT-A-REAL-HASH', 'ACTIVE',              false, now()),
    (4103, 1001, 3103, 'hana.kim',     'NOT-A-REAL-HASH', 'ACTIVE',              false, now()),
    (4104, 1001, 3104, 'dan.okafor',   'NOT-A-REAL-HASH', 'ACTIVE',              false, now()),
    (4105, 1001, 3105, 'pete.novak',   'NOT-A-REAL-HASH', 'ACTIVE',              false, now()),
    (4106, 1001, 3106, 'alice.sharma', 'NOT-A-REAL-HASH', 'ACTIVE',              false, now()),
    (4107, 1001, 3107, 'bob.lee',      'NOT-A-REAL-HASH', 'PENDING_FIRST_LOGIN', true,  NULL),
    (4201, 1002, 3201, 'gina.morales', 'NOT-A-REAL-HASH', 'ACTIVE',              false, now()),
    (4202, 1002, 3202, 'greg.walsh',   'NOT-A-REAL-HASH', 'ACTIVE',              false, now()),
    (4203, 1002, 3203, 'carol.nguyen', 'NOT-A-REAL-HASH', 'ACTIVE',              false, now());
COMMIT;

BEGIN;
-- Current salary, at most one per employee (tier 2)
INSERT INTO compensation (compensation_id, tenant_id, employee_id, base_salary) VALUES
    (5102, 1001, 3102,  98000.00),
    (5103, 1001, 3103, 105000.00),
    (5104, 1001, 3104, 112000.00),
    (5105, 1001, 3105,  87000.00),
    (5106, 1001, 3106,  76000.00),
    (5107, 1001, 3107,  64000.00),
    (5202, 1002, 3202,  91000.00),
    (5203, 1002, 3203,  71000.00);

-- Current bank account, at most one per employee (tier 2)
INSERT INTO bank_accounts (bank_account_id, tenant_id, employee_id, account_number, bank_name) VALUES
    (6105, 1001, 3105, 'SYNTH-ACCT-3105', 'First Synthetic Bank'),
    (6106, 1001, 3106, 'SYNTH-ACCT-3106', 'First Synthetic Bank'),
    (6107, 1001, 3107, 'SYNTH-ACCT-3107', 'Second Synthetic Bank'),
    (6203, 1002, 3203, 'SYNTH-ACCT-3203', 'Globex Credit Union');

-- Who owns (approves access to) each protected type, per tenant (tier 3)
INSERT INTO asset_owner_assignments (tenant_id, employee_id, type_id) VALUES
    (1001, 3102, 'A01'),     -- Hugo (HR Admin): date of birth
    (1001, 3102, 'A02'),     -- Hugo (HR Admin): SSN
    (1001, 3105, 'A03'),     -- Pete (Payroll):  salary
    (1001, 3105, 'A04'),     -- Pete (Payroll):  account number
    (1002, 3202, 'A01'),     -- Greg (HR Admin): all four in GLOBEX
    (1002, 3202, 'A02'),
    (1002, 3202, 'A03'),
    (1002, 3202, 'A04');
COMMIT;
