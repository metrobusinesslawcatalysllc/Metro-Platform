-- Control-plane D1 schema.
-- This database stores identities, tenant routing metadata, branches, and
-- memberships only. Do not put banking or brokerage records in this database.

CREATE TABLE platform_operators (
  user_id TEXT PRIMARY KEY NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('SUPER_MASTER', 'ADMIN_OWNER')),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX platform_operators_single_super_master
  ON platform_operators (role)
  WHERE role = 'SUPER_MASTER';

CREATE TABLE admin_tenants (
  tenant_id TEXT PRIMARY KEY NOT NULL,
  tenant_name TEXT NOT NULL CHECK (length(trim(tenant_name)) BETWEEN 1 AND 120),
  admin_owner_user_id TEXT NOT NULL UNIQUE,
  provisioned_by_super_master_id TEXT NOT NULL,
  d1_database_id TEXT NOT NULL UNIQUE,
  d1_database_name TEXT NOT NULL UNIQUE,
  worker_script_name TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (admin_owner_user_id)
    REFERENCES platform_operators (user_id) ON DELETE RESTRICT,
  FOREIGN KEY (provisioned_by_super_master_id)
    REFERENCES platform_operators (user_id) ON DELETE RESTRICT
);

CREATE INDEX admin_tenants_provisioner_idx
  ON admin_tenants (provisioned_by_super_master_id, created_at DESC);

CREATE TRIGGER admin_tenants_validate_owners_insert
BEFORE INSERT ON admin_tenants
WHEN NOT EXISTS (
    SELECT 1 FROM platform_operators
    WHERE user_id = NEW.admin_owner_user_id
      AND role = 'ADMIN_OWNER'
      AND is_active = 1
  )
  OR NOT EXISTS (
    SELECT 1 FROM platform_operators
    WHERE user_id = NEW.provisioned_by_super_master_id
      AND role = 'SUPER_MASTER'
      AND is_active = 1
  )
BEGIN
  SELECT RAISE(ABORT, 'tenant requires an active Admin Owner and Super Master');
END;

CREATE TRIGGER admin_tenants_ownership_immutable
BEFORE UPDATE OF tenant_id, admin_owner_user_id, provisioned_by_super_master_id,
  d1_database_id, d1_database_name, worker_script_name ON admin_tenants
WHEN NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.admin_owner_user_id IS NOT OLD.admin_owner_user_id
  OR NEW.provisioned_by_super_master_id IS NOT OLD.provisioned_by_super_master_id
  OR NEW.d1_database_id IS NOT OLD.d1_database_id
  OR NEW.d1_database_name IS NOT OLD.d1_database_name
  OR NEW.worker_script_name IS NOT OLD.worker_script_name
BEGIN
  SELECT RAISE(ABORT, 'tenant owner and infrastructure identity are immutable');
END;

CREATE TABLE tenant_branches (
  tenant_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  branch_name TEXT NOT NULL CHECK (length(trim(branch_name)) BETWEEN 1 AND 120),
  status TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'INACTIVE')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (tenant_id, branch_id),
  FOREIGN KEY (tenant_id)
    REFERENCES admin_tenants (tenant_id) ON DELETE RESTRICT
);

CREATE INDEX tenant_branches_tenant_status_idx
  ON tenant_branches (tenant_id, status, branch_name);

CREATE TABLE tenant_memberships (
  user_id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('SUBADMIN', 'MANAGER', 'CLIENT')),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id, branch_id)
    REFERENCES tenant_branches (tenant_id, branch_id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id)
    REFERENCES admin_tenants (tenant_id) ON DELETE RESTRICT
);

CREATE INDEX tenant_memberships_scope_idx
  ON tenant_memberships (user_id, tenant_id, branch_id, role, is_active);
CREATE INDEX tenant_memberships_tenant_branch_idx
  ON tenant_memberships (tenant_id, branch_id, role, is_active);

CREATE TRIGGER tenant_memberships_validate_insert
BEFORE INSERT ON tenant_memberships
WHEN EXISTS (
  SELECT 1 FROM platform_operators WHERE user_id = NEW.user_id
)
  OR NOT EXISTS (
    SELECT 1 FROM admin_tenants
    WHERE tenant_id = NEW.tenant_id AND status = 'ACTIVE'
  )
  OR NOT EXISTS (
    SELECT 1 FROM tenant_branches
    WHERE tenant_id = NEW.tenant_id
      AND branch_id = NEW.branch_id
      AND status = 'ACTIVE'
  )
BEGIN
  SELECT RAISE(ABORT, 'membership must be a non-operator in an active tenant branch');
END;

CREATE TRIGGER tenant_memberships_validate_update
BEFORE UPDATE OF user_id, tenant_id, branch_id, role, is_active ON tenant_memberships
WHEN EXISTS (
  SELECT 1 FROM platform_operators WHERE user_id = NEW.user_id
)
  OR NOT EXISTS (
    SELECT 1 FROM admin_tenants
    WHERE tenant_id = NEW.tenant_id AND status = 'ACTIVE'
  )
  OR NOT EXISTS (
    SELECT 1 FROM tenant_branches
    WHERE tenant_id = NEW.tenant_id
      AND branch_id = NEW.branch_id
      AND status = 'ACTIVE'
  )
BEGIN
  SELECT RAISE(ABORT, 'membership must be a non-operator in an active tenant branch');
END;
