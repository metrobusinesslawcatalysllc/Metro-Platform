-- Apply once to each tenant's dedicated D1 database.
-- tenant_metadata is seeded by the trusted provisioning workflows. Records are
-- physically isolated by the tenant-specific Worker D1 binding.
-- Store money in integer minor units, never SQLite REAL.

CREATE TABLE tenant_metadata (
  tenant_id TEXT PRIMARY KEY NOT NULL,
  elevated_review_threshold_minor INTEGER NOT NULL DEFAULT 10000
    CHECK (elevated_review_threshold_minor > 0),
  elevated_review_currency TEXT NOT NULL DEFAULT 'USD'
    CHECK (elevated_review_currency GLOB '[A-Z][A-Z][A-Z]'),
  risk_limit_minor INTEGER NOT NULL DEFAULT 100000
    CHECK (risk_limit_minor > 0),
  fee_basis_points INTEGER NOT NULL DEFAULT 250
    CHECK (fee_basis_points BETWEEN 0 AND 10000),
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE banking_ledgers (
  ledger_id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  branch_id TEXT,
  ledger_name TEXT NOT NULL CHECK (length(trim(ledger_name)) BETWEEN 1 AND 120),
  ledger_type TEXT NOT NULL
    CHECK (ledger_type IN ('CHECKING', 'SAVINGS', 'ESCROW', 'SETTLEMENT', 'TREASURY')),
  currency TEXT NOT NULL CHECK (currency GLOB '[A-Z][A-Z][A-Z]'),
  status TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'FROZEN', 'CLOSED')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE (tenant_id, ledger_id),
  FOREIGN KEY (tenant_id) REFERENCES tenant_metadata (tenant_id) ON DELETE RESTRICT
);

CREATE INDEX banking_ledgers_tenant_branch_idx
  ON banking_ledgers (tenant_id, branch_id, status, created_at DESC);

CREATE TABLE banking_transactions (
  transaction_id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING', 'POSTED', 'VOIDED')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE (tenant_id, transaction_id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id) REFERENCES tenant_metadata (tenant_id) ON DELETE RESTRICT
);

CREATE INDEX banking_transactions_tenant_created_idx
  ON banking_transactions (tenant_id, created_at DESC);

CREATE TABLE banking_ledger_entries (
  entry_id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  transaction_id TEXT NOT NULL,
  ledger_id TEXT NOT NULL,
  entry_type TEXT NOT NULL CHECK (entry_type IN ('DEBIT', 'CREDIT')),
  amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
  currency TEXT NOT NULL CHECK (currency GLOB '[A-Z][A-Z][A-Z]'),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (tenant_id, transaction_id)
    REFERENCES banking_transactions (tenant_id, transaction_id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, ledger_id)
    REFERENCES banking_ledgers (tenant_id, ledger_id) ON DELETE RESTRICT
);

CREATE INDEX banking_ledger_entries_tenant_ledger_idx
  ON banking_ledger_entries (tenant_id, ledger_id, created_at DESC);
CREATE INDEX banking_ledger_entries_tenant_transaction_idx
  ON banking_ledger_entries (tenant_id, transaction_id);

CREATE TRIGGER banking_entries_validate_insert
BEFORE INSERT ON banking_ledger_entries
WHEN NOT EXISTS (
    SELECT 1 FROM banking_ledgers
    WHERE tenant_id = NEW.tenant_id
      AND ledger_id = NEW.ledger_id
      AND currency = NEW.currency
  )
  OR NOT EXISTS (
    SELECT 1 FROM banking_transactions
    WHERE tenant_id = NEW.tenant_id
      AND transaction_id = NEW.transaction_id
      AND status = 'PENDING'
  )
BEGIN
  SELECT RAISE(ABORT, 'entry must match a pending transaction and ledger currency');
END;

CREATE TRIGGER banking_entries_validate_update
BEFORE UPDATE OF tenant_id, transaction_id, ledger_id, currency ON banking_ledger_entries
WHEN NOT EXISTS (
    SELECT 1 FROM banking_ledgers
    WHERE tenant_id = NEW.tenant_id
      AND ledger_id = NEW.ledger_id
      AND currency = NEW.currency
  )
  OR NOT EXISTS (
    SELECT 1 FROM banking_transactions
    WHERE tenant_id = NEW.tenant_id
      AND transaction_id = NEW.transaction_id
      AND status = 'PENDING'
  )
BEGIN
  SELECT RAISE(ABORT, 'entry must match a pending transaction and ledger currency');
END;

CREATE TRIGGER banking_transactions_validate_insert
BEFORE INSERT ON banking_transactions
WHEN NEW.status <> 'PENDING'
BEGIN
  SELECT RAISE(ABORT, 'transactions must be created as pending');
END;

CREATE TRIGGER banking_transactions_validate_status
BEFORE UPDATE OF status ON banking_transactions
WHEN NEW.status <> OLD.status
  AND NOT (
    (OLD.status = 'PENDING' AND NEW.status IN ('POSTED', 'VOIDED'))
    OR (OLD.status = 'POSTED' AND NEW.status = 'VOIDED')
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid transaction status transition');
END;

CREATE TRIGGER banking_transactions_validate_posting
BEFORE UPDATE OF status ON banking_transactions
WHEN NEW.status = 'POSTED'
BEGIN
  SELECT CASE
    WHEN OLD.status <> 'PENDING'
      THEN RAISE(ABORT, 'only a pending transaction can be posted')
    WHEN (
      SELECT COUNT(*)
      FROM banking_ledger_entries
      WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
    ) < 2
      THEN RAISE(ABORT, 'a posted transaction requires at least two ledger entries')
    WHEN EXISTS (
      SELECT currency
      FROM banking_ledger_entries
      WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
      GROUP BY currency
      HAVING SUM(
        CASE entry_type WHEN 'DEBIT' THEN amount_minor ELSE -amount_minor END
      ) <> 0
    )
      THEN RAISE(ABORT, 'ledger entries must balance for each currency')
  END;
END;

CREATE TRIGGER banking_transactions_posted_immutable
BEFORE UPDATE OF transaction_id, tenant_id, idempotency_key, description, created_at
ON banking_transactions
WHEN OLD.status <> 'PENDING'
  AND (
    NEW.transaction_id IS NOT OLD.transaction_id
    OR NEW.tenant_id IS NOT OLD.tenant_id
    OR NEW.idempotency_key IS NOT OLD.idempotency_key
    OR NEW.description IS NOT OLD.description
    OR NEW.created_at IS NOT OLD.created_at
  )
BEGIN
  SELECT RAISE(ABORT, 'non-pending transaction fields are immutable');
END;

CREATE TRIGGER banking_entries_posted_immutable_update
BEFORE UPDATE ON banking_ledger_entries
WHEN EXISTS (
  SELECT 1 FROM banking_transactions
  WHERE tenant_id = OLD.tenant_id
    AND transaction_id = OLD.transaction_id
    AND status <> 'PENDING'
)
BEGIN
  SELECT RAISE(ABORT, 'entries of non-pending transactions are immutable');
END;

CREATE TRIGGER banking_entries_posted_immutable_delete
BEFORE DELETE ON banking_ledger_entries
WHEN EXISTS (
  SELECT 1 FROM banking_transactions
  WHERE tenant_id = OLD.tenant_id
    AND transaction_id = OLD.transaction_id
    AND status <> 'PENDING'
)
BEGIN
  SELECT RAISE(ABORT, 'entries of non-pending transactions cannot be deleted');
END;

CREATE TABLE deposit_routes (
  route_id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  ledger_id TEXT NOT NULL,
  asset TEXT NOT NULL CHECK (length(trim(asset)) BETWEEN 2 AND 16),
  network TEXT NOT NULL CHECK (length(trim(network)) BETWEEN 2 AND 32),
  deposit_address TEXT NOT NULL
    CHECK (length(trim(deposit_address)) BETWEEN 8 AND 256),
  status TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'INACTIVE')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE (tenant_id, route_id),
  UNIQUE (tenant_id, asset, network, deposit_address),
  FOREIGN KEY (tenant_id, ledger_id)
    REFERENCES banking_ledgers (tenant_id, ledger_id) ON DELETE RESTRICT
);

CREATE INDEX deposit_routes_tenant_active_idx
  ON deposit_routes (tenant_id, status, asset, network);

CREATE TABLE banking_account_access (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  ledger_id TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (tenant_id, user_id, ledger_id),
  FOREIGN KEY (tenant_id, ledger_id)
    REFERENCES banking_ledgers (tenant_id, ledger_id) ON DELETE RESTRICT
);

CREATE INDEX banking_account_access_user_idx
  ON banking_account_access (tenant_id, user_id, ledger_id);

CREATE TABLE brokerage_accounts (
  brokerage_account_id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  branch_id TEXT,
  provider TEXT NOT NULL CHECK (length(trim(provider)) BETWEEN 1 AND 64),
  external_account_ref TEXT NOT NULL
    CHECK (length(trim(external_account_ref)) BETWEEN 1 AND 128),
  currency TEXT NOT NULL CHECK (currency GLOB '[A-Z][A-Z][A-Z]'),
  leverage_tier INTEGER NOT NULL DEFAULT 100
    CHECK (leverage_tier BETWEEN 1 AND 1000),
  equity_minor INTEGER NOT NULL DEFAULT 0 CHECK (equity_minor >= 0),
  margin_used_minor INTEGER NOT NULL DEFAULT 0 CHECK (margin_used_minor >= 0),
  status TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE (tenant_id, brokerage_account_id),
  UNIQUE (tenant_id, provider, external_account_ref),
  FOREIGN KEY (tenant_id) REFERENCES tenant_metadata (tenant_id) ON DELETE RESTRICT,
  CHECK (margin_used_minor <= equity_minor OR status <> 'ACTIVE')
);

CREATE INDEX brokerage_accounts_tenant_branch_idx
  ON brokerage_accounts (tenant_id, branch_id, status, created_at DESC);

CREATE TABLE brokerage_account_access (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  brokerage_account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (tenant_id, user_id, brokerage_account_id),
  FOREIGN KEY (tenant_id, brokerage_account_id)
    REFERENCES brokerage_accounts (tenant_id, brokerage_account_id) ON DELETE RESTRICT
);

CREATE INDEX brokerage_account_access_user_idx
  ON brokerage_account_access (tenant_id, user_id, brokerage_account_id);

CREATE TABLE trade_orders (
  trade_order_id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  brokerage_account_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  symbol TEXT NOT NULL CHECK (length(trim(symbol)) BETWEEN 1 AND 32),
  option_type TEXT NOT NULL CHECK (option_type IN ('CALL', 'PUT')),
  stake_minor INTEGER NOT NULL CHECK (stake_minor > 0),
  payout_rate_bps INTEGER NOT NULL CHECK (payout_rate_bps BETWEEN 0 AND 1000000),
  opened_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL CHECK (expires_at > opened_at),
  status TEXT NOT NULL DEFAULT 'OPEN'
    CHECK (status IN ('OPEN', 'WON', 'LOST', 'VOID', 'CANCELLED')),
  settlement_price_micros INTEGER,
  payout_minor INTEGER NOT NULL DEFAULT 0 CHECK (payout_minor >= 0),
  settled_at INTEGER,
  UNIQUE (tenant_id, trade_order_id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, brokerage_account_id)
    REFERENCES brokerage_accounts (tenant_id, brokerage_account_id) ON DELETE RESTRICT,
  CHECK (
    (status = 'OPEN'
      AND settlement_price_micros IS NULL
      AND payout_minor = 0
      AND settled_at IS NULL)
    OR (status IN ('WON', 'LOST', 'VOID')
      AND settlement_price_micros IS NOT NULL
      AND settled_at IS NOT NULL)
    OR (status = 'CANCELLED'
      AND settlement_price_micros IS NULL
      AND payout_minor = 0
      AND settled_at IS NOT NULL)
  ),
  CHECK (status <> 'LOST' OR payout_minor = 0),
  CHECK (status <> 'WON' OR payout_minor > 0)
);

CREATE INDEX trade_orders_tenant_status_created_idx
  ON trade_orders (tenant_id, status, opened_at DESC);
CREATE INDEX trade_orders_tenant_account_created_idx
  ON trade_orders (tenant_id, brokerage_account_id, opened_at DESC);

CREATE TRIGGER trade_orders_terms_immutable
BEFORE UPDATE OF tenant_id, brokerage_account_id, idempotency_key, symbol,
  option_type, stake_minor, payout_rate_bps, opened_at, expires_at ON trade_orders
WHEN NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.brokerage_account_id IS NOT OLD.brokerage_account_id
  OR NEW.idempotency_key IS NOT OLD.idempotency_key
  OR NEW.symbol IS NOT OLD.symbol
  OR NEW.option_type IS NOT OLD.option_type
  OR NEW.stake_minor IS NOT OLD.stake_minor
  OR NEW.payout_rate_bps IS NOT OLD.payout_rate_bps
  OR NEW.opened_at IS NOT OLD.opened_at
  OR NEW.expires_at IS NOT OLD.expires_at
BEGIN
  SELECT RAISE(ABORT, 'trade terms are immutable');
END;

CREATE TRIGGER trade_orders_status_transition
BEFORE UPDATE OF status ON trade_orders
WHEN NEW.status <> OLD.status
  AND NOT (OLD.status = 'OPEN' AND NEW.status IN ('WON', 'LOST', 'VOID', 'CANCELLED'))
BEGIN
  SELECT RAISE(ABORT, 'invalid trade status transition');
END;

CREATE TRIGGER trade_orders_settlement_immutable
BEFORE UPDATE OF settlement_price_micros, payout_minor, settled_at ON trade_orders
WHEN OLD.status <> 'OPEN'
  AND (
    NEW.settlement_price_micros IS NOT OLD.settlement_price_micros
    OR NEW.payout_minor IS NOT OLD.payout_minor
    OR NEW.settled_at IS NOT OLD.settled_at
  )
BEGIN
  SELECT RAISE(ABORT, 'trade settlement is immutable');
END;

CREATE TABLE management_queue (
  queue_id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  branch_id TEXT,
  requester_user_id TEXT NOT NULL,
  request_type TEXT NOT NULL
    CHECK (request_type IN ('BANKING_TRANSFER', 'BROKERAGE_ORDER', 'BINARY_CONTRACT')),
  review_level TEXT NOT NULL CHECK (review_level IN ('STANDARD', 'ELEVATED')),
  status TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING', 'APPROVED', 'DECLINED')),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  requested_at INTEGER NOT NULL DEFAULT (unixepoch()),
  reviewed_by TEXT,
  reviewed_at INTEGER,
  review_note TEXT CHECK (review_note IS NULL OR length(review_note) <= 1000),
  UNIQUE (tenant_id, requester_user_id, idempotency_key),
  FOREIGN KEY (tenant_id) REFERENCES tenant_metadata (tenant_id) ON DELETE RESTRICT,
  CHECK (
    (status = 'PENDING' AND reviewed_by IS NULL AND reviewed_at IS NULL)
    OR (
      status IN ('APPROVED', 'DECLINED')
      AND reviewed_by IS NOT NULL
      AND reviewed_at IS NOT NULL
      AND reviewed_by <> requester_user_id
    )
  )
);

CREATE INDEX management_queue_tenant_status_created_idx
  ON management_queue (tenant_id, status, requested_at DESC, queue_id);
CREATE INDEX management_queue_tenant_branch_status_idx
  ON management_queue (tenant_id, branch_id, status, requested_at DESC, queue_id);

CREATE TRIGGER management_queue_request_immutable
BEFORE UPDATE OF queue_id, tenant_id, branch_id, requester_user_id, request_type,
  review_level, idempotency_key, payload_json, requested_at ON management_queue
WHEN NEW.queue_id IS NOT OLD.queue_id
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.branch_id IS NOT OLD.branch_id
  OR NEW.requester_user_id IS NOT OLD.requester_user_id
  OR NEW.request_type IS NOT OLD.request_type
  OR NEW.review_level IS NOT OLD.review_level
  OR NEW.idempotency_key IS NOT OLD.idempotency_key
  OR NEW.payload_json IS NOT OLD.payload_json
  OR NEW.requested_at IS NOT OLD.requested_at
BEGIN
  SELECT RAISE(ABORT, 'management requests are immutable');
END;

CREATE TRIGGER management_queue_review_transition
BEFORE UPDATE OF status ON management_queue
WHEN NEW.status <> OLD.status
  AND NOT (OLD.status = 'PENDING' AND NEW.status IN ('APPROVED', 'DECLINED'))
BEGIN
  SELECT RAISE(ABORT, 'invalid management review transition');
END;

CREATE TRIGGER management_queue_no_delete
BEFORE DELETE ON management_queue
BEGIN
  SELECT RAISE(ABORT, 'management review records cannot be deleted');
END;
