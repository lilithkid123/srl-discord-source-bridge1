CREATE TABLE IF NOT EXISTS handoffs (
  token_hash TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_handoffs_expires_at ON handoffs (expires_at);
