CREATE TABLE passkey(
  id TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  username TEXT NOT NULL,
  counter INTEGER NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')),
  created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime'))
);

CREATE TRIGGER passkey_updated_at AFTER UPDATE ON passkey
BEGIN
  UPDATE passkey SET updated_at = DATETIME('now', 'localtime') WHERE rowid == NEW.rowid;
END;
