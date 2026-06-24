-- Per-secret human metadata for the TUI:
--   note         : short operator note (<= ~25 words), shown next to the title
--   require_2fa  : when 1, leasing this secret needs a TOTP second factor at
--                  approval time (enforced by the approval broker)
ALTER TABLE secrets ADD COLUMN note TEXT NOT NULL DEFAULT '';
ALTER TABLE secrets ADD COLUMN require_2fa INTEGER NOT NULL DEFAULT 0;
