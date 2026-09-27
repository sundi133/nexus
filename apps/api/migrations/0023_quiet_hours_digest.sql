-- 0023: quiet hours and a daily email digest (SPEC NTF-07). Critical notifications are never held.
ALTER TABLE notification_preferences
  ADD COLUMN timezone        text NOT NULL DEFAULT 'UTC',
  ADD COLUMN quiet_enabled   boolean NOT NULL DEFAULT false,
  ADD COLUMN quiet_start     text NOT NULL DEFAULT '22:00' CHECK (quiet_start ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
  ADD COLUMN quiet_end       text NOT NULL DEFAULT '07:00' CHECK (quiet_end ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
  ADD COLUMN digest_enabled  boolean NOT NULL DEFAULT false,
  ADD COLUMN digest_time     text NOT NULL DEFAULT '08:00' CHECK (digest_time ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$');

-- "held": waiting for quiet hours to end or for the digest; becomes sent/skipped when the summary goes out.
ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_status_check;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_status_check CHECK (status IN ('sent', 'failed', 'skipped', 'held'));
CREATE INDEX notification_deliveries_held ON notification_deliveries (org_id, channel) WHERE status = 'held';
