-- The HA drill's stand-in for a new release's migration: backward compatible (a new nullable
-- column), as every migration must be, since the previous release keeps serving while it runs.
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS drill_note text;
