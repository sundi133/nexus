-- 0070: iPhone and iPad in Nexus Apple MDM. The same protocol as Macs; what differs is which
-- commands and profile payloads apply, and that phones have no Nexus agent to say whose they are.
ALTER TABLE apple_mdm_devices ADD COLUMN platform text NOT NULL DEFAULT 'macos' CHECK (platform IN ('macos', 'ios', 'ipados', 'other'));
ALTER TABLE apple_mdm_devices ADD COLUMN assigned_user_id uuid REFERENCES users (id) ON DELETE SET NULL; -- whose phone (Macs: their agent's user)
ALTER TABLE apple_mdm_devices ADD COLUMN lost_mode boolean NOT NULL DEFAULT false;
UPDATE apple_mdm_devices SET platform = CASE
  WHEN info->>'ProductName' LIKE 'iPhone%' OR info->>'ProductName' LIKE 'iPod%' THEN 'ios'
  WHEN info->>'ProductName' LIKE 'iPad%' THEN 'ipados'
  ELSE 'macos' END;

-- Which platforms a profile is for; existing profiles were made for Macs.
ALTER TABLE apple_mdm_profiles ADD COLUMN platforms text[] NOT NULL DEFAULT '{macos}';
