-- 0057: HR systems (BambooHR, Workday) as directory sources for joiners, movers and leavers;
-- leavers can be offboarded (not just suspended).
ALTER TABLE directory_connections DROP CONSTRAINT directory_connections_provider_check;
ALTER TABLE directory_connections ADD CONSTRAINT directory_connections_provider_check CHECK (provider IN ('google', 'entra', 'scim', 'ldap', 'bamboohr', 'workday'));
ALTER TABLE directory_connections DROP CONSTRAINT directory_connections_deprovision_check;
ALTER TABLE directory_connections ADD CONSTRAINT directory_connections_deprovision_check CHECK (deprovision IN ('suspend', 'offboard', 'none'));
