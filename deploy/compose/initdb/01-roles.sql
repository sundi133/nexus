-- nexus_owner owns the schema and runs migrations (bypasses RLS as table owner).
-- nexus_app is what the API uses for tenant-scoped work: RLS is always enforced for it.
CREATE ROLE nexus_app LOGIN PASSWORD 'nexus_app';
GRANT CONNECT ON DATABASE nexus TO nexus_app;
CREATE DATABASE nexus_test OWNER nexus_owner;
GRANT CONNECT ON DATABASE nexus_test TO nexus_app;
