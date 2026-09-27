-- 0006: a SAML service provider (entity ID) can be registered once per organization;
-- incoming AuthnRequests are matched to apps by it.
CREATE UNIQUE INDEX applications_saml_entity ON applications (org_id, (config->>'entity_id')) WHERE protocol = 'saml';
