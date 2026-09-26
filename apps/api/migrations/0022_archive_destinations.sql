-- 0022: archive audit events to Amazon S3 / Google Cloud Storage, and stream to Microsoft Sentinel (AUD-04).
ALTER TABLE event_destinations DROP CONSTRAINT event_destinations_kind_check;
ALTER TABLE event_destinations ADD CONSTRAINT event_destinations_kind_check
  CHECK (kind IN ('webhook', 'splunk_hec', 'datadog', 's3', 'gcs', 'sentinel'));
