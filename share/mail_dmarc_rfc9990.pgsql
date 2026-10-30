-- RFC 9990 report fields. Databases created by Mail::DMARC 2.20260827 or
-- earlier lack them, so stored reports drop np, fo, testing and
-- discovery_method. Safe to re-run.
--
--   psql dmarc_report < mail_dmarc_rfc9990.pgsql

ALTER TABLE report_policy_published ADD COLUMN IF NOT EXISTS np varchar(10) DEFAULT NULL;
ALTER TABLE report_policy_published ADD COLUMN IF NOT EXISTS fo varchar(32) DEFAULT NULL;
ALTER TABLE report_policy_published ADD COLUMN IF NOT EXISTS testing char(1) DEFAULT NULL;
ALTER TABLE report_policy_published ADD COLUMN IF NOT EXISTS discovery_method varchar(8) DEFAULT NULL;
