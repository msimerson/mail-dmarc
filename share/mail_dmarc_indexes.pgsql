-- Indexes the aggregate views in dmarc_httpd need. PostgreSQL does not index
-- foreign keys automatically. Safe to re-run.
--
--   psql dmarc_report < mail_dmarc_indexes.pgsql

CREATE INDEX IF NOT EXISTS report_begin_idx ON report("begin");
CREATE INDEX IF NOT EXISTS report_author_id_idx ON report(author_id);
CREATE INDEX IF NOT EXISTS report_from_domain_id_idx ON report(from_domain_id);
CREATE INDEX IF NOT EXISTS report_error_report_id_idx ON report_error(report_id);
CREATE INDEX IF NOT EXISTS report_record_source_ip_idx ON report_record(source_ip);
