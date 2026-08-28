-- Indexes required by the aggregate report views in dmarc_httpd.
--
-- PostgreSQL does not index foreign keys automatically, so databases created
-- before Mail::DMARC 2.2 are missing indexes that every windowed aggregation
-- needs. Safe to re-run: every statement is IF NOT EXISTS.
--
--   psql dmarc_report < mail_dmarc_indexes.pgsql

CREATE INDEX IF NOT EXISTS report_begin_idx ON report("begin");
CREATE INDEX IF NOT EXISTS report_author_id_idx ON report(author_id);
CREATE INDEX IF NOT EXISTS report_from_domain_id_idx ON report(from_domain_id);
CREATE INDEX IF NOT EXISTS report_error_report_id_idx ON report_error(report_id);
CREATE INDEX IF NOT EXISTS report_record_source_ip_idx ON report_record(source_ip);
