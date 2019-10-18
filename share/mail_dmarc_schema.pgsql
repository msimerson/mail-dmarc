-- $Id$

-- Dump of table author
-- ------------------------------------------------------------

DROP TABLE IF EXISTS author CASCADE;
CREATE TABLE author (
  id serial unique,
  org_name varchar(253) NOT NULL DEFAULT '',
  email    varchar(255) DEFAULT NULL,
  extra_contact varchar(255) DEFAULT NULL
);


-- Dump of table domain
-- ------------------------------------------------------------

DROP TABLE IF EXISTS domain CASCADE;
CREATE TABLE domain (
  id serial unique,
  domain varchar(253) NOT NULL DEFAULT '',
  UNIQUE (domain)
);


-- Dump of table report
-- ------------------------------------------------------------

DROP TABLE IF EXISTS report CASCADE;
CREATE TABLE report (
  id serial unique,
  "begin" int NOT NULL,
  "end" int NOT NULL,
  author_id int NOT NULL REFERENCES author (id) ON DELETE NO ACTION,
  rcpt_domain_id int DEFAULT NULL,
  from_domain_id int NOT NULL REFERENCES domain (id),
  uuid varchar(253) DEFAULT NULL
);


DROP TABLE IF EXISTS report_error CASCADE;
CREATE TABLE report_error (
  id serial unique,
  report_id int REFERENCES report(id) ON DELETE CASCADE,
  error varchar(255) NOT NULL DEFAULT '',
  time timestamp NOT NULL DEFAULT now()
);


-- Dump of table report_policy_published
-- ------------------------------------------------------------

DROP TABLE IF EXISTS report_policy_published CASCADE;
CREATE TABLE report_policy_published (
  id serial unique,
  report_id int NOT NULL REFERENCES report (id) ON DELETE CASCADE,
  adkim varchar(1) DEFAULT NULL,
  aspf varchar(1) DEFAULT NULL,
  p varchar(10) DEFAULT NULL,
  sp varchar(10) DEFAULT NULL,
  pct int DEFAULT NULL,
  rua varchar(255) DEFAULT NULL
);


-- Dump of table report_record
-- ------------------------------------------------------------

DROP TABLE IF EXISTS report_record CASCADE;
CREATE TABLE report_record (
  id serial unique,
  report_id int NOT NULL REFERENCES report (id) ON DELETE CASCADE,
  source_ip BYTEA NOT NULL,
  count int DEFAULT NULL,
  disposition varchar(10) NOT NULL,
  dkim varchar(4) NOT NULL DEFAULT '',
  spf varchar(4) NOT NULL DEFAULT '',
  envelope_to_did int DEFAULT NULL,
  envelope_from_did int DEFAULT NULL,
  header_from_did int NOT NULL
);


DROP TABLE IF EXISTS report_record_reason CASCADE;
CREATE TABLE report_record_reason (
  id serial unique,
  report_record_id int NOT NULL REFERENCES report_record (id) ON DELETE CASCADE,
  type varchar(24) NOT NULL,
  comment varchar(255) DEFAULT NULL
);


-- Dump of table report_record_dkim
-- ------------------------------------------------------------

DROP TABLE IF EXISTS report_record_dkim CASCADE;
CREATE TABLE report_record_dkim (
  id serial unique,
  report_record_id int NOT NULL REFERENCES report_record (id) ON DELETE CASCADE,
  domain_id int NOT NULL,
  selector varchar(253) DEFAULT NULL,
  result varchar(9) NOT NULL DEFAULT '',
  human_result varchar(64) DEFAULT NULL
);


-- Dump of table report_record_spf
-- ------------------------------------------------------------

DROP TABLE IF EXISTS report_record_spf CASCADE;
CREATE TABLE report_record_spf (
  id serial unique,
  report_record_id int NOT NULL REFERENCES report_record (id) ON DELETE CASCADE,
  domain_id int NOT NULL,
  scope varchar(5) DEFAULT NULL,
  result varchar(9) NOT NULL
);


-- Indexes
-- -----------------------------------------------------------

CREATE INDEX report_record_spf_report_record_id_idx ON  report_record_spf(report_record_id);
CREATE INDEX report_record_dkim_report_record_id_idx ON report_record_dkim(report_record_id);
CREATE INDEX report_record_report_id_idx ON report_record(report_id);
CREATE INDEX report_record_reason_report_record_id_idx ON report_record_reason(report_record_id);
CREATE INDEX report_policy_published_report_id_idx ON report_policy_published(report_id);
