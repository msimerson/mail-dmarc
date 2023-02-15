### 1.20230215

- Fix error when logging a report which was skipped for size

### 1.20211209

- Properly delete sent reports when the database does not support cascade

### 1.20210927

- Fix reporting for selectors whose name evaluates to false
- Use maybestarttls for opportunistic encryption when sending reports using Email::Sender v2.0 or greater
- Remove dead domain dmarc-qa.com from tests
- Print full syntax guide with "--help" option (Jeremiah Morris)

### 1.20210427

- Fix report sending issues with SSL/TLS

### 1.20210220

- Fix db connection cache
- use Email::Sender for report sending

### 1.20200214

- move HTTP::Tiny into deps (used for PSL updates)

### 1.20200116

- skip HTTP tests when optional JSON not installed #171

### 1.20200114

- skip HTTP tests when optional deps not installed #171
- update PSL
- auto update PSL as part of release

### 1.20200113

- lazy load Net::SMTPS #168

### 1.20200108

- NEW FEATURE: Postgres support #150
- removed dist::zilla
- additional tests enabled
- html UI: use https URLS everywhere
- SPF: don't warn when scope is missing from reports
- receive: permit other MIME types that have xml.gz filename
- DKIM: when message has no result, add "none"
- sqlite: add default current_timestamp
- bin/install_deps.pl: apt improvements

### 1.20191004

- updated PSL
- update jQuery, jQuery grid
- empty ENV FROM when missing #144

### 1.20190831

- improve aggregate report docs #142
- added dmarc_whitelist hosts #119

### 1.20190308

- Lower memory usage when sending reports

### 1.20181001

- Check author when saving a new report record
- Fix bug in RUA filtering when recipient had a size filter
- Fix TLS fails for report sending to certain domains
- Fix report sending loop problem

### 1.20180125

- Allow domains listed in the public suffix list to align.

### 1.20170911

- STARTTLS workaround for Net::SMTPS issue.

### 1.20170906

- Ignore the case of tag keys when parsing DMARC records

### 1.20170222

- Ensure entities in XML agg reports are properly escaped #104
- geoip v6 support and field selection #103
- use a larger integer type for report_record.count #102
- improved apt package lookups in install_deps.pl #98

### 1.20160612

- fix aggregrate schema test #96
- Do not reject NXDOMAIN as per rfc #94
- added none result for no policy #93
- avoid deadlock with some invalid rua data #92
- avoid loop when sending reports via http #92

### 1.20150908

- Optionally log sending of reports to syslog

### 1.20150527

- check for an updated PSL file and load if necessary
- handle domains with missing rua/ruf
- add timeout to sending script

### 1.20150317

- squash subdomains w/o DMARC records into parent report (#59)
- add batch reporting (suppress throttling until...)
- align reports with hour/UTC day
- swap git contributors plugin

### 1.20150310

- lower case domain names at entry points (resolves #53)
- tolerate substitution of = with : in DMARC DNS rec

### 1.20150228

- fix the policy_evaluated fields in outbound reports
- accommodate a common DMARC error substiting = with :
- initialized config file first (was non-deterministic)
- tolerate missing SPF auth type scope

### 1.20150222

- remove ./mail-dmarc.ini (sample in share/mail-dmarc.ini)
- load PSL before dmarc_httpd forks, so we only load it once
- quieter report sending output unless --verbose

### 1.20150211

- optionally DKIM sign sent reports
- warn when DMARC record format is invalid
- accept callbacks (lazy eval) for SPF & DKIM results
- make the report record building consistent for eval and reporting
- rewrite DKIM result invalid -> temperror
- capture test warnings, so 'make test' is prettier

### 1.20150123

- enable lazy evaluation of SPF & DKIM (Ricardo Signes)
- check ShareDir for mail-dmarc.ini, if not in a standard location
- map DKIM status=invalid to status->temperror
- add config arg to dmarc_update_public_suffix_list (Ricardo Signes)
- Send only a single cc email (Marc Bradshaw)
- DMARC: update docs to show SPF one-shot syntax
- PurePerl: one shot accepts a Mail::DKIM::Verifier
- trap errors thrown by is_dkim_aligned
- INSTALL: added 'install mail-dmarc.ini' step
- Show "new record" output only in verbose mode. (Marc Bradshaw)
- require DBIx::Simple 1.35 (was any)

### 1.20141230

- Add script to update the public suffix list file (Marc Bradshaw)

### 1.20141206

- Delete reports with no valid rua (Marc Bradshaw)
- Ignore DomainKeys signatures (Marc Bradshaw)
- allow configurable delay between sending emails (Marc Bradshaw)
- permit absolute paths for public suffix list file location (Marc Bradshaw)
- fix lookup for *.foo entries (Marc Bradshaw)

### 1.20141119

- added auto_save option for validation reports
- updated bin/install_deps.pl

### 1.20141030

- percent policy logic wasn't being applied correctly
- fix for reasons not stored in SQL

### 1.20140711

- Store/SQL: use full sql name in WHERE clause
- DMARC/HTTP: added error handling and tests
- removed excess comma in mail_dmarc_schema.mysql
- added quotes around ($commit || ''), just in case
- try IMAP fetch without SORT if no results, for IMAP servers like Gmail that don't support SORT
- warn but still pass test if DNS query fails

### 1.20140623

- updated tests to accomodate the cached PSL

### 1.20140622

- load PSL into hash to speed subsequent lookups (esp for daemon)
- uncommented Net::Server in Prereqs/Recommended section
- added INSTALL
- updated dmarc_httpd description to note validation feature
- updated public_suffix_list

### 1.20140210

- NEW FEATURE: added HTTP validation service (see dmarc_httpd)
- install_deps: install optional prereqs by default
- added Best Current Practices link on main page
- minor tweaks to Pod (Ricardo Signes)
- PurePerl: added comments about Sender header when message has multiple-address format used in the From header
- updated public_suffix_list

### 1.20130906

- handle errors encountered when reporting address is illegal
- delete reports that return a SMTP 5XX code for the recipient
- delete reports after encountering 12 errors
- added 'too big' notices when report size exceeds limit
- updated install_deps.pl

### 1.20130625

- added a bunch of tests from http://dmarc-qa.com
- URI: supress undef error if URI scheme not defined
- policy->parse: properly parse records with unnecessary trailing ;
- reporting is 'external' based on Org Domain (was email domain)

### 1.20130616

- combined update/replace SQL methods
- dmarc_view_reports: fix duplicated variable name

### 1.20130615

- bug fixes and purge unused classes

### 1.20130614

- Added whitelist feature
- SMTP: remove Subject: Report-ID <braces>
- SMTP: more types of SMTP errors are stored and reported
- dmarc_send_reports: added verbose option
- dmarc_view_reports: fix for searches with MySQL backend

### 1.20130612

-  dmarc_view_reports: improve gentoo support by adding /usr to search path for GeoIP DBs on gentoo - Benny Pedersen

### 1.20130610

- tolerate receiving reports with no records (ahem, hotmail.com)
- simplify SMTP flow-of-control, additional SMTP tests
- avoid the join/split of binip in SQL::populate_agg_records
- replace carp with warn in several places (more legible warning)
- added RUA validity checks to dmarc_lookup

### 1.20130605

- in aggregate reports, group by IP and auth results (was only IP)
- refactored SQL::retrieve_todo into 3 methods, added tests
- SQL: added unique constraint on domain.domain

### 1.20130604

- main branches are master (devel) and releases (more obvious)
- added mailing list impact FAQ
- SQL: removed record.rcpt_dom
- corrected a XML schema error
- index.html
    - widened disposition column
    - only show rcpt domain in record (subgrid)
    - corrected subgrid row_id
- additional validation of aggregate reports

### 1.20130601

- make sure a report record exists when fetching SMTP todo
- added insecure SMTP fallback if STARTTLS fails
- added color coded results to HTTP grid

### 1.20130531

- added gzip support to HTTP server, compressed JS files
- reason is internally an arrayref of hashrefs (was a single hashref)
- documentation additions
- removed unused JS files
- add validation and fixup of SPF result for incoming reports
- normalized domain columns in spf & dkim tables

### 1.20130528

- bump major version to 1
- normalized domain columns in report_record
- fixups to handle reports with invalid formatting
- improved handling for IMAP SSL connections
- made internal represention of Mail::DMARC::dkim & spf consistent with their aggregate report representation

### 0.20130528

- updated Send/SMTP to use report::aggregate
- switched back to gzip reports (instead of zip)
- dmarc_view_reports, added filtering ability, GeoIP location

### 0.20130524

- added bin/dmarc_httpd
- added bin/dmarc_view_reports
- renamed: dmarc_report -> dmarc_send_reports

### 0.20130521

- check for report_record existence before insertion
- SQL: added report_record.count column
- subclassed aggregreate reports into Report::Aggregate
    - consolidates two agg. rep. generation methods to one
- SQL: added table report_error
- updated SQLite schema with native column types

### 0.20130520

- added bin/dmarc_receive (via IMAP, mbox, or message file)
- added report retrieval via IMAP
- extract sender domain from subject or MIME metadata
- SQL: added author.extra_contact
- SQL: removed 'NOT NULL' requirements for values often missing from incoming reports.

### 0.20130517

- send reports with zip until 7/1, gzip after
- replace Socket 2 with Socket6 (better Windows compatibility)
- added parsing of incoming email reports
- added author and domain tables
- added three related columns from/rcpt/author ids to report table
- add email hostname to MX list when attempting SMTP delivery
- during report delivery, check report URI max size

### 0.20130515

- use File::ShareDir to access share/*
- added external reporting verification

### 0.20130514

- moved DNS settings into config file
- fixed a case where disposition was not set
- added bin/dmarc_report
    - sends email reports with Email::MIME & Net::SMTPS
- deletes reports after successful delivery
- required Socket 2 (correct IPv6 handling)
- several SQL schema changes
- has_valid_reporting_uri does validation now

### 0.20130510

### 0.20130507

- added sql and MySQL schema
- added bin/dmarc_lookup
- replaced Regexp::Common IP validation with Net::IP (perl 5.8 compat)
- added Results.pm tests
- added full section numbers to Draft quotes

### 0.20130506

- added Result and Result/Evaluated.pm
- consolidated DNS functions into DNS.pm
    - uses Regexp::Common, requiring perl 5.10.
- Mail::DMARC::Policy is well defined and tested
- setting up package
