#!/bin/sh

psql -c 'CREATE DATABASE dmarc_report;' -U postgres  || exit
psql -U postgres dmarc_report < share/mail_dmarc_schema.pgsql || exit

mysql -e 'CREATE DATABASE IF NOT EXISTS dmarc_report;' || exit
mysql -u root --password="" dmarc_report < share/mail_dmarc_schema.mysql || exit

exit 0