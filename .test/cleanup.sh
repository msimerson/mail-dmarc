#!/bin/sh

mysql -e 'DROP DATABASE dmarc_report'

if [ -f t/reports-test.sqlite ]; then
    rm t/reports-test.sqlite
fi

if [ -f dmarc_reports.sqlite ]; then
    rm dmarc_reports.sqlite
fi
