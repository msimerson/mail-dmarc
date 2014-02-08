* Forensic reports
* HTTP report delivery
* skip DMARC reporting for incoming DMARC reports
  * destined to config->organization->email
* expand Public Suffix List tests with
  http://mxr.mozilla.org/mozilla-central/source/netwerk/test/unit/data/test_psl.txt?raw=1


# Maybe TODO:

* detect > 1 From recipient, apply strongest policy


# Done

* automatically delete reports after 12 delivery errors
* send a 'too big' notification email
