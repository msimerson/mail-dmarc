
### Planned Features

* [ ] Forensic reports
* [ ] HTTP report delivery
* [ ] more SMTP error reporting
* [ ] Report SPF records in dmarc\_lookup output
* [ ] add a 'cron' mode for dmarc\_send and dmarc\_receive, if no controlling TTY, don't output status messages
* [ ] skip DMARC reporting for incoming DMARC reports destined to config->organization->email


### Maybe TODO:

* [ ] detect > 1 From recipient, apply strongest policy


### Done

* [x] automatically delete reports after 12 delivery errors
* [x] send a 'too big' notification email
