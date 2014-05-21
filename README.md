ldapChangeMonitor
=================

Monitor ldif files from openldap and report changes to syslog. Meant to run as a cron job and will automagically tail it's target file, deal with file rotations, etc. 

Options are in the *.conf file, run using ldapChangeMonitor.py -c ldapChangeMonitor.conf

createLogRecord is the funtion you're after if you wish to alter the message format, contents, etc
