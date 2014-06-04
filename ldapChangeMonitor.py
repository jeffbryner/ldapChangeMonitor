#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014 Mozilla Corporation

# Contributor: gdestuynder@mozilla.com
# Contributor: jbryner@mozilla.com

import copy
import os
import sys
import re
import json
import glob
import string
import ConfigParser
import tempfile
import logging
import socket
from logging.handlers import SysLogHandler
from requests import Session
from optparse import OptionParser
from datetime import datetime
from os import stat
from os.path import exists, getsize
from ldif import LDIFRecordList, MOD_OP_STR

"""
    Script to monitor changes in an openldap .ldif audit log
    Uses the pygtail class to tail lines and follow rotated files
    Reports changes to syslog as a standard syslog message
    Uses the standard python ldif library wih an overridden parse class to catch all changes.
    (The original ldif library doesn't report object deletions and is difficult navigate to report changes.)
"""


class MozDefError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)


class MozDefEvent():
    # create requests session to allow for keep alives
    httpsession = Session()
    # Turns off needless and repetitive .netrc check for creds
    httpsession.trust_env = False
    debug = False
    verify_certificate = True
    # Never fail (ie no unexcepted exceptions sent to user, such as server/network not responding)
    fire_and_forget_mode = True
    log = {}
    log['timestamp'] = datetime.isoformat(datetime.now())
    log['hostname'] = socket.getfqdn()
    log['processid'] = os.getpid()
    log['processname'] = sys.argv[0]
    log['severity'] = 'INFO'
    log['summary'] = None
    log['category'] = 'event'
    log['tags'] = list()
    log['details'] = dict()

    def __init__(self, url='http://localhost/events', summary=None, category='event', severity='INFO', tags=[], details={}):
        self.summary = summary
        self.category = category
        self.severity = severity
        self.tags = tags
        self.details = details
        self.url = url

    def send(self, summary=None, category=None, severity=None, tags=None, details=None):
        log_msg = copy.copy(self.log)

        if summary is None:
            log_msg['summary'] = self.summary
        else:
            log_msg['summary'] = summary

        if category is None:
            log_msg['category'] = self.category
        else:
            log_msg['category'] = category

        if severity is None:
            log_msg['severity'] = self.severity
        else:
            log_msg['severity'] = severity

        if tags is None:
            log_msg['tags'] = self.tags
        else:
            log_msg['tags'] = tags

        if details is None:
            log_msg['details'] = self.details
        else:
            log_msg['details'] = details

        if type(log_msg['details']) != dict:
            raise MozDefError('details must be a dict')
        elif type(log_msg['tags']) != list:
            raise MozDefError('tags must be a list')
        elif summary is None:
            raise MozDefError('Summary is a required field')

        if self.debug:
            print(json.dumps(log_msg, sort_keys=True, indent=4))

        try:
            r = self.httpsession.post(self.url, json.dumps(log_msg), verify=self.verify_certificate)
        except Exception as e:
            if not self.fire_and_forget_mode:
                raise e


class mzLDIFRecordList(LDIFRecordList):

    def parse(self):
        """
        Continously read and parse LDIF records
        assumes records start with
        # <changetype>
        and end with
        # end <changetype>

        builds a python structure consisting of:
        a list:
            list[0] is the dn of the item being changed
            list[1] is a dictionary consisting of several keys:
                list[1]['dn'] is a repeat of the dn for ease of access
                list[1]['actions'] is a summary list of the actions taken against the dn
                list[1]['changes'] is a detailed list of all changes (attribute/value pairs)

                retrieve these with:
                    changes=list[1]['changes']
                    changepairs=zip(changes,changes[1:])[::2]

                    actions=list[1]['actions']
                    actionpairs=zip(actions,actions[1:])[::2]

        """
        beginActionRe = re.compile(r"""# (add|change|delete|modify) ([0-9]{1,100}) (.*)""", re.IGNORECASE)
        self._line = self._input_file.readline()
        dn = None
        changetype = None
        entry = {}
        action = ''
        actor = ''
        while self._line and (not self._max_entries
                              or self.records_read < self._max_entries):

            # for deletes the modifier is on the beginning comment line
            # read it before parseAttrTypeAndValue which ignores comments and folds lines
            if beginActionRe.match(self._line):
                actor = beginActionRe.search(self._line).groups()[2]
                entry['actor'] = actor

            attr_type, attr_value = self._parseAttrTypeandValue()
            if attr_type == 'dn':
                dn = attr_value
                entry['dn'] = dn
            elif attr_type in MOD_OP_STR.values():
                # this is an action (add/delete/replace)
                action = attr_type
                if 'actions' in entry.keys():
                    entry['actions'] += [attr_type, attr_value]
                else:
                    entry['actions'] = [attr_type, attr_value]
                    entry['actions']
            elif attr_type == 'changetype':
                # generally used to denote the type of change to the dn ('add/delete/modify')
                changetype = attr_value
                entry['changetype'] = changetype

            elif attr_value != None and not self._ignored_attr_types.has_key(attr_type.lower()):
                # this is an attribute/value pair of a change:
                # telephonenumber: +1 408 555 1234
                # since there can be many of these, this is stored as a list
                # since there can be adds/deletes/replaces of many of these the list includes the
                # action:attributeName as the [0] item in the value/pair
                if action == '':
                    # adding a new dn can have no attribute action
                    action = changetype
                if attr_type == 'modifiersName':
                    entry['actor'] = attr_value
                if 'changes' in entry.keys():
                    entry['changes'] += (action + ':' + attr_type, attr_value)
                else:
                    entry['changes'] = (action + ':' + attr_type, attr_value)

            # append entry to result list
            if dn != None and len(entry) > 0 and "# end" in self._line:
                if 'actor' not in entry.keys():
                    # we didn't find an actor..set the default
                    entry['actor'] = 'unknown'
                self.handle(dn, entry)
                self.records_read = self.records_read + 1
                # reset record
                dn = None
                changetype = None
                entry = {}
                action
                actor = ''

        return


def createLogRecord(dictIn):
    # make an event message that can be used
    # for syslog, text, json, etc.
    log = {}
    log['category'] = 'ldapChange'
    log['summary'] = '{0} {1} {2} '.format(dictIn['actor'], dictIn['changetype'], dictIn['dn'])
    log['details'] = dict()
    log['details']['actor'] = dictIn['actor']
    log['details']['changetype'] = dictIn['changetype']
    log['details']['dn'] = dictIn['dn']
    # gather the actions and change lists into pairs of action,value and action:attribute,value
    if 'actions' in dictIn.keys():
        actionpairs = zip(dictIn['actions'], dictIn['actions'][1:])[::2]
        changepairs = zip(dictIn['changes'], dictIn['changes'][1:])[::2]
        log['details']['actionpairs'] = actionpairs
        log['details']['changepairs'] = changepairs

        # what to show in the summary field?
        if ('member' in dictIn['actions']) or 'memberUid' in dictIn['actions']:
            # likely a group membership change (add or delete)
            for a, v in actionpairs:
                if v in ('member', 'memberUid'):
                    for ca, cv in changepairs:
                        if ca == a + ':' + v:
                            if ' {0}: {1} '.format(ca, cv) not in log['summary']:
                                log['summary'] += ' {0}: {1} '.format(ca, cv)
        else:
            # default message logs action pairs
            for action, value in actionpairs:
                log['summary'] += '{0} {1} '.format(action, value)

    log['timestamp'] = datetime.isoformat(datetime.now())
    return(log)


class Pygtail(object):
    """
    Creates an iterable object that returns only unread lines.
    """
    def __init__(self, filename, offset_file=None, paranoid=False, pretend=False):
        self.filename = filename
        self.paranoid = paranoid
        self._offset_file = offset_file or "%s.offset" % self.filename
        self._offset_file_inode = 0
        self._offset = 0
        self._fh = None
        self._rotated_logfile = None
        self.pretend = pretend

        # if offset file exists and non-empty, open and parse it
        if exists(self._offset_file) and getsize(self._offset_file):
            offset_fh = open(self._offset_file, "r")
            (self._offset_file_inode, self._offset) = \
                [int(line.strip()) for line in offset_fh]
            offset_fh.close()
            if self._offset_file_inode != stat(self.filename).st_ino:
                # The inode has changed, so the file might have been rotated.
                # Look for the rotated file and process that if we find it.
                self._rotated_logfile = self._determine_rotated_logfile()

    def __del__(self):
        if self._filehandle():
            self._filehandle().close()

    def __iter__(self):
        return self

    def next(self):
        """
        Return the next line in the file, updating the offset.
        """
        try:
            line = next(self._filehandle())
        except StopIteration:
            # we've reached the end of the file; if we're processing the
            # rotated log file, we can continue with the actual file; otherwise
            # update the offset file
            if self._rotated_logfile:
                self._rotated_logfile = None
                self._fh.close()
                self._offset = 0
                self._update_offset_file()
                # open up current logfile and continue
                try:
                    line = next(self._filehandle())
                except StopIteration:  # oops, empty file
                    self._update_offset_file()
                    raise
            else:
                self._update_offset_file()
                raise

        if self.paranoid:
            self._update_offset_file()

        return line

    def __next__(self):
        """`__next__` is the Python 3 version of `next`"""
        return self.next()

    def readlines(self):
        """
        Read in all unread lines and return them as a list.
        """
        return [line for line in self]

    def read(self):
        """
        Read in all unread lines and return them as a single string.
        """
        lines = self.readlines()
        if lines:
            return ''.join(lines)
        else:
            return None

    def _filehandle(self):
        """
        Return a filehandle to the file being tailed, with the position set
        to the current offset.
        """
        if not self._fh or self._fh.closed:
            filename = self._rotated_logfile or self.filename
            self._fh = open(filename, "r")
            self._fh.seek(self._offset)

        return self._fh

    def _update_offset_file(self):
        """
        Update the offset file with the current inode and offset.
        """
        if not self.pretend:
            offset = self._filehandle().tell()
            inode = stat(self.filename).st_ino
            fh = open(self._offset_file, "w")
            fh.write("%s\n%s\n" % (inode, offset))
            fh.close()

    def _determine_rotated_logfile(self):
        """
        We suspect the logfile has been rotated, so try to guess what the
        rotated filename is, and return it.
        """
        for rotated_filename in self._check_rotated_filename_candidates():
            if exists(rotated_filename) and stat(rotated_filename).st_ino == self._offset_file_inode:
                return rotated_filename
        return None

    def _check_rotated_filename_candidates(self):
        """
        Check for various rotated logfile filename patterns and return the
        matches we find.
        """
        candidates = []
        # savelog(8)
        candidate = "%s.0" % self.filename
        if (exists(candidate) and
            exists("%s.1.gz" % self.filename) and
                (stat(candidate).st_mtime >
                 stat("%s.1.gz" % self.filename).st_mtime)):
            candidates.append(candidate)

        # logrotate(8)
        candidate = "%s.1" % self.filename
        if exists(candidate):
            candidates.append(candidate)

        # dateext rotation scheme
        for candidate in glob.glob("%s-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]" % self.filename):
            candidates.append(candidate)

        # for TimedRotatingFileHandler
        for candidate in glob.glob("%s.[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]" % self.filename):
            candidates.append(candidate)

        return candidates


def main():
    if not exists(options.inputfile):
        print('no file found')
        return
    if options.output == 'syslog':
        logger = logging.getLogger()
        logger.addHandler(SysLogHandler(address=(options.sysloghostname, options.syslogport), facility='local4'))
    ptlines = 0

    # take a look the file to see if it has a complete # begin # end multi-line
    # structure..if not bail as we likely read it while it was being appended
    bRecords = False
    pt = Pygtail(options.inputfile, options.offsetfile, pretend=True)
    temp = tempfile.NamedTemporaryFile(suffix='_ldif', delete=False)
    for line in pt:
        temp.write(line)
        ptlines += 1
        if "# end" in line:
            bRecords = True
    temp.close()

    if ptlines == 0 or not bRecords:
        os.unlink(temp.name)
    elif ptlines > 0 and bRecords:
        mdEvent = MozDefEvent(options.url)
        mdEvent.debug = False
        mdEvent.fire_and_forget_mode = False
        # read and ignore certain noisy fields
        l = mzLDIFRecordList(open(temp.name, 'rb'), ['jpegPhoto', 'lmPassword', 'ntPassword', 'userPassword', 'sshPublicKey', 'pwdHistory', 'other', 'description'])
        l.parse()
        temp.close()
        os.unlink(temp.name)
        pt.pretend = False
        pt._update_offset_file()
        for i in l.all_records:
            log = createLogRecord(i[1])
            # http post/syslog/stdout
            if options.output == 'syslog':   
                logger.warn(log["summary"])

            elif options.output == 'http':
                # some changes have no details
                logDetails = dict()
                if 'details' in log:
                    logDetails = log['details']
    
                mdEvent.send(summary=log['summary'],
                             category=log['category'],
                             tags=['ldap', 'ldif'],
                             details=logDetails)
            elif options.output == 'stdout':
                    print(log['summary'])


def getConfig(optionname, thedefault, configfile):
    """read an option from a config file or set a default
       send 'thedefault' as the data class you want to get a string back
       i.e. 'True' will return a string
       True will return a bool
       1 will return an int
    """
    retvalue = thedefault
    opttype = type(thedefault)
    if os.path.isfile(configfile):
        config = ConfigParser.ConfigParser()
        config.readfp(open(configfile))
        if config.has_option('options', optionname):
            if opttype == bool:
                retvalue = config.getboolean('options', optionname)
            elif opttype == int:
                retvalue = config.getint('options', optionname)
            elif opttype == float:
                retvalue = config.getfloat('options', optionname)
            else:
                retvalue = config.get('options', optionname)
    return retvalue


def initConfig(configfile):
    # default options
    options.format = getConfig('format', 'text', configfile)
    options.inputfile = getConfig('inputfile', '', configfile)
    options.output = getConfig('output', 'stdout', configfile)
    options.sysloghostname = getConfig('sysloghostname', 'localhost', configfile)
    options.syslogport = getConfig('syslogport', 514, configfile)
    options.offsetfile = getConfig('offsetfile', 'ldapchangetail.offset', configfile)
    options.url = getConfig('url', 'http://localhost:8080/events', configfile)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-c", dest='configfile', default='', help="configuration file to use")
    (options, args) = parser.parse_args()
    initConfig(options.configfile)
    main()