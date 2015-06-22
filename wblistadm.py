#!/usr/bin/env python

# Author: Zhang Huangbin <zhb@iredmail.org>
# Author: Michael Rasmussen <mir@datanom.net>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# As a special exception, the copyright holders of this application gives
# permission to use this application as part of iRedAdmin-Pro under the
# terms and conditions which covers iRedAdmin-Pro provided that any
# changes or add-ons to this application made as part of the further
# development of iRedAdmin-Pro are returned back to this application
# unmodified under the same terms and conditions which covers this
# application.

# Usage:
#
#   *) Add white/blacklists global, per-domain, or per-user
#
#       # python wblistadm.py --recipient=user@domain.com --blacklist '@test.com @.example.com'
#

import os
import sys
import logging
import getopt
import web

web.config.debug = False

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

from libs import is_valid_amavisd_address
from libs.wblistadm_utils import update_wblist, show_wblist

USAGE = """Usage:

    wblistadm [option]
    
    Options:
    -b | --blacklist sender
        Blacklist specified sender. Multiple senders must be separated by a space
        and the entire list must be enclosed in " or '.
    -d | --delete
        This means remove the blacklist or whitelist.
    -h | --help
        Show this help
    -r | --recipient
        Recipient can be global, domain, or user.
        If recipient is not listed recipient will be global.
    -s | --show
        If recipient is listed only list for this recipient.
        If neither blacklist nor whitelist is present show all.
    -w | --whitelist sender
        Whitelist specified sender. Multiple senders must be separated by a space
        and the entire list must be enclosed in " or '.
    
    blacklist and whitelist option is mutual exclusive.
    Unless option delete or list is present the implied action is add.
"""

logging.basicConfig(level=logging.WARNING,
                    format='* [%(asctime)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

def show_wb(blacklist, whitelist, recipient):
    if blacklist:
        list_type = 'blacklist'
    elif whitelist:
        list_type = 'whitelist'
    else:
        list_type = None

    try:
        show_wblist(list_type, recipient)
    except:
        raise

def delete_wb(blacklist,  whitelist,  recipient):
    if blacklist:
        list_type = 'blacklist'
        wblist = blacklist
    else:
        list_type = 'whitelist'
        wblist = whitelist
    
    try:
        update_wblist('delete', list_type, wblist, recipient)
    except:
        raise

def add_wb(blacklist,  whitelist,  recipient):
    if blacklist:
        list_type = 'blacklist'
        wblist = blacklist
    else:
        list_type = 'whitelist'
        wblist = whitelist
    
    try:
        update_wblist('add', list_type, wblist, recipient)
    except:
        raise

def main():
    blacklist = None
    whitelist = None
    recipient = None
    show      = False
    delete    = False

    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:],
        "hbdr:sw", ["help", "blacklist", "delete", "recipient=", "show", "whitelist"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err) # will print something like "option -a not recognized"
        print USAGE
        sys.exit(2)
    for option,  argument in opts:
        if option in ("-h",  "--help"):
            print USAGE
            sys.exit(0)
        elif option in ("-b", "--blacklist"):
            blacklist = True
        elif option in ("-d", "--delete"):
            delete = True
        elif option in ("-r", "--recipient"):
            if is_valid_amavisd_address(argument):
                recipient = argument
            else:
                print "%s: Invalid recipient" % argument
                sys.exit(1)
        elif option in ("-s", "--show"):
            show = True
        elif option in ("-w", "--whitelist"):
            whitelist = True
        else:
            assert False, "%s: unhandled option" % option

    if blacklist and whitelist:
        print "Error: whitelist and blacklist is mutual exclusive"
        print USAGE
        sys.exit(1)
    if show and delete:
        print "Error: show and delete is mutual exclusive"
        print USAGE
        sys.exit(1)
    if (blacklist or whitelist) and not show:
        if args:
            a = args[0].split()
            s = set(a)
            if blacklist:
                blacklist = [v for v in a if is_valid_amavisd_address(v)]
                bad = [x for x in s if x not in blacklist]
            else:
                whitelist = [v for v in a if is_valid_amavisd_address(v)]
                bad = [x for x in s if x not in whitelist]
            if bad:
                s = "Skipping: %s" % ' '.join(bad)
                logging.warning(s)
                print "Warning: %s" % s
        else:
            print "Error: whitelist or blacklist needs arguments"
            print USAGE
            sys.exit(1)

    logging.info('Excecuting request')

    try:
        if show:
            show_wb(blacklist, whitelist, recipient)
        elif delete:
            if blacklist or whitelist:
                delete_wb(blacklist, whitelist, recipient)
            else:
                print "blacklist and whitelist cannot be empty"
                sys.exit(1)
        else:
            if blacklist or whitelist:
                add_wb(blacklist, whitelist, recipient)
            else:
                print "blacklist and whitelist cannot be empty"
                sys.exit(1)
    except Exception, e:
        logging.error(str(e))
        print str(e)
        sys.exit(1)

    logging.info('DONE')

if __name__ == '__main__':
    sys.exit(main())
