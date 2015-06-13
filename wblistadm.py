# Author: Zhang Huangbin <zhb@iredmail.org>

# TODO:
#   - able to remove white/blacklist sender addresses
#   - able to specify recipient
#   - able to list all white/blacklists

# Usage:
#
#   *) Add global white/blacklists
#
#       # python wblistadm.py xx.xx.xx.xx user@domain.com @test.com @.example.com
#
#   *) TODO: Add per-domain white/blacklists
#   *) TODO: Add per-user white/blacklists
#   *) TODO: list account (global, per-domain, per-user) wblist

import os
import sys
import web
import logging

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

from libs import is_valid_amavisd_address, get_db_conn

web.config.debug = False

logging.basicConfig(level=logging.INFO,
                    format='* [%(asctime)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

USAGE = """Usage:

    --whitelist sender
        Whitelist specified sender. Multiple senders must be separated by a space.

    --blacklist sender
        Blacklist specified sender. Multiple senders must be separated by a space.
"""

if len(sys.argv) == 1:
    print USAGE
    sys.exit()
elif not len(sys.argv) >= 3:
    sys.exit()

action = sys.argv[1]
wb = [v for v in sys.argv[2:] if is_valid_amavisd_address(v)]

if not action in ['--whitelist', '--blacklist']:
    sys.exit('Invalid action (%s), must be --whitelist or --blacklist' % action)

if not wb:
    sys.exit('No valid white/blacklist.')

wl = []
bl = []
if action == '--whitelist':
    wl = wb
    logging.info('Submitting whitelist sender address(es): %s' % str(wb))
elif action == '--blacklist':
    bl = wb
    logging.info('Submit blacklist sender address(es): %s' % str(wb))

logging.info('Establish SQL connection.')
conn = get_db_conn('amavisd')

try:
    # Add global wblist: account='@.'
    wb.add_wblist(account='@.',
                  wl_senders=wl,
                  bl_senders=bl,
                  flush_before_import=False)
except Exception, e:
    logging.info(str(e))

logging.info('DONE')
