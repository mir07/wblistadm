# Author: Zhang Huangbin <zhb@iredmail.org>
# Author: Michael Rasmussen <mir@datanom.net>

# TODO:
#   - able to remove white/blacklist sender addresses

# Usage:
#
#   *) Add white/blacklists global, per-domain, or per-user
#
#       # python wblistadm.py --recipient=user@domain.com --blacklist '@test.com @.example.com'
#

import os
import sys
import web
import logging
import getopt

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

from libs import is_valid_amavisd_address, get_db_conn

web.config.debug = False

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
    -l | --list
        If recipient is listed only list for this recipient.
        If neither blacklist nor whitelist is present show all.
    -r | --recipient
        Recipient can be global, domain, or user.
        If recipient is not listed recipient will be global.
    -w | --whitelist sender
        Whitelist specified sender. Multiple senders must be separated by a space
        and the entire list must be enclosed in " or '.
    
    blacklist and whitelist option is mutual exclusive.
    Unless option delete or list is present the implied action is add.
"""

logging.basicConfig(level=logging.INFO,
                    format='* [%(asctime)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
conn = None

# Priority used in SQL table "amavisd.mailaddr". 0 is the lowest priority.
# Reference: http://www.amavis.org/README.lookups.txt
#
# The following order (implemented by sorting on the 'priority' field
# in DESCending order, zero is low priority) is recommended, to follow
# the same specific-to-general principle as in other lookup tables;
#   9 - lookup for user+foo@sub.example.com
#   8 - lookup for user@sub.example.com (only if $recipient_delimiter is '+')
#   7 - lookup for user+foo (only if domain part is local)
#   6 - lookup for user     (only local; only if $recipient_delimiter is '+')
#   5 - lookup for @sub.example.com
#   3 - lookup for @.sub.example.com
#   2 - lookup for @.example.com
#   1 - lookup for @.com
#   0 - lookup for @.       (catchall)
MAILADDR_PRIORITIES = {
    'ip': 10,
    'email': 8,
    'wildcard_addr': 6,     # r'user@*'. used in iRedAPD plugin `amavisd_wblist`
                            # as wildcard sender. e.g. 'user@*'
    'domain': 5,
    'subdomain': 3,
    'top_level_domain': 1,
    'catchall': 0,
}

def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def checkRecipient(recipient):
    """Do we serve mail for user or domain"""
    we_serve = False
    
    if recipient:
        """
            Lookup user or domain in:
                database vmail.mailbox
                database vmail.domain
                ldap.mailbox
                ldap.domain
        """
        we_serve = True
    else:
        we_serve = True
    
    return we_serve

def getPriority(address):
    res = {}
    
    try:
        if not address:
            res['priority'] = MAILADDR_PRIORITIES['catchall']
            res['email'] = '@.'
        else:
            res['priority'] = MAILADDR_PRIORITIES[is_valid_amavisd_address(address)]
            res['email'] = address
    except KeyError,  e:
        print str(e)
        res = {}
    
    try:
        if (not res['priority'] and not is_int(res['priority'])) or not res['email']:
            res = {}
    except KeyError, e:
        print str(e)
        res = {}
        
    return res

def list_wb(blacklist, whitelist, recipient):
    global conn
    
    all = """select u.email as recipient, m.email as sender, w.wb as policy, 
            m.priority as priority from users u, mailaddr m, wblist w 
            where m.id = w.sid and u.id = w.rid
           """
    
    if recipient:
        sql = "%s and u.email = '%s'" % (all, recipient)
    else:
        sql = all

    if blacklist or whitelist:
        if blacklist:
            sql += " and w.wb = 'B'"
        else:
            sql += " and w.wb = 'W'"

    rows = conn.query(sql)
    if rows:
        print "%-30s %-30s %s %s" % ("Recipient","Sender","Policy", "Priority")
        print "%s %s %s %s" % ("------------------------------","------------------------------","------","--------")
        for row in rows:
            print "%-30s %-30s %+6s %+8s" % (row.recipient, row.sender, row.policy, row.priority)
        print "\nFound %d instances." % len(rows)
    else:
        print "Nothing to list"

def delete_wb(blacklist,  whitelist,  recipient):
    global conn

    try:
        t = conn.transaction()
    except:
        raise

    if not checkRecipient(recipient):
        print "%s: Unknown recipient"
        sys.exit(1)

    user_priority = getPriority(recipient)
    if not user_priority:
        print "Error: Could not determine address"
        sys.exit(1)

    rid = None
    try:
        # The mysql driver in webpy.db crashes if any exceptions is raised
        where = "email='%s'" % user_priority['email']
        row = conn.select('users', where=where)
        if row:
            rid = int(row[0].id)
        if not rid:
            print "Error: Recipient does not exist"
            sys.exit(1)
    except:
        t.rollback()
        raise

    if blacklist:
        """Blacklist"""
        try:
            for b in blacklist:
                sid = None
                priority = getPriority(b)
                if not priority:
                    msg = "%s: Could not determine priority" % b
                    logging.warning(msg)
                    continue
                # The mysql driver in webpy.db crashes if any exceptions is raised
                where = "email='%s'" % priority['email']
                row = conn.select('mailaddr', where=where)
                if row:
                    sid = int(row[0].id)
                else:
                    msg = "%s: Does not exists" % priority['email']
                    logging.warning(msg)
                    continue

                where = "rid=%d and sid=%d and wb='B'" % (rid,  sid)
                n = int(conn.delete('wblist', where=where))
                if n:
                    where = "email='%s'" % priority['email']
                    n = int(conn.delete('mailaddr', where=where))
                else:
                    msg = "%s: No blacklist" % priority['email']
                    logging.warning(msg)
                    continue
                if not n:
                    msg = "%s: Missing relation" % priority['email']
                    logging.error(msg)
                    raise Exception(msg)
            t.commit()
        except:
            t.rollback()
            raise
    else:
        """Whitelist"""
        try:
            for w in whitelist:
                sid = None
                priority = getPriority(w)
                if not priority:
                    msg = "%s: Could not determine priority" % w
                    logging.warning(msg)
                    continue
                # The mysql driver in webpy.db crashes if any exceptions is raised
                where = "email='%s'" % priority['email']
                row = conn.select('mailaddr', where=where)
                if row:
                    sid = int(row[0].id)
                else:
                    msg = "%s: Does not exists" % priority['email']
                    logging.warning(msg)
                    continue
                    
                where = "rid=%d and sid=%d and wb='W'" % (rid,  sid)
                n = int(conn.delete('wblist', where=where))
                if n:
                    n = int(conn.delete('mailaddr', where="email=" + priority['email']))
                else:
                    msg = "%s: No whitelist" % priority['email']
                    logging.warning(msg)
                    continue
                if not n:
                    msg = "%s: Missing relation" % priority['email']
                    logging.error(msg)
                    raise Exception(msg)
        except:
            t.rollback()
            raise
        else:
            t.commit()

def add_wb(blacklist,  whitelist,  recipient):
    global conn
    
    try:
        t = conn.transaction()
    except:
        raise

    if not checkRecipient(recipient):
        print "%s: Unknown recipient"
        sys.exit(1)

    user_priority = getPriority(recipient)
    if not user_priority:
        print "Error: Could not determine priority"
        sys.exit(1)

    rid = None
    try:
        # The mysql driver in webpy.db crashes if any exceptions is raised
        where = "email='%s'" % user_priority['email']
        row = conn.select('users', where=where)
        if row:
            rid = int(row[0].id)
        if not rid:
            rid = int(conn.insert('users', email=user_priority['email'], priority=int(user_priority['priority'])))
    except:
        t.rollback()
        raise

    if blacklist:
        """Blacklist"""
        try:
            for b in blacklist:
                sid = None
                priority = getPriority(b)
                if not priority:
                    msg = "%s: Could not determine priority" % b
                    logging.warning(msg)
                    continue
                # The mysql driver in webpy.db crashes if any exceptions is raised
                where = "email='%s'" % priority['email']
                row = conn.select('mailaddr', where=where)
                if row:
                    msg = "%s: Exists" % row[0].email
                    logging.warning(msg)
                    continue
                sid = int(conn.insert('mailaddr', email=priority['email'], priority=int(priority['priority'])))
                conn.insert('wblist', rid=rid, sid=sid, wb='B')
            t.commit()
        except:
            t.rollback()
            raise
    else:
        """Whitelist"""
        try:
            for w in whitelist:
                sid = None
                priority = getPriority(w)
                if not priority:
                    msg = "%s: Could not determine priority" % w
                    logging.warning(msg)
                    continue
                # The mysql driver in webpy.db crashes if any exceptions is raised
                where = "email='%s'" % priority['email']
                row = conn.select('mailaddr', where=where)
                if row:
                    msg = "%s: Exists" % row[0].email
                    logging.warning(msg)
                    continue
                sid = int(conn.insert('mailaddr', email=priority['email'], priority=int(priority['priority'])))
                conn.insert('wblist', rid=rid, sid=sid, wb='W')
        except:
            t.rollback()
            raise
        else:
            t.commit()

def main():
    global conn
    
    blacklist = None
    whitelist = None
    recipient = None
    list      = False
    delete    = False

    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:],
        "hbdlr:w", ["help", "blacklist", "delete", "list", "recipient=", "whitelist"])
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
        elif option in ("-l", "--list"):
            list = True
        elif option in ("-r", "--recipient"):
            if is_valid_amavisd_address(argument):
                recipient = argument
            else:
                print "%s: Invalid recipient" % argument
                sys.exit(1)
        elif option in ("-w", "--whitelist"):
            whitelist = True
        else:
            assert False, "%s: unhandled option" % option

    if blacklist and whitelist:
        print "Error: whitelist and blacklist is mutual exclusive"
        print USAGE
        sys.exit(1)
    if list and delete:
        print "Error: list and delete is mutual exclusive"
        print USAGE
        sys.exit(1)
    if (blacklist or whitelist) and not list:
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

    #print blacklist, whitelist, delete, list, recipient
    
    logging.info('Establish SQL connection.')
    conn = get_db_conn('amavisd')
    if not conn:
        print "Could not connect to database"
        sys.exit(1)

    try:
        if list:
            list_wb(blacklist, whitelist, recipient)
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
