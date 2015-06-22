# Author: Michael Rasmussen <mir@datanom.net>

# This file is part of wblistadm.
#
# Wblistadm is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Wblistadm is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Wblistadm.  If not, see <http://www.gnu.org/licenses/>.

import os
import logging
import auth

os.environ['LC_ALL'] = 'C'

from libs import is_valid_amavisd_address, get_db_conn, MAILADDR_PRIORITIES

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
        if not 'priority' in res or not 'email' in res:
            res = {}
    except KeyError, e:
        print str(e)
        res = {}
        
    return res

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
        addr = is_valid_amavisd_address(recipient)
        if addr in ['subdomain', 'domain', 'top_level_domain']:
            validate = 'domain'
        elif addr == 'email':
            validate = 'email'
        else:
            validate = None
        
        if validate:
            we_serve = auth.checkUser(validate, recipient)
        else:
            we_serve = True
    else:
        we_serve = True
    
    return we_serve

def update_wblist(action, list_type, wblist, recipient = None):
    
    if not checkRecipient(recipient):
        raise Exception("%s: Unknown recipient" % recipient)

    user_priority = getPriority(recipient)
    if not user_priority:
        raise Exception("Error: Could not determine address")

    if list_type not in ("blacklist", "whitelist"):
        raise Exception("%s: Unknown list type" % list_type)

    if action not in ("add", "delete"):
        raise Exception("%s: Unknown action" % action)

    conn = get_db_conn('amavisd')

    try:
        t = conn.transaction()
    except:
        raise

    rid = None
    try:
        # The mysql driver in webpy.db crashes if any exceptions is raised
        where = "email='%s'" % user_priority['email']
        row = conn.select('users', where=where)
        if row:
            rid = int(row[0].id)
        if not rid:
            raise Exception("Error: Recipient does not exist")
    except:
        t.rollback()
        raise

    if list_type == 'blacklist':
        wb = 'B'
    else:
        wb = 'W'
    
    try:
        for l in wblist:
            sid = None
            priority = getPriority(l)
            if not priority:
                msg = "%s: Could not determine priority" % l
                logging.warning(msg)
                continue
            # The mysql driver in webpy.db crashes if any exceptions is raised
            where = "email='%s'" % priority['email']
            row = conn.select('mailaddr', where=where)

            if action == 'delete':
                if row:
                    sid = int(row[0].id)
                else:
                    msg = "%s: Does not exists" % priority['email']
                    logging.warning(msg)
                    continue
                where = "rid=%d and sid=%d and wb='%s'" % (rid, sid, wb)
                n = int(conn.delete('wblist', where=where))
                if n:
                    where = "email='%s'" % priority['email']
                    n = int(conn.delete('mailaddr', where=where))
                else:
                    msg = "%s: No %s" % (priority['email'], list_type)
                    logging.warning(msg)
                    continue
                if not n:
                    msg = "%s: Missing relation" % priority['email']
                    logging.error(msg)
                    raise Exception(msg)
            else:
                if row:
                    msg = "%s: Exists" % row[0].email
                    logging.warning(msg)
                    continue
                sid = int(conn.insert('mailaddr', email=priority['email'], priority=int(priority['priority'])))
                conn.insert('wblist', rid=rid, sid=sid, wb=wb)
        t.commit()
    except:
        t.rollback()
        raise

def show_wblist(list_type = None, recipient = None, silent = False):
    all = """select u.email as recipient, m.email as sender, w.wb as policy, 
            m.priority as priority from users u, mailaddr m, wblist w 
            where m.id = w.sid and u.id = w.rid
           """
    
    if recipient:
        sql = "%s and u.email = '%s'" % (all, recipient)
    else:
        sql = all

    if list_type and list_type not in ("blacklist", "whitelist"):
        raise Exception("%s: Unknown list type" % list_type)
    elif list_type:
        if list_type == 'blacklist':
            sql += " and w.wb = 'B'"
        else:
            sql += " and w.wb = 'W'"

    try:
        conn = get_db_conn('amavisd')
        
        rows = conn.query(sql)
        
        if rows:
            if silent:
                list = []
            else:
                out = "%-30s %-30s %s %s\n" % ("Recipient","Sender","Policy", "Priority")
                out += "%s %s %s %s\n" % ("------------------------------","------------------------------","------","--------")
            for row in rows:
                if silent:
                    list.append(row)
                else:            
                    out += "%-30s %-30s %+6s %+8s\n" % (row.recipient, row.sender, row.policy, row.priority)
            if not silent:
                out += "\nFound %d instances." % len(rows)
        else:
            if silent:
                list = []
            else:
                out = "Nothing to show"
        
        if not silent:
            print out
        else:
            return list
    except:
        raise
