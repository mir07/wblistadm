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
import ldap
import settings
import logging
import web

web.config.debug = False

os.environ['LC_ALL'] = 'C'

logging.basicConfig(level=logging.WARNING,
                    format='* [%(asctime)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

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
            if settings.backend == 'ldap':
                adm_con = get_db_conn('ldap')
                if adm_con:
                    if validate == 'email':
                        filter = "(&(objectClass=mailUser)(mail=%s))" % recipient
                        result = adm_con.search_s(settings.ldap_basedn, 
                                                  ldap.SCOPE_SUBTREE, 
                                                  filter, 
                                                  ['mail'])
                        if result:
                            # just to be absolutely sure
                            if recipient == result[0][1]['mail'][0]:
                                we_serve = True
                    else:
                        domain = recipient.split('@')[1]
                        filter =  "(&(objectClass=mailDomain)(domainName=%s))" % domain
                        result = adm_con.search_s(settings.ldap_basedn, 
                                                  ldap.SCOPE_SUBTREE, 
                                                  filter, 
                                                  ['domainName'])
                        if result:
                            # just to be absolutely sure
                            if domain == result[0][1]['domainName'][0]:
                                we_serve = True
            else:
                adm_con = get_db_conn('vmail')
                if adm_con:
                    if validate == 'email':
                        domain = recipient.split('@')[1]
                        user_where = "username='%s' and domain='%s'" % (recipient, domain)
                        row = adm_con.select('mailbox', where=user_where)
                        if row:
                            we_serve = True
                    else:
                        domain_where = "domain='%s'" % recipient.split('@')[1]
                        row = adm_con.select('domain', where=domain_where)
                        if row:
                            we_serve = True
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
            out = "%-30s %-30s %s %s\n" % ("Recipient","Sender","Policy", "Priority")
            out += "%s %s %s %s\n" % ("------------------------------","------------------------------","------","--------")
            for row in rows:
                out += "%-30s %-30s %+6s %+8s\n" % (row.recipient, row.sender, row.policy, row.priority)
            out += "\nFound %d instances." % len(rows)
        else:
            out = "Nothing to show"
        
        if not silent:
            print out
        
        return out
    except:
        raise
