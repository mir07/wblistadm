# Author: Zhang Huangbin <zhb@iredmail.org>

from libs import MAILADDR_PRIORITIES
from libs import is_valid_amavisd_address
import web

def create_mailaddr(conn, addresses):
    for addr in addresses:
        addr_type = is_valid_amavisd_address(addr)
        if addr_type in MAILADDR_PRIORITIES:
            try:
                conn.insert('mailaddr',
                            priority=MAILADDR_PRIORITIES[addr_type],
                            email=addr)
            except:
                pass

    return True


def get_user_record(conn, account, create_if_missing=True):
    try:
        qr = conn.select('users',
                         vars={'email': account},
                         what='*',
                         where='email=$email',
                         limit=1)

        if qr:
            return (True, qr[0])
        else:
            if create_if_missing:
                qr = create_user(conn=conn,
                                 account=account,
                                 return_record=True)

                if qr[0]:
                    return (True, qr[1])
                else:
                    return qr
            else:
                (False, 'ACCOUNT_NOT_EXIST')
    except Exception, e:
        return (False, str(e))


def create_user(conn, account, policy_id=0, return_record=True):
    # Create a new record in `amavisd.users`
    addr_type = is_valid_amavisd_address(account)
    try:
        # Use policy_id=0 to make sure it's not linked to any policy.
        conn.insert('users',
                    policy_id=0,
                    email=account,
                    priority=MAILADDR_PRIORITIES[addr_type])

        if return_record:
            qr = conn.select('users',
                             vars={'account': account},
                             what='*',
                             where='email=$account',
                             limit=1)
            return (True, qr[0])
        else:
            return (True, )
    except Exception, e:
        return (False, str(e))


def get_account_wblist(conn, account, whitelist=True, blacklist=True):
    sql_where = 'users.email=$user AND users.id=wblist.rid AND wblist.sid = mailaddr.id'
    if whitelist and not blacklist:
        sql_where += ' AND wblist.wb=%s' % web.sqlquote('W')
    if not whitelist and blacklist:
        sql_where += ' AND wblist.wb=%s' % web.sqlquote('B')

    wl = []
    bl = []

    try:
        qr = conn.select(['mailaddr', 'users', 'wblist'],
                         vars={'user': account},
                         what='mailaddr.email AS address, wblist.wb AS wb',
                         where=sql_where)
        for r in qr:
            if r.wb == 'W':
                wl.append(r.address)
            else:
                bl.append(r.address)
    except Exception, e:
        return (False, e)

    return (True, {'whitelist': wl, 'blacklist': bl})

def add_wblist(conn,
               account,
               wl_senders=[],
               bl_senders=[],
               flush_before_import=False):
    if not is_valid_amavisd_address(account):
        return (False, 'INVALID_ACCOUNT')

    # Remove duplicate.
    wl_senders = set([str(s).lower()
                      for s in wl_senders
                      if is_valid_amavisd_address(s)])
    # Whitelist has higher priority, don't include whitelisted sender.
    bl_senders = set([str(s).lower()
                      for s in bl_senders
                      if is_valid_amavisd_address(s)])

    if flush_before_import and wl_senders:
        bl_senders = set([s for s in bl_senders if s not in wl_senders])

    addresses = list(wl_senders | bl_senders)

    # Get current user's id from `amavisd.users`
    qr = get_user_record(conn, account)

    if qr[0]:
        user_id = qr[1].id
    else:
        return qr

    # Delete old records
    if flush_before_import:
        conn.delete('wblist',
                    vars={'rid': user_id},
                    where='rid=$rid')

    if not addresses:
        return (True, )

    # Insert all senders into `amavisd.mailaddr`
    create_mailaddr(conn, addresses)

    # Get `mailaddr.id` of senders
    sender_records = {}
    qr = conn.select('mailaddr',
                     vars={'addresses': addresses},
                     what='id, email',
                     where='email IN $addresses')
    for r in qr:
        sender_records[str(r.email)] = r.id
    del qr

    # Remove existing records of current submitted records then insert new.
    try:
        conn.delete('wblist',
                    vars={'rid': user_id, 'sid': sender_records.values()},
                    where='rid=$rid AND sid IN $sid')
    except Exception, e:
        return (False, str(e))

    # Generate SQL statements to import wblist
    values = []
    for s in wl_senders:
        if sender_records.get(s):
            values.append({'rid': user_id, 'sid': sender_records[s], 'wb': 'W'})

    for s in bl_senders:
        # Filter out same record in blacklist
        if sender_records.get(s) and s not in wl_senders:
            values.append({'rid': user_id, 'sid': sender_records[s], 'wb': 'B'})

    try:
        conn.multiple_insert('wblist', values)

        # Log
        if wl_senders or bl_senders:
            if flush_before_import:
                web.logger(msg='Update whitelists and/or blacklists for %s.' % account,
                           admin='CLI',
                           event='update_wblist')
            else:
                if wl_senders:
                    web.logger(msg='Add whitelists for %s: %s.' % (account, ', '.join(wl_senders)),
                               admin='CLI',
                               event='update_wblist')

                if bl_senders:
                    web.logger(msg='Add blacklists for %s: %s.' % (account, ', '.join(bl_senders)),
                               admin=session['username'],
                               event='update_wblist')

    except Exception, e:
        return (False, str(e))

    return (True, )
