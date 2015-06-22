import settings
from uuid import uuid4
from libs import get_db_conn
import ldap
import iredpwd
import utils

def checkUser(validate, recipient, password = None):
    we_serve = False
    
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
                    we_serve = True
            elif validate == 'user':
                if password:
                    filter = "(&(objectClass=mailUser)(mail=%s))" % recipient
                    result = adm_con.search_s(settings.ldap_basedn, 
                                              ldap.SCOPE_SUBTREE, 
                                              filter,
                                              ['userPassword'])
                    if result:
                        challenge = result[0][1]['userPassword'][0]
                        we_serve = iredpwd.verify_password_hash(challenge, password)
            else:
                domain = recipient.split('@')[1]
                filter =  "(&(objectClass=mailDomain)(domainName=%s))" % domain
                result = adm_con.search_s(settings.ldap_basedn, 
                                          ldap.SCOPE_SUBTREE, 
                                          filter, 
                                          ['domainName'])
                if result:
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
            elif validate == 'user':
                if password:
                    domain = recipient.split('@')[1]
                    user_where = "username='%s' and domain='%s'" % (recipient, domain)
                    row = adm_con.select('mailbox', what='password', where=user_where)
                    if row:
                        challenge = row[0].password
                        print challenge
                        we_serve = iredpwd.verify_password_hash(challenge, password)
            else:
                domain_where = "domain='%s'" % recipient.split('@')[1]
                row = adm_con.select('domain', where=domain_where)
                if row:
                    we_serve = True

    return we_serve

def createTicket(session, data):
    authKey = {}

    params = utils.str2Dict(data)
    try:
        if not params or not params['password'] or not params['username']:
            return None
    except KeyError:
        return None
    
    if checkUser('user', params['username'], params['password']):
        authKey['CSRFPreventionToken'] = uuid4().hex
        authKey['username'] = params['username']
        ticket = params['username'] + ':' + uuid4().hex
        authKey['ticket'] = ticket
        session.ticket = authKey
        
    return authKey

def validateCSRFToken(headers, session):
    result = False
    
    try:
        token = headers['HTTP_CSRFPREVENTIONTOKEN']
    except KeyError:
        token = None
    try:
        ticket = session.ticket
    except AttributeError:
        ticket = None

    if token and ticket:
        if ticket['CSRFPreventionToken'] == token:
            result = True

    return result
    
class Cookie(object):
    def __init__(self, cookie):
        self.params = utils.str2Dict(cookie)

    def __getattr__(self, attr):
        try:
            return self.params[attr]
        except KeyError:
            return None

    def __str__(self):
        return "%s(%r)" % (self.__class__, self.params)

