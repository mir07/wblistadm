import re
import web
import settings

######################
# Regular expressions.
#
# Mail address. +, = is used in SRS rewritten addresses.
regx_email = r'''[\w\-][\w\-\.\+\=]*@[\w\-][\w\-\.]*\.[a-zA-Z0-9\-]{2,15}'''

# Domain name
regx_domain = r'''[\w\-][\w\-\.]*\.[a-z0-9\-]{2,25}'''
regx_top_level_domain = r'''[a-z0-9\-]{2,25}'''

regx_valid_account_first_char = r'''[0-9a-zA-Z]{1,1}'''

# IP address
regx_ipv4 = r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})$'
regx_ipv6 = r'^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$'
regx_wildcard_ipv4 = r'(?:[\d\*]{1,3})\.(?:[\d\*]{1,3})\.(?:[\d\*]{1,3})\.(?:[\d\*]{1,3})$'

# Wildcard sender address: 'user@*'
regx_wildcard_addr = r'''[\w\-][\w\-\.\+\=]*@\*'''

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


def is_email(s):
    try:
        s = str(s).strip()
    except UnicodeEncodeError:
        return False

    # Not contain invalid characters and match regular expression
    if not set(s) & set(r'~!#$%^&*()\/ ') \
       and re.compile(regx_email + '$', re.IGNORECASE).match(s):
        return True

    return False


def is_domain(s):
    s = str(s)
    if len(set(s) & set('~!#$%^&*()+\\/\ ')) > 0 or '.' not in s:
        return False

    comp_domain = re.compile(regx_domain + '$', re.IGNORECASE)
    if comp_domain.match(s):
        return True
    else:
        return False


def is_tld_domain(s):
    s = str(s)

    comp_domain = re.compile(regx_top_level_domain + '$', re.IGNORECASE)
    if comp_domain.match(s):
        return True
    else:
        return False


# Valid IP address
def is_ipv4(s):
    if re.match(regx_ipv4, s):
        return True

    return False


def is_ipv6(s):
    if re.match(regx_ipv6, s):
        return True
    return False


def is_strict_ip(s):
    if is_ipv4(s):
        return True
    elif is_ipv6(s):
        return True

    return False


def is_wildcard_ipv4(s):
    if re.match(regx_wildcard_ipv4, s):
        return True

    return False


def is_wildcard_addr(s):
    if re.match(regx_wildcard_addr, s):
        return True

    return False


def is_valid_amavisd_address(addr):
    # Valid address format:
    #
    #   - email: single address. e.g. user@domain.ltd
    #   - domain: @domain.ltd
    #   - subdomain: entire domain and all sub-domains. e.g. @.domain.ltd
    #   - catch-all: catch all address. @.
    #   - ip: IPv4 or IPv6 address. Used in iRedAPD plugin `amavisd_wblist`
    #   - 'user@*': sender address with wildcard. used in wblist
    #
    # WARNING: don't forget to update MAILADDR_PRIORITIES above after you add
    #          a new address format.
    if addr.startswith(r'@.'):
        if addr == r'@.':
            return 'catchall'
        else:
            domain = addr.split(r'@.', 1)[-1]

            if is_domain(domain):
                return 'subdomain'
            elif is_tld_domain(domain):
                return 'top_level_domain'

    elif addr.startswith(r'@'):
        # entire domain
        domain = addr.split(r'@', 1)[-1]
        if is_domain(domain):
            return 'domain'

    elif is_email(addr):
        # single email address
        return 'email'

    elif is_wildcard_addr(addr):
        return 'wildcard_addr'

    elif is_strict_ip(addr):
        return 'ip'
    elif is_wildcard_ipv4(addr):
        return 'ip'

    return False


def get_db_conn(db):
    if db == 'ldap':
        from libs.ldap_auth import verify_bind_dn_pw
        qr = verify_bind_dn_pw(dn=settings.ldap_binddn,
                               password=settings.ldap_bindpw,
                               close_connection=False)
        if qr[0]:
            return qr[1]
        else:
            return None

    if settings.backend == 'pgsql':
        sql_dbn = 'postgres'
    else:
        sql_dbn = 'mysql'

    try:
        if db == 'vmail':
            conn = web.database(dbn=sql_dbn,
                                host=settings.__dict__['sql_server'],
                                port=int(settings.__dict__['sql_port']),
                                db=settings.__dict__['sql_db'],
                                user=settings.__dict__['sql_user'],
                                pw=settings.__dict__['sql_password'])
        else:
            conn = web.database(dbn=sql_dbn,
                                host=settings.__dict__[db + '_db_server'],
                                port=int(settings.__dict__[db + '_db_port']),
                                db=settings.__dict__[db + '_db_name'],
                                user=settings.__dict__[db + '_db_user'],
                                pw=settings.__dict__[db + '_db_password'])

        conn.supports_multiple_insert = True
        return conn
    except Exception, e:
        print 'Error while estiblishing SQL connection: ', e
