import ldap
import web
import settings
from libs import iredpwd

# Verify bind dn/pw or return LDAP connection object
# Return True if bind success, error message (string) if failed
def verify_bind_dn_pw(dn, password, close_connection=True):
    dn = web.safestr(dn.strip())
    password = password.strip()

    uri = settings.ldap_uri

    # Detect STARTTLS support.
    starttls = False
    if uri.startswith('ldaps://'):
        starttls = True

        # Rebuild uri, use ldap:// + STARTTLS (with normal port 389)
        # instead of ldaps:// (port 636) for secure connection.
        uri = uri.replace('ldaps://', 'ldap://')

        # Don't check CA cert
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    conn = ldap.initialize(uri)

    # Set LDAP protocol version: LDAP v3.
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)

    if starttls:
        conn.start_tls_s()

    try:
        # bind as vmailadmin
        conn.bind_s(settings.ldap_bind_dn, settings.ldap_bind_password)
        qr = conn.search_s(dn,
                           ldap.SCOPE_BASE,
                           '(objectClass=*)',
                           ['userPassword'])
        if not qr:
            return (False, 'INVALID_CREDENTIALS')

        entries = qr[0][1]
        qr_password = entries.get('userPassword', [''])[0]
        if iredpwd.verify_password_hash(qr_password, password):
            if close_connection:
                conn.unbind_s()
                return (True, )
            else:
                # Return connection
                return (True, conn)
        else:
            return (False, 'INVALID_CREDENTIALS')
    except Exception, e:
        return (False, str(e))
