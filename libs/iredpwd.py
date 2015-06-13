# Author: Zhang Huangbin <zhb@iredmail.org>

from os import urandom
import string
import random
import subprocess
from base64 import b64encode, b64decode
from libs import iredutils, md5crypt
import settings


def __has_non_ascii_character(s):
    for i in s:
        try:
            if not (32 <= ord(i) <= 126):
                return True
        except TypeError:
            # ord() will raise TypeError for non-ascii character (or syntax error)
            return True

    return False


def verify_new_password(newpw,
                        confirmpw,
                        min_passwd_length=None,
                        max_passwd_length=None):
    # Confirm password
    if newpw == confirmpw:
        passwd = newpw
    else:
        return (False, 'PW_MISMATCH')

    # Cannot contain non-ascii character
    if __has_non_ascii_character(passwd):
        return (False, 'PW_NON_ASCII')

    # Empty password is not allowed.
    if not passwd:
        return (False, 'PW_EMPTY')

    # Get and verify password length
    if not min_passwd_length or not isinstance(min_passwd_length, int):
        min_passwd_length = settings.min_passwd_length

    if not max_passwd_length or not isinstance(max_passwd_length, int):
        max_passwd_length = settings.max_passwd_length

    if not len(passwd) >= min_passwd_length:
        return (False, 'PW_LESS_THAN_MIN_LENGTH')

    if max_passwd_length > 0:
        if not len(passwd) <= max_passwd_length:
            return (False, 'PW_GREATER_THAN_MAX_LENGTH')

    # Password restriction rules
    if settings.PASSWORD_HAS_LETTER:
        if not set(newpw) & set(string.ascii_letters):
            return (False, 'PW_NO_LETTER')

    if settings.PASSWORD_HAS_UPPERCASE:
        if not set(newpw) & set(string.ascii_uppercase):
            return (False, 'PW_NO_UPPERCASE')

    if settings.PASSWORD_HAS_NUMBER:
        if not set(newpw) & set(string.digits):
            return (False, 'PW_NO_DIGIT_NUMBER')

    if settings.PASSWORD_HAS_SPECIAL_CHAR:
        if not set(newpw) & set(settings.PASSWORD_SPECIAL_CHARACTERS):
            return (False, 'PW_NO_SPECIAL_CHAR')

    return (True, passwd)


def generate_random_password(length=10):
    length = int(length)
    if length < settings.min_passwd_length:
        length = settings.min_passwd_length

    numbers = '23456789'                        # No 0, 1
    letters = 'abcdefghjkmnpqrstuvwxyz'         # no i, l
    uppercases = 'ABCDEFGHJKLMNPQRSTUVWXYZ'     # no I

    opts = []
    if settings.PASSWORD_HAS_LETTER:
        opts += random.choice(letters)
        length -= 1

    if settings.PASSWORD_HAS_UPPERCASE:
        opts += random.choice(uppercases)
        length -= 1

    if settings.PASSWORD_HAS_NUMBER:
        opts += random.choice(numbers)
        length -= 1

    if settings.PASSWORD_HAS_SPECIAL_CHAR and settings.PASSWORD_SPECIAL_CHARACTERS:
        opts += random.choice(settings.PASSWORD_SPECIAL_CHARACTERS)
        length -= 1

    opts += list(iredutils.generate_random_strings(length))

    password = ''
    for i in range(len(opts)):
        one = random.choice(opts)
        password += one
        opts.remove(one)

    return password


def generate_bcrypt_password(p):
    try:
        import bcrypt
    except:
        return generate_ssha_password(p)

    return '{CRYPT}' + bcrypt.hashpw(p, bcrypt.gensalt())


def verify_bcrypt_password(challenge_password, plain_password):
    try:
        import bcrypt
    except:
        return False

    if challenge_password.startswith('{CRYPT}$2a$') \
       or challenge_password.startswith('{CRYPT}$2b$') \
       or challenge_password.startswith('{crypt}$2a$') \
       or challenge_password.startswith('{crypt}$2b$'):
        challenge_password = challenge_password[7:]

    return bcrypt.checkpw(plain_password, challenge_password)


def generate_md5_password(p):
    p = str(p).strip()
    return md5crypt.unix_md5_crypt(p, iredutils.generate_random_strings(length=8))


def verify_md5_password(challenge_password, plain_password):
    """Verify salted MD5 password"""
    if challenge_password.startswith('{MD5}') or challenge_password.startswith('{md5}'):
        challenge_password = challenge_password[5:]
    elif challenge_password.startswith('{CRYPT}') or challenge_password.startswith('{crypt}'):
        challenge_password = challenge_password[7:]

    if not (challenge_password.startswith('$')
            and len(challenge_password) == 34
            and challenge_password.count('$') == 3):
        return False

    # Get salt from hashed string
    salt = '$'.join(challenge_password.split('$')[:3])

    if md5crypt.md5crypt(plain_password, salt) == challenge_password:
        return True

    return False


def generate_plain_md5_password(p):
    p = str(p).strip()
    try:
        from hashlib import md5
        return md5(p).hexdigest()
    except ImportError:
        import md5
        return md5.new(p).hexdigest()

    return p


def verify_plain_md5_password(challenge_password, plain_password):
    if challenge_password.startswith('{PLAIN-MD5}') \
       or challenge_password.startswith('{plain-md5}'):
        challenge_password = challenge_password[11:]

    if challenge_password == generate_plain_md5_password(plain_password):
        return True
    else:
        return False


def generate_ssha_password(p):
    p = str(p).strip()
    salt = urandom(8)
    try:
        from hashlib import sha1
        pw = sha1(p)
    except ImportError:
        import sha
        pw = sha.new(p)
    pw.update(salt)
    return '{SSHA}' + b64encode(pw.digest() + salt)


def verify_ssha_password(challenge_password, plain_password):
    """Verify SHA or SSHA (salted SHA) hash with or without prefix {SHA}, {SSHA}"""
    if challenge_password.startswith('{SSHA}') \
       or challenge_password.startswith('{ssha}'):
        challenge_password = challenge_password[6:]
    elif challenge_password.startswith('{SHA}') or challenge_password.startswith('{sha}'):
        challenge_password = challenge_password[5:]

    if not len(challenge_password) > 20:
        # Not a valid SSHA hash
        return False

    try:
        challenge_bytes = b64decode(challenge_password)
        digest = challenge_bytes[:20]
        salt = challenge_bytes[20:]
        try:
            from hashlib import sha1
            hr = sha1(plain_password)
        except ImportError:
            import sha
            hr = sha.new(plain_password)
        hr.update(salt)
        return digest == hr.digest()
    except:
        return False


def generate_ssha512_password(p):
    """Generate salted SHA512 password with prefix '{SSHA512}'.
    Return SSHA instead if python is older than 2.5 (not supported in module hashlib)."""
    p = str(p).strip()
    try:
        from hashlib import sha512
        salt = urandom(8)
        pw = sha512(p)
        pw.update(salt)
        return '{SSHA512}' + b64encode(pw.digest() + salt)
    except ImportError:
        # Use SSHA password instead if python is older than 2.5.
        return generate_ssha_password(p)


def verify_ssha512_password(challenge_password, plain_password):
    """Verify SSHA512 password with or without prefix '{SSHA512}'.
    Python-2.5 is required since it requires module hashlib."""
    if challenge_password.startswith('{SSHA512}') \
       or challenge_password.startswith('{ssha512}'):
        challenge_password = challenge_password[9:]

    # With SSHA512, hash itself is 64 bytes (512 bits/8 bits per byte),
    # everything after that 64 bytes is the salt.
    if not len(challenge_password) > 64:
        return False

    try:
        challenge_bytes = b64decode(challenge_password)
        digest = challenge_bytes[:64]
        salt = challenge_bytes[64:]

        from hashlib import sha512
        hr = sha512(plain_password)
        hr.update(salt)

        return digest == hr.digest()
    except:
        return False


def generate_password_with_doveadmpw(scheme, plain_password):
    """Generate password hash with `doveadm pw` command.
    Return SSHA instead if no 'doveadm' command found or other error raised."""
    # scheme: CRAM-MD5, NTLM
    scheme = scheme.upper()
    p = str(plain_password).strip()

    try:
        pp = subprocess.Popen(['doveadm', 'pw', '-s', scheme, '-p', p],
                              stdout=subprocess.PIPE)
        pw = pp.communicate()[0]

        if scheme in settings.HASHES_WITHOUT_PREFIXED_PASSWORD_SCHEME:
            pw = pw.lstrip('{' + scheme + '}')

        # remove '\n'
        pw = pw.strip()

        return pw
    except:
        return generate_ssha_password(p)


def verify_password_with_doveadmpw(challenge_password, plain_password):
    """Verify password hash with `doveadm pw` command."""
    try:
        exit_status = subprocess.call(['doveadm',
                                      'pw',
                                      '-t',
                                      challenge_password,
                                      '-p',
                                      plain_password])
        if exit_status == 0:
            return True
    except:
        pass

    return False


def generate_cram_md5_password(p):
    return generate_password_with_doveadmpw('CRAM-MD5', p)


def verify_cram_md5_password(challenge_password, plain_password):
    """Verify CRAM-MD5 hash with 'doveadm pw' command."""
    if not (challenge_password.startswith('{CRAM-MD5}') or challenge_password.startswith('{cram-md5}')):
        return False

    return verify_password_with_doveadmpw(challenge_password, plain_password)


def generate_ntlm_password(p):
    return generate_password_with_doveadmpw('NTLM', p)


def verify_ntlm_password(challenge_password, plain_password):
    """Verify NTLM hash with 'doveadm pw' command."""
    if not 'NTLM' in settings.HASHES_WITHOUT_PREFIXED_PASSWORD_SCHEME:
        if not (challenge_password.startswith('{NTLM}') or challenge_password.startswith('{ntlm}')):
            # Prefix '{NTLM}' so that doveadm can verify it.
            challenge_password = '{NTLM}' + challenge_password
    else:
        if not (challenge_password.startswith('{NTLM}') or challenge_password.startswith('{ntlm}')):
            return False

    return verify_password_with_doveadmpw(challenge_password, plain_password)


def generate_password_hash(p, pwscheme=None):
    """Generate password for LDAP mail user and admin."""
    p = str(p).strip()

    if not pwscheme:
        pwscheme = settings.DEFAULT_PASSWORD_SCHEME

    # Supports returning multiple passwords.
    pw_schemes = pwscheme.split('+')
    pws = []

    for scheme in pw_schemes:
        if scheme == 'BCRYPT':
            pws.append(generate_bcrypt_password(p))
        elif scheme == 'SSHA512':
            pws.append(generate_ssha512_password(p))
        elif scheme == 'SSHA':
            pws.append(generate_ssha_password(p))
        elif scheme == 'MD5':
            pws.append('{CRYPT}' + generate_md5_password(p))
        elif scheme == 'CRAM-MD5':
            pws.append(generate_cram_md5_password(p))
        elif scheme == 'PLAIN-MD5':
            pws.append(generate_plain_md5_password(p))
        elif scheme == 'NTLM':
            pws.append(generate_ntlm_password(p))
        elif scheme == 'PLAIN':
            if 'PLAIN' in settings.HASHES_WITHOUT_PREFIXED_PASSWORD_SCHEME:
                pws.append(p)
            else:
                pws.append('{PLAIN}' + p)
        else:
            # Plain password
            pws.append(p)

    if len(pws) == 1:
        return pws[0]
    else:
        return pws


def verify_password_hash(challenge_password, plain_password):
    # Check plain password and MD5 first.
    if challenge_password in [plain_password,
                              '{PLAIN}' + plain_password,
                              '{plain}' + plain_password]:
        return True
    elif verify_md5_password(challenge_password, plain_password):
        return True

    upwd = challenge_password.upper()
    if upwd.startswith('{SSHA}') or upwd.startswith('{SHA}'):
        return verify_ssha_password(challenge_password, plain_password)
    elif upwd.startswith('{SSHA512}'):
        return verify_ssha512_password(challenge_password, plain_password)
    elif upwd.startswith('{CRYPT}$2A$') or upwd.startswith('{CRYPT}$2B$'):
        return verify_bcrypt_password(challenge_password, plain_password)
    elif upwd.startswith('{PLAIN-MD5}'):
        return verify_plain_md5_password(challenge_password, plain_password)
    elif upwd.startswith('{CRAM-MD5}'):
        return verify_cram_md5_password(challenge_password, plain_password)
    elif upwd.startswith('{NTLM}'):
        return verify_ntlm_password(challenge_password, plain_password)

    return False
