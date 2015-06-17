# wblistadm

A command line tool used to manage white/blacklists in [iRedMail server](http://www.iredmail.org/).

# Requirements

Below are required Python modules, if you have a working iRedMail server, they
are already installed by iRedMail.

* `psycopg2`: required by PostgreSQL backend.
* `mysqldb`: required by both MySQL and OpenLDAP backend.
* `ldap`: required by OpenLDAP backend.
* `webpy`: a simple web framework. [http://webpy.org/](http://webpy.org/)

# How to use

Copy iRedAdmin config file `settings.py` to this directory, then run:

```python
# python wblistadm.py [option]
```

# Available arguments

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

