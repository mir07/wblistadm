# wblistadm
administrate wblist in iRedMail

Requires the following python modules:

* psycopg2
* mysqldb
* ldap
* web (webpy)

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
    -l | --list
        If recipient is listed only list for this recipient.
    -r | --recipient
        Recipient can be global, domain, or user.
        If recipient is not listed recipient will be global.
    -w | --whitelist sender
        Whitelist specified sender. Multiple senders must be separated by a space
        and the entire list must be enclosed in " or '.
    
    blacklist and whitelist option is mutual exclusive.
    Unless option delete or list is present the implied action is add.

