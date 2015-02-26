django-ldap3-sync
================
django-ldap3-sync is a fork of [django-ldap-sync]("https://github.com/jbittel/django-ldap-sync", "django-ldap-sync") originally created by Jason Bittel.
django-ldap3-sync introduces the following features:
	- Uses the [ldap3 library]("https://github.com/cannatag/ldap3", "ldap3") for ldap communication. ldap3 is pure python and python 3 compatible.
	- Can synchronize group membership directly out of the ldap directory.
	- Can manage deletion of groups / users in the directory by suspending or deleting those objects in Django.
	- Will update existing Django users groups if information changes in the directory.

django-ldap3-sync provides a Django management command that synchronizes LDAP
users and groups from an authoritative server. It performs a one-way
synchronization that creates and/or updates the local Django users and groups.

This synchronization is performed each time the management command is run and
can be fired manually on demand, via an automatic cron script or as a periodic
`Celery`_ task.

Quickstart
----------

#. Install the application::

      pip install django-ldap3-sync

#. Append it to the installed apps::

      INSTALLED_APPS = (
          # ...
          'ldap3_sync',
      )

#. Configure the required `settings`_.

#. Run the synchronization management command::

      manage.py syncldap

For more information on installation and configuration, see the included
documentation or read the documentation online at
`django-ldap3-sync.readthedocs.org`_.

Configuration
-------------

### User Synchronization Options

**LDAP_SYNC_USER_FILTER** -- Required

Default: ""

The filter used to retrieve users from the directory. Should be in standard LDAP filter syntax as per [RFC2254]("http://www.ietf.org/rfc/rfc2254.txt?number=2254", "RFC 22545")

**LDAP_SYNC_USER_BASE**

Default: Will default to the value of LDAP_SYNC_BASE

The distinguished name of the container to base the search for ussers in.

**LDAP_SYNC_USER_ATTRIBUTES** -- Required

Default: ""

A dictionary of key value pairs where the keys are the names of ldap fields and the values are the names of corresponding django model fields. New users will be created with these fields populated and existing users will have these fields updated.

**LDAP_SYNC_USER_EXEMPT_FROM_SYNC**

Default: []

A list of usernames corresponding to Django users who should be excluded from the sync. Useful for Administrative users who do not have a corresponding user in the directory.

**LDAP_SYNC_USER_REMOVAL_ACTION**

Default: NOTHING

The action to take when a user no longer exists in the directory. Possible values are NOTHING, SUSPEND and DELETE. Note that the SUSPEND option uses the Django user models is_active field and sets it to false.


**LDAP_SYNC_USER_SET_UNUSABLE_PASSWORD**

Default: True

If true this uses the django method set_unusable_password on all newly created users. Useful where django authentication will not be used.

**LDAP_SYNC_USERS**

Default: True

Controls whether users should be synchronized from the directory.






**Common Options**


**LDAP_SYNC_URI**

Default: ""

The address of the LDAP server containing the authoritative user account information. This should be a string specifying the complete address::
	LDAP_SYNC_URI = "ldap://users.example.com:389"


**LDAP_SYNC_BIND_USER**

Default: ""

A user with appropriate permissions to connect to the LDAP server and retrieve user account information. This should be a string specifying the LDAP user account::
	LDAP_SYNC_BIND_USER = "CN=Django,OU=Users,DC=example,DC=com"


**LDAP_SYNC_BIND_PASS**

Default: ""

The corresponding password for the above user account. This should be a string specifying the password::
	LDAP_SYNC_BIND_PASS = "My super secret password"


**User Sync Options**


**LDAP_SYNC_USER_BASE**

Default: ""

The root of the LDAP tree to search for user account information. The contents of this tree can be further refined using the filtering settings. This should be a string specifying the complete root path::
	LDAP_SYNC_USER_BASE = "OU=Users,DC=example,DC=com"


**LDAP_SYNC_USER_FILTER**

Default: ""

An LDAP filter to further refine the user accounts to synchronize. This should be a string specifying a valid LDAP filter::
	LDAP_SYNC_USER_FILTER = "(&(objectCategory=person)(objectClass=User)(memberOf=CN=Web,OU=Users,DC=example,DC=com))"


**LDAP_SYNC_USER_ATTRIBUTES**

Default: {}

A dictionary mapping LDAP field names to User profile attributes. New users will be created with this data populated, and existing users will be updated as necessary. The mapping must at least contain a field mapping the User model’s username field::
	LDAP_SYNC_USER_ATTRIBUTES = {
	"sAMAccountName": "username",
	"givenName": "first_name",
	"sn": "last_name",
	"mail": "email",
	}


**LDAP_SYNC_USER_EXEMPT_FROM_REMOVAL**

Default: []

A list of usernames that will never be deleted from the Django authentication store::
	LDAP_SYNC_USER_EXEMPT_FROM_REMOVAL = ['admin', 'superadmin', 'webadmin']


**LDAP_SYNC_USER_REMOVAL_ACTION**

Default: 'nothing'

The action to take when deleting users from the Django store. Can take one of three values, 'nothing' which does nothing to the user, 'disable' which sets the User.is_active attribute to False and 'delete' which removes the user from the Django store.


**Group Sync Options**


**LDAP_SYNC_GROUP_BASE**

Default: ""

The root of the LDAP tree to search for group information. The contents of this tree can be further refined using the filtering settings. This should be a string specifying the complete root path::
	LDAP_SYNC_GROUP_BASE = "OU=Groups,DC=example,DC=com"


**LDAP_SYNC_GROUP_FILTER**

Default: ""

An LDAP filter to further refine the groups to synchronize. This should be a string specifying a valid LDAP filter::
	LDAP_SYNC_GROUP_FILTER = "(&(objectClass=group))"


**LDAP_SYNC_GROUP_ATTRIBUTES**

Default: {}

A dictionary mapping LDAP field names to Group attributes. New groups will be created with this data populated, and existing groups will be updated as necessary. The mapping must at least contain a field mapping the Groups name field::
	LDAP_SYNC_GROUP_ATTRIBUTES = {
	'name': 'name',
	}


**LDAP_SYNC_GROUP_EXEMPT_FROM_REMOVAL**

Default: []

A list of group names that will never be deleted from the Django authentication store::
	LDAP_SYNC_GROUP_EXEMPT_FROM_REMOVAL = ['administrators']


**LDAP_SYNC_GROUP_MEMBERSHIP**

Default: False

A boolean value that controls group membership synchronization. If True django users will be added to django groups based on their equivalent LDAP group membership. This feature will only work for users that are synchronized by django-sync-ldap.



.. _Celery: http://www.celeryproject.org
.. _settings: http://django-ldap3-sync.readthedocs.org/en/latest/settings.html
.. _django-ldap3-sync.readthedocs.org: http://django-ldap3-sync.readthedocs.org
