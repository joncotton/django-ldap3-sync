from django.db import models
from django.conf import settings
from django.contrib.auth.models import Group

# Store LDAP info about the created groups so that we can easily
# identify them in subsequent syncs

HELP_TEXT = ('DO NOT edit this unless you really know '
             'what your doing. It is much safer to delete '
             'this entire record and let the sync command '
             'recreate it.')


class LDAPUser(models.Model):
    obj = models.OneToOneField(settings.AUTH_USER_MODEL, related_name='ldap_sync_user', verbose_name='User')
    # There does not appear to be a maximum length for distinguishedName
    # safest to use text to avoid any length issues down the track
    distinguished_name = models.TextField(blank=True, help_text=HELP_TEXT)

    def __unicode__(self):
        return '{} {} ({})'.format(self.obj.first_name,
                                   self.obj.last_name,
                                   self.distinguished_name)

    class Meta:
        verbose_name = 'LDAP User'
        verbose_name_plural = 'LDAP Users'

# Horrible Hack Incoming
# settings.AUTH_GROUP_MODEL isnt a django standard like settings.AUTH_USER_MODEL, assuming it will be present is probably wrong.
# I need to check and see if it is, just in case, and if not then use the standard django.contrib.auth.models.Group
if hasattr(settings, 'AUTH_GROUP_MODEL'):
    pre_obj = models.OneToOneField(settings.AUTH_GROUP_MODEL, related_name='ldap_sync_group', verbose_name='Group')
else:
    pre_obj = models.OneToOneField(Group, related_name='ldap_sync_group', verbose_name='Group')


class LDAPGroup(models.Model):
    obj = pre_obj
    distinguished_name = models.TextField(blank=True, help_text=HELP_TEXT)

    def __unicode__(self):
        return '{} ({})'.format(self.obj.name, self.distinguished_name)

    class Meta:
        verbose_name = 'LDAP Group'
        verbose_name_plural = 'LDAP Groups'
