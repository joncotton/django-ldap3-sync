from django.db import models
from django.contrib.auth.models import User, Group


# Store LDAP info about the created groups so that we can easily
# identify them in subsequent syncs

HELP_TEXT = ('DO NOT edit this unless you really know '
            'what your doing. It is much safer to delete '
            'this entire record and let the sync command '
            'recreate it.')


class LDAPUser(models.Model):
    obj = models.OneToOneField(User, related_name='ldap_sync_user', verbose_name='User')
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


class LDAPGroup(models.Model):
    obj = models.OneToOneField(Group, related_name='ldap_sync_group', verbose_name='Group')
    distinguished_name = models.TextField(blank=True, help_text=HELP_TEXT)

    def __unicode__(self):
        return '{} ({})'.format(self.obj.name, self.distinguished_name)

    class Meta:
        verbose_name = 'LDAP Group'
        verbose_name_plural = 'LDAP Groups'
