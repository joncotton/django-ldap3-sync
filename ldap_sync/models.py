from django.db import models
from django.contrib.auth.models import User, Group


# Store LDAP info about the created groups so that we can easily
# identify them in subsequent syncs


class LDAPUser(models.Model):
    user = models.OneToOneField(User, related_name='ldap_user')
    # There does not appear to be a maximum length for distinguishedName
    # safest to use text to avoid any length issues down the track
    distinguishedName = models.TextField(blank=True)


class LDAPGroup(models.Model):
    group = models.OneToOneField(Group, related_name='ldap_group')
    distinguishedName = models.TextField(blank=True)
