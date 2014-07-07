from django.contrib import admin
from ldap_sync.models import LDAPUser, LDAPGroup

# Only providing these so that if something odd happens
# They can be deleted from the admin interface


class LDAPUserAdmin(admin.ModelAdmin):
    model = LDAPUser
    ordering = ['user__username']
    fields = ['distinguishedName']
    search_fields = ['user__username', 'user__first_name',
                     'user__last_name', 'distinguishedName']


class LDAPGroupAdmin(admin.ModelAdmin):
    model = LDAPGroup
    ordering = ['group__name']
    fields = ['distinguishedName']
    search_fields = ['group__name', 'distinguishedName']


admin.site.register(LDAPUser, LDAPUserAdmin)
admin.site.register(LDAPGroup, LDAPGroupAdmin)
