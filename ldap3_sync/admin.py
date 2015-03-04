from django.contrib import admin
from ldap3_sync.models import LDAPUser, LDAPGroup

# Only providing these so that if something odd happens
# They can be deleted from the admin interface


class LDAPUserAdmin(admin.ModelAdmin):
    model = LDAPUser
    ordering = ['obj__username']
    fields = ['distinguishedName']
    search_fields = ['obj__username', 'obj__first_name',
                     'obj__last_name', 'distinguishedName']


class LDAPGroupAdmin(admin.ModelAdmin):
    model = LDAPGroup
    ordering = ['obj__name']
    fields = ['distinguishedName']
    search_fields = ['obj__name', 'distinguishedName']


admin.site.register(LDAPUser, LDAPUserAdmin)
admin.site.register(LDAPGroup, LDAPGroupAdmin)
