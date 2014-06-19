import logging

import ldap
from ldap.ldapobject import LDAPObject
from ldap.controls import SimplePagedResultsControl

from django.conf import settings
from django.core.management.base import NoArgsCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, DataError


logger = logging.getLogger(__name__)


class Command(NoArgsCommand):
    help = "Synchronize users and groups from an authoritative LDAP server"

    def handle_noargs(self, **options):
        ldap_groups = self.get_ldap_groups()
        if ldap_groups:
            self.sync_ldap_groups(ldap_groups)

        ldap_users = self.get_ldap_users()
        if ldap_users:
            self.sync_ldap_users(ldap_users)

    def get_ldap_users(self):
        """
        Retrieve user data from target LDAP server.
        """
        user_filter = getattr(settings, 'LDAP_SYNC_USER_FILTER', None)
        if not user_filter:
            msg = "LDAP_SYNC_USER_FILTER not configured, skipping user sync"
            logger.info(msg)
            return None

        user_base = getattr(settings, 'LDAP_SYNC_USER_BASE', None)
        if not user_base:
            error_msg = ("LDAP_SYNC_USER_BASE must be specified in your Django "
                         "settings file")
            raise ImproperlyConfigured(error_msg)

        attributes = getattr(settings, 'LDAP_SYNC_USER_ATTRIBUTES', None)
        if not attributes:
            error_msg = ("LDAP_SYNC_USER_ATTRIBUTES must be specified in "
                         "your Django settings file")
            raise ImproperlyConfigured(error_msg)
        user_attributes = attributes.keys()

        users = self.ldap_search(user_filter, user_attributes, user_base)
        msg = "Retrieved {} LDAP users".format(len(users))
        self.stdout.write(msg)
        logger.debug(msg)
        return users

    def sync_ldap_users(self, ldap_users):
        """
        Synchronize users with local user database.
        """
        model = get_user_model()
        username_field = getattr(model, 'USERNAME_FIELD', 'username')
        attributes = getattr(settings, 'LDAP_SYNC_USER_ATTRIBUTES', None)

        # Do this first
        if username_field not in attributes.values():
            error_msg = ("LDAP_SYNC_USER_ATTRIBUTES must contain the "
                         "username field '%s'" % username_field)
            raise ImproperlyConfigured(error_msg)

        # simulates django in_bulk but works with larger sets of objects
        existing_users = dict([(getattr(u, username_field), u)
                              for u in model.objects.all()])
        msg = 'Found {} existing django users'.format(len(existing_users))
        self.stdout.write(msg)
        logger.info(msg)
        logger.debug('Existing django users: {}'.format(existing_users.keys()))

        unsaved_users = []

        updated_users_count = 0

        for cname, attrs in ldap_users:
            # In some cases with AD, attrs is a list instead of a
            # dict; these are not valid users, so skip them
            try:
                items = attrs.items()
            except AttributeError:
                continue

            # Extract user attributes from LDAP response
            user_attr = {}
            for name, attr in items:
                user_attr[attributes[name]] = attr[0].decode('utf-8')

            try:
                username = user_attr[username_field]
                user_attr[username_field] = username.lower()
            except KeyError:
                logger.warning("User is missing a required attribute '%s'" %
                               username_field)
                continue

            # kwargs = {
            #     username_field + '__iexact': username,
            #     'defaults': user_attr,
            # }
            if user_attr[username_field] in existing_users:
                this_local_user = existing_users[user_attr[username_field]]
                if self.will_user_change(user_attr, this_local_user):
                    this_updated_local_user = self.apply_updated_attrs(user_attr, this_local_user)
                    this_updated_local_user.save()
                    updated_users_count += 1
                # Regardless of it the user is updated or not, remove from existing users
                del(existing_users[user_attr[username_field]])
            else:
                new_user = model(**user_attr)
                unsaved_users.append(new_user)
        model.objects.bulk_create(unsaved_users)
        
        msg = 'Updated {} existing django users'.format(updated_users_count)
        self.stdout.write(msg)
        logger.info(msg)

        msg = 'Created {} new django users'.format(len(unsaved_users))
        self.stdout.write(msg)
        logger.info(msg)

        # Anything left in the existing_users dict is no longer in the ldap directory
        # These should be disabled.
        exempt_users = getattr(settings, 'LDAP_SYNC_USER_EXEMPT_FROM_REMOVAL', [])
        removal_action = getattr(settings, 'LDAP_SYNC_USER_REMOVAL_ACTION', 'nothing')

        existing_user_ids = set([getattr(i, username_field) for i in existing_users.values()])
        existing_user_ids.difference_update(exempt_users)

        if removal_action != 'nothing' and len(existing_users) > 0:
            if removal_action == 'disable':
                model.objects.filter(username__in=existing_user_ids).update(is_active=False)
                msg = 'Disabling {} django users'.format(len(existing_user_ids))
                logger.info(msg)
                self.stdout.write(msg)
                logger.debug('Disabling django users: {}'.format(existing_user_ids))
            if removal_action == 'delete':
                # There are going to be issues here if there are more than 999 exiting user ids
                model.objects.filter(username__in=existing_user_ids).delete()
                msg = 'Deleting {} django users'.format(len(existing_user_ids))
                logger.info(msg)
                self.stdout.write(msg)
                logger.debug('Deleting django users: {}'.format(existing_user_ids))
        else:
            if len(existing_user_ids) > 0:
                msg = '{} django users no longer exist in the LDAP store but are being ignored as LDAP_SYNC_USER_REMOVAL_ACTION = \'nothing\''.format(len(existing_user_ids))
                self.stdout.write(msg)
                logger.warn(msg)

        logger.info("Users are synchronized")
        self.stdout.write('Users are synchronized')

    def get_ldap_groups(self):
        """
        Retrieve groups from target LDAP server.
        """
        group_filter = getattr(settings, 'LDAP_SYNC_GROUP_FILTER', None)
        if not group_filter:
            msg = "LDAP_SYNC_GROUP_FILTER not configured, skipping group sync"
            logger.info(msg)
            return None

        group_base = getattr(settings, 'LDAP_SYNC_GROUP_BASE', None)
        if not group_base:
            error_msg = ("LDAP_SYNC_GROUP_BASE must be specified in your Django "
                         "settings file")
            raise ImproperlyConfigured(error_msg)

        attributes = getattr(settings, 'LDAP_SYNC_GROUP_ATTRIBUTES', None)
        if not attributes:
            error_msg = ("LDAP_SYNC_GROUP_ATTRIBUTES must be specified in "
                         "your Django settings file")
            raise ImproperlyConfigured(error_msg)
        group_attributes = attributes.keys()

        groups = self.ldap_search(group_filter, group_attributes, group_base)
        logger.debug("Retrieved %d groups" % len(groups))
        return groups

    def sync_ldap_groups(self, ldap_groups):
        """
        Synchronize LDAP groups with local group database.
        """
        attributes = getattr(settings, 'LDAP_SYNC_GROUP_ATTRIBUTES', None)
        groupname_field = 'name'

        if groupname_field not in attributes.values():
            error_msg = ("LDAP_SYNC_GROUP_ATTRIBUTES must contain the "
                         "group name field '%s'" % groupname_field)
            raise ImproperlyConfigured(error_msg)

        for cname, attrs in ldap_groups:
            # In some cases with AD, attrs is a list instead of a
            # dict; these are not valid groups, so skip them
            try:
                items = attrs.items()
            except AttributeError:
                continue

            # Extract user data from LDAP response
            group_attr = {}
            for name, attr in items:
                group_attr[attributes[name]] = attr[0].decode('utf-8')

            try:
                groupname = group_attr[groupname_field]
                group_attr[groupname_field] = groupname.lower()
            except KeyError:
                logger.warning("Group is missing a required attribute '%s'" %
                               groupname_field)
                continue

            kwargs = {
                groupname_field + '__iexact': groupname,
                'defaults': group_attr,
            }

            # Create or update group data in the local database
            try:
                group, created = Group.objects.get_or_create(**kwargs)
            except IntegrityError as e:
                logger.error("Error creating group %s" % e)
            else:
                if created:
                    logger.debug("Created group %s" % groupname)

        logger.info("Groups are synchronized")

    def ldap_search(self, filter, attributes, base):
        """
        Query the configured LDAP server with the provided search
        filter and attribute list. Returns a list of the results
        returned.
        """
        uri = getattr(settings, 'LDAP_SYNC_URI', None)
        if not uri:
            error_msg = ("LDAP_SYNC_URI must be specified in your Django "
                         "settings file")
            raise ImproperlyConfigured(error_msg)

        bind_user = getattr(settings, 'LDAP_SYNC_BIND_USER', None)
        if not bind_user:
            error_msg = ("LDAP_SYNC_BIND_USER must be specified in your "
                         "Django settings file")
            raise ImproperlyConfigured(error_msg)

        bind_pass = getattr(settings, 'LDAP_SYNC_BIND_PASS', None)
        if not bind_pass:
            error_msg = ("LDAP_SYNC_BIND_PASS must be specified in your "
                         "Django settings file")
            raise ImproperlyConfigured(error_msg)

        # base = getattr(settings, 'LDAP_SYNC_BASE', None)
        # if not base:
        #     error_msg = ("LDAP_SYNC_BASE must be specified in your Django "
        #                  "settings file")
        #     raise ImproperlyConfigured(error_msg)

        ldap.set_option(ldap.OPT_REFERRALS, 0)
        l = PagedLDAPObject(uri)
        l.protocol_version = 3
        try:
            l.simple_bind_s(bind_user, bind_pass)
        except ldap.LDAPError:
            logger.error("Error connecting to LDAP server %s" % uri)
            raise

        results = l.paged_search_ext_s(base,
                                       ldap.SCOPE_SUBTREE,
                                       filter,
                                       attrlist=attributes,
                                       serverctrls=None)
        l.unbind_s()
        return results

    def will_user_change(self, ldap_attrs, local_user):
        '''
        Return true if the data in the ldap_user would change the data stored
        in the local_user, otherwise false.
        '''
        # I think all the attrs are utf-8 strings, possibly need to coerce
        # local user values to strings?
        for key, value in ldap_attrs.items():
            if not getattr(local_user, key) == value:
                return True
        return False

    def apply_updated_attrs(self, ldap_attrs, local_user):
        for key, value in ldap_attrs.items():
            setattr(local_user, key, value)
        return local_user



class PagedResultsSearchObject:
    """
    Taken from the python-ldap paged_search_ext_s.py demo, showing how to use
    the paged results control: https://bitbucket.org/jaraco/python-ldap/
    """
    page_size = getattr(settings, 'LDAP_SYNC_PAGE_SIZE', 100)

    def paged_search_ext_s(self, base, scope, filterstr='(objectClass=*)',
                           attrlist=None, attrsonly=0, serverctrls=None,
                           clientctrls=None, timeout=-1, sizelimit=0):
        """
        Behaves exactly like LDAPObject.search_ext_s() but internally uses the
        simple paged results control to retrieve search results in chunks.
        """
        req_ctrl = SimplePagedResultsControl(True, size=self.page_size,
                                             cookie='')

        # Send first search request
        msgid = self.search_ext(base, ldap.SCOPE_SUBTREE, filterstr,
                                attrlist=attrlist,
                                serverctrls=(serverctrls or []) + [req_ctrl])
        results = []

        while True:
            rtype, rdata, rmsgid, rctrls = self.result3(msgid)
            results.extend(rdata)
            # Extract the simple paged results response control
            pctrls = [c for c in rctrls if c.controlType ==
                      SimplePagedResultsControl.controlType]

            if pctrls:
                if pctrls[0].cookie:
                    # Copy cookie from response control to request control
                    req_ctrl.cookie = pctrls[0].cookie
                    msgid = self.search_ext(base, ldap.SCOPE_SUBTREE,
                                            filterstr, attrlist=attrlist,
                                            serverctrls=(serverctrls or []) +
                                            [req_ctrl])
                else:
                    break

        return results


class PagedLDAPObject(LDAPObject, PagedResultsSearchObject):
    pass
