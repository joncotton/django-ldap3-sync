import logging


import ldap3
from ldap3.core.exceptions import LDAPExceptionError, LDAPCommunicationError

from django.conf import settings
from django.core.management.base import NoArgsCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, DataError
from ldap_sync.models import LDAPUser, LDAPGroup


logger = logging.getLogger(__name__)

NOTHING = 'NOTHING'
SUSPEND = 'SUSPEND'
DELETE = 'DELETE'

USER_REMOVAL_OPTIONS = (NOTHING, SUSPEND, DELETE)
GROUP_REMOVAL_OPTIONS = (NOTHING, DELETE)


class Command(NoArgsCommand):
    help = "Synchronize users, groups and group membership from an LDAP server"

    def handle_noargs(self, **options):
        self.load_settings()
        self.sync_ldap_users()
        self.sync_ldap_groups()

        # ldap_groups = self.get_ldap_groups()
        # if ldap_groups:
        #     self.sync_ldap_groups(ldap_groups)

    def get_ldap_users(self):
        """
        Retrieve user data from target LDAP server.
        """
        logging.debug('Retrieving Users from LDAP')
        users = self.smart_ldap_searcher.search(self.user_base, self.user_filter, ldap3.SEARCH_SCOPE_WHOLE_SUBTREE, self.user_ldap_attribute_names)
        logger.info("Retrieved {} LDAP users".format(len(users)))
        return users

    def sync_ldap_users(self):
        """
        Synchronize users with local user database.
        """
        ldap_users = self.get_ldap_users()
        django_users = self.get_django_users()

        self.sync_generic(ldap_objects=ldap_users,
                          django_objects=django_users,
                          attribute_map=self.user_attribute_map,
                          django_object_model=self.user_model,
                          unique_name_field='username',
                          ldap_sync_model=LDAPUser,
                          ldap_sync_related_name='ldap_sync_user',
                          exempt_unique_names=self.exempt_usernames,
                          removal_action=self.user_removal_action)
        # ldap_users = self.get_ldap_users()
        # if len(ldap_users) == 0:
        #     raise SyncError('No users were returned from the LDAP search')

        # existing_users = self.get_django_users()

        # unsaved_user_models = []
        # username_dn_map = {}

        # updated_users_count = 0

        # for ldap_user in ldap_users:
        #     try:
        #         value_map = self.generate_value_map(self.user_attribute_map, ldap_user['attributes'])
        #     except MissingLdapField as e:
        #         logger.error('LDAP User {} is missing a field: {}'.format(ldap_user['dn'], e))
        #         continue
        #     username = value_map[self.username_field]
        #     distinguished_name = ldap_user['dn']

        #     username_dn_map[username] = distinguished_name

        #     try:
        #         local_user = existing_users[username]
        #         if self.will_model_change(value_map, local_user):
        #             self.apply_value_map(value_map, local_user)
        #             local_user.save()
        #             updated_users_count += 1
        #         try:
        #             if local_user.ldap_sync_user.distinguished_name != distinguished_name:
        #                 local_user.ldap_sync_user.distinguished_name = distinguished_name
        #                 local_user.ldap_sync_user.save()
        #         except LDAPUser.DoesNotExist:
        #             LDAPUser(obj=local_user, distinguished_name=distinguished_name).save()
        #         del(existing_users[username])
        #     except KeyError:
        #         local_user = self.user_model(**value_map)
        #         local_user.set_unusable_password()
        #         unsaved_user_models.append(local_user)
        # logger.debug('Bulk creating unsaved users')
        # self.user_model.objects.bulk_create(unsaved_user_models)
        # logger.debug('Retreiving just saved users for ID\'s')
        # just_saved_user_models = self.user_model.objects.filter(username__in=[u.username for u in unsaved_user_models]).all()
        # logger.debug('Bulk creating LDAPUser models')
        # LDAPUser.objects.bulk_create([LDAPUser(obj=u, distinguished_name=username_dn_map[u.username]) for u in just_saved_user_models])

        # msg = 'Updated {} existing django users'.format(updated_users_count)
        # self.stdout.write(msg)
        # logger.info(msg)

        # msg = 'Created {} new django users'.format(len(unsaved_user_models))
        # self.stdout.write(msg)
        # logger.info(msg)

        # # Anything left in the existing_users dict is no longer in the ldap directory
        # # These should be disabled.
        # existing_user_usernames = set(_username for _username in existing_users.keys())
        # existing_user_usernames.difference_update(self.exempt_usernames)
        # existing_user_ids = [e.id for e in existing_users.values() if getattr(e, self.username_field) in existing_user_usernames]

        # if self.user_removal_action == NOTHING:
        #     logger.info('LDAP_SYNC_USER_REMOVAL_ACTION is NOTHING so the {} users that would have been removed are being ignored.'.format(len(existing_user_usernames)))
        # elif self.user_removal_action == SUSPEND:
        #     self.user_model.objects.in_bulk(existing_user_ids).update(is_active=False)
        #     logger.info('Suspended {} users.'.format(len(existing_user_ids)))
        # elif self.user_removal_action == DELETE:
        #     self.user_model.objects.in_bulk(existing_user_ids).all().delete()
        #     logger.info('Deleted {} users.'.format(len(existing_user_usernames)))

        # logger.info("Users are synchronized")
        # self.stdout.write('Users are synchronized')


    def get_ldap_groups(self):
        """
        Retrieve groups from target LDAP server.
        """
        logger.debug('Retrieving Groups from LDAP')
        groups = self.smart_ldap_searcher.search(self.group_base, self.group_filter, ldap3.SEARCH_SCOPE_WHOLE_SUBTREE, self.group_ldap_attribute_names)
        logger.info('Rerieved {} LDAP Groups'.format(len(groups)))
        return groups

    def get_ldap_group_membership(self, group_dn):
        '''
        Retrieve a list of user DN's that are members of a particular group.
        '''
        logger.debug('Retrieving members for group with DN {}'.format(group_dn))
        members = self.smart_ldap_searcher.search(self.user_base, self.membership_filter.format(dn=group_dn))
        logger.debug('Retrieved {} members for group with DN {}'.format(len(members), group_dn))
        return members

    def sync_ldap_groups(self):
        """
        Synchronize LDAP groups with local group database.
        """
        ldap_groups = self.get_ldap_groups()
        django_groups = self.get_django_groups()

        self.sync_generic(ldap_objects=ldap_groups,
                          django_objects=django_groups,
                          attribute_map=self.group_attribute_map,
                          django_object_model=Group,
                          unique_name_field='name',
                          ldap_sync_model=LDAPGroup,
                          ldap_sync_related_name='ldap_sync_group',
                          exempt_unique_names=self.exempt_groupnames,
                          removal_action=self.group_removal_action)

    def sync_generic(self,
                     ldap_objects,
                     django_objects,
                     attribute_map,
                     django_object_model,
                     unique_name_field,
                     ldap_sync_model,
                     ldap_sync_related_name,
                     exempt_unique_names=[],
                     removal_action=NOTHING):
        """
        A generic synchronization method.
        """
        model_name = django_object_model.__name__

        unsaved_models = []
        model_dn_map = {}

        updated_model_count = 0

        for ldap_object in ldap_objects:
            try:
                value_map = self.generate_value_map(attribute_map, ldap_object['attributes'])
            except MissingLdapField as e:
                logger.error('LDAP Object {} is missing a field: {}'.format(ldap_object['dn'], e))
                continue
            unique_name = value_map[unique_name_field]
            distinguished_name = ldap_object['dn']

            model_dn_map[unique_name] = distinguished_name

            try:
                django_object = django_objects[unique_name]
                if self.will_model_change(value_map, django_object):
                    self.apply_value_map(value_map, django_object)
                    django_object.save()
                    updated_model_count += 1
                try:
                    if getattr(django_object, ldap_sync_related_name).distinguished_name != distinguished_name:
                        getattr(django_object, ldap_sync_related_name).distinguished_name = distinguished_name
                        getattr(django_object, ldap_sync_related_name).save()
                except ldap_sync_model.DoesNotExist:
                    ldap_sync_model(obj=django_object, distinguished_name=distinguished_name).save()
                del(django_objects[unique_name])
            except KeyError:
                django_object = django_object_model(**value_map)
                if hasattr(django_object, 'set_unusable_password'):
                    # only do this when its a user (or has this method)
                    django_object.set_unusable_password()
                unsaved_models.append(django_object)
        logger.debug('Bulk creating unsaved {}'.format(model_name))
        django_object_model.objects.bulk_create(unsaved_models)
        logger.debug('Retrieving ID\'s for the objects that were just created')

        filter_key = '{}__in'.format(unique_name_field)
        filter_value = [getattr(u, unique_name_field) for u in unsaved_models]
        just_saved_models = django_object_model.objects.filter(**{filter_key: filter_value}).all()
        logger.debug('Bulk creating ldap_sync models')
        ldap_sync_model.objects.bulk_create([ldap_sync_model(obj=u, distinguished_name=model_dn_map[getattr(u, unique_name_field)]) for u in just_saved_models])

        msg = 'Updated {} existing django objects'.format(updated_model_count)
        self.stdout.write(msg)
        logger.info(msg)

        msg = 'Created {} new django objects'.format(len(unsaved_models))
        self.stdout.write(msg)
        logger.info(msg)

        # Anything left in the existing_users dict is no longer in the ldap directory
        # These should be disabled.
        existing_unique_names = set(_unique_name for _unique_name in django_objects.keys())
        existing_unique_names.difference_update(exempt_unique_names)
        existing_model_ids = [e.id for e in django_objects.values() if getattr(e, unique_name_field) in existing_unique_names]

        if removal_action == NOTHING:
            logger.info('Removal action is set to NOTHING so the {} objects that would have been removed are being ignored.'.format(len(existing_unique_names)))
        elif removal_action == SUSPEND:
            if hasattr(django_object_model, 'is_active'):
                django_object_model.objects.in_bulk(existing_user_ids).update(is_active=False)
            logger.info('Suspended {} users.'.format(len(existing_user_ids)))
        elif removal_action == DELETE:
            django_object_model.objects.in_bulk(existing_user_ids).all().delete()
            logger.info('Deleted {} users.'.format(len(existing_unique_names)))

        logger.info("Objects are synchronized")
        self.stdout.write('Objects are synchronized')

    def will_model_change(self, value_map, user_model):
        # I think all the attrs are utf-8 strings, possibly need to coerce
        # local user values to strings?
        for model_attr, value in value_map.items():
            if not getattr(user_model, model_attr) == value:
                return True
        return False

    def apply_value_map(self, value_map, user_model):
        for k, v in value_map.items():
            try:
                setattr(user_model, k, v)
            except AttributeError:
                raise UnableToApplyValueMapError('User model {} does not have attribute {}'.format(user_model.__class__.__name__, k))
        return user_model

    def generate_value_map(self, attribute_map, ldap_attribute_values):
        '''Given an attribute map (dict with keys as ldap attrs and values as model attrs) generate a dictionary
           which maps model attribute keys to ldap values'''
        value_map = {}
        for ldap_attr, model_attr in attribute_map.items():
            try:
                value_map[model_attr] = ldap_attribute_values[ldap_attr]
            except KeyError:
                raise MissingLdapField(ldap_attr)
        return value_map

    def get_django_objects(self, model):
        '''
        Given a Django model class get all of the current records that match.
        This is better than django's bulk methods and has no upper limit.
        '''
        model_name = model.__class__.__name__
        model_objects = [i for i in model.objects.all()]
        logger.debug('Found {} {} objects in DB'.format(len(model_objects), model_name))
        return model_objects

    def get_django_users(self):
        '''
        Return a dictionary of all existing users where the key is the username and the value is the user object.
        '''
        return dict([(getattr(u, self.username_field), u) for u in self.get_django_objects(self.user_model)])

    def get_django_groups(self):
        '''
        Return a dictionary of all existing groups where the key is the group name and the value is the group object.
        '''
        return dict([(g.name, g) for g in self.get_django_objects(Group)])

    def load_settings(self):
        '''
        Get all of the required settings to perform a sync and check them for sanity.
        '''
        # User sync settings
        try:
            self.user_filter = getattr(settings, 'LDAP_SYNC_USER_FILTER')
        except AttributeError:
            raise ImproperlyConfigured('LDAP_SYNC_USER_FILTER not found in settings. This is a required setting.')

        try:
            self.user_base = getattr(settings, 'LDAP_SYNC_USER_BASE')
        except AttributeError:
            try:
                self.user_base = getattr(settings, 'LDAP_SYNC_BASE')
            except AttributeError:
                raise ImproperlyConfigured('Either LDAP_SYNC_USER_BASE or LDAP_SYNC_BASE are required. Neither were found.')

        try:
            self.user_attribute_map = getattr(settings, 'LDAP_SYNC_USER_ATTRIBUTES')
        except AttributeError:
            raise ImproperlyConfigured('LDAP_SYNC_USER_ATTRIBUTES is a required setting')
        self.user_ldap_attribute_names = self.user_attribute_map.keys()
        self.user_model_attribute_names = self.user_attribute_map.values()

        self.exempt_usernames = getattr(settings, 'LDAP_SYNC_USER_EXEMPT_FROM_SYNC', [])
        self.user_removal_action = getattr(settings, 'LDAP_SYNC_USER_REMOVAL_ACTION', NOTHING)
        if self.user_removal_action not in USER_REMOVAL_OPTIONS:
            raise ImproperlyConfigured('LDAP_SYNC_USER_REMOVAL_ACTION must be one of {}'.format(USER_REMOVAL_OPTIONS))

        self.user_model = get_user_model()
        self.username_field = getattr(self.user_model, 'USERNAME_FIELD', 'username')

        # Check to make sure we have assigned a value to the username field
        if self.username_field not in self.user_model_attribute_names:
            raise ImproperlyConfigured("LDAP_SYNC_USER_ATTRIBUTES must contain the username field '%s'" % self.username_field)

        # Group sync settings
        try:
            self.group_filter = getattr(settings, 'LDAP_SYNC_GROUP_FILTER')
        except AttributeError:
            self.group_filter = None
            logger.info("LDAP_SYNC_GROUP_FILTER not configured, skipping group sync")

        try:
            self.group_base = getattr(settings, 'LDAP_SYNC_GROUP_BASE')
        except AttributeError:
            try:
                self.group_base = getattr(settings, 'LDAP_SYNC_BASE')
            except AttributeError:
                    raise ImproperlyConfigured('Either LDAP_SYNC_GROUP_BASE or LDAP_SYNC_BASE are required. Neither were found.')

        try:
            self.group_attribute_map = getattr(settings, 'LDAP_SYNC_GROUP_ATTRIBUTES')
        except AttributeError:
            raise ImproperlyConfigured('LDAP_SYNC_GROUP_ATTRIBUTES is a required setting')
        self.group_ldap_attribute_names = self.group_attribute_map.keys()
        self.group_model_attribute_names = self.group_attribute_map.values()

        self.group_removal_action = getattr(settings, 'LDAP_SYNC_GROUP_REMOVAL_ACTION', NOTHING)
        if self.group_removal_action not in GROUP_REMOVAL_OPTIONS:
            raise ImproperlyConfigured('LDAP_SYNC_GROUP_REMOVAL_ACTION must be one of {}'.format(GROUP_REMOVAL_OPTIONS))

        self.sync_membership = getattr(settings, 'LDAP_SYNC_GROUP_MEMBERSHIP', False)
        if self.sync_membership:
            self.group_ldap_attribute_names.append('member')

        self.exempt_groupnames = getattr(settings, 'LDAP_SYNC_GROUP_EXEMPT_FROM_REMOVAL', [])

        self.membership_filter = getattr(settings, 'LDAP_SYNC_GROUP_MEMBERSHIP_FILTER', '(objectClass=user)(memberOf={dn})')

        # LDAP Servers
        try:
            self.ldap_config = getattr(settings, 'LDAP_CONFIG')
        except AttributeError:
            raise ImproperlyConfigured('LDAP_CONFIG is a required configuration item')
        self.smart_ldap_searcher = SmartLDAPSearcher(self.ldap_config)


class SmartLDAPSearcher:
    def __init__(self, ldap_config):
        self.ldap_config = ldap_config
        # Setup a few other config items
        self.page_size = self.ldap_config.get('page_size', 500)
        self.bind_user = self.ldap_config.get('bind_user', None)
        self.bind_password = self.ldap_config.get('bind_password', None)
        # Setup Server Pool
        # pooling_strategy = self.ldap_config.get('pooling_strategy', 'ROUND_ROBIN')
        # pooling_strategy = self._strategy_to_constant(pooling_strategy)
        # import pdb; pdb.set_trace() 
        self.server_pool = ldap3.ServerPool(None, ldap3.POOLING_STRATEGY_ROUND_ROBIN)
        try:
            server_defns = self.ldap_config.get('servers')
        except AttributeError:
            raise ImproperlyConfigured('ldap_config.servers must be defined and must contain at least one server')
        for server_defn in server_defns:
            self.server_pool.add(self._defn_to_server(server_defn))

    def _strategy_to_constant(self, strategy):
        '''Convert a strategy defined in the config file into an ldap3 constant'''
        if strategy.lower() == 'round_robin':
            return ldap3.POOLING_STRATEGY_ROUND_ROBIN
        elif strategy.lower() == 'first':
            return ldap3.POOLING_STRATEGY_FIRST
        elif strategy.lower() == 'random':
            return ldap3.POOLING_STRATEGY_RANDOM
        else:
            raise ImproperlyConfigured('Invalid pooling strategy passed {}, stratey can be one of RANDOM, ROUND_ROBIN, FIRST')

    def _defn_to_server(self, defn):
        '''Turn a settings file server definition into a ldap3 server object'''
        try:
            address = defn.get('address')
        except AttributeError:
            raise ImproperlyConfigured('Server definition must contain an address')
        port = defn.get('port', 389)
        use_ssl = True if defn.get('use_ssl', False) else False
        timeout = defn.get('timeout', 30)
        return ldap3.Server(address, port=port, use_ssl=use_ssl, connect_timeout=timeout, get_info=ldap3.GET_SCHEMA_INFO)

    def get_connection(self):
        c = ldap3.Connection(self.server_pool, user=self.bind_user, password=self.bind_password)
        c.bind()
        return c

    def search(self, base, filter, scope, attributes):
        '''Perform a paged search but return all of the results in one hit'''
        connection = self.get_connection()
        connection.search(search_base=base, search_filter=filter, search_scope=ldap3.SEARCH_SCOPE_WHOLE_SUBTREE, attributes=attributes, paged_size=self.page_size, paged_cookie=None)
        if len(connection.response) < self.page_size:
            results = connection.response
        else:
            results = connection.response
            cookie = connection.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
            while cookie:
                connection.search(search_base=base, search_filter=filter, search_scope=ldap3.SEARCH_SCOPE_WHOLE_SUBTREE, attributes=attributes, paged_size=self.page_size, paged_cookie=cookie)
                results += connection.response
                cookie = connection.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        connection.unbind()
        return results


class UnableToApplyValueMapError(Exception):
    pass


class MissingLdapField(Exception):
    pass


class SyncError(Exception):
    pass

# class PagedResultsSearchObject:
#     """
#     Taken from the python-ldap paged_search_ext_s.py demo, showing how to use
#     the paged results control: https://bitbucket.org/jaraco/python-ldap/
#     """
#     page_size = getattr(settings, 'LDAP_SYNC_PAGE_SIZE', 100)

#     def paged_search_ext_s(self, base, scope, filterstr='(objectClass=*)',
#                            attrlist=None, attrsonly=0, serverctrls=None,
#                            clientctrls=None, timeout=-1, sizelimit=0):
#         """
#         Behaves exactly like LDAPObject.search_ext_s() but internally uses the
#         simple paged results control to retrieve search results in chunks.
#         """
#         req_ctrl = SimplePagedResultsControl(True, size=self.page_size,
#                                              cookie='')

#         # Send first search request
#         msgid = self.search_ext(base, ldap.SCOPE_SUBTREE, filterstr,
#                                 attrlist=attrlist,
#                                 serverctrls=(serverctrls or []) + [req_ctrl])
#         results = []

#         while True:
#             rtype, rdata, rmsgid, rctrls = self.result3(msgid)
#             results.extend(rdata)
#             # Extract the simple paged results response control
#             pctrls = [c for c in rctrls if c.controlType ==
#                       SimplePagedResultsControl.controlType]

#             if pctrls:
#                 if pctrls[0].cookie:
#                     # Copy cookie from response control to request control
#                     req_ctrl.cookie = pctrls[0].cookie
#                     msgid = self.search_ext(base, ldap.SCOPE_SUBTREE,
#                                             filterstr, attrlist=attrlist,
#                                             serverctrls=(serverctrls or []) +
#                                             [req_ctrl])
#                 else:
#                     break

#         return results


# class PagedLDAPObject(LDAPObject, PagedResultsSearchObject):
#     pass
