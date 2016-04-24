# -*- coding: utf-8 -*-
'''
Use the cloud cache on the master to derive IPv4 addresses based on minion ID.

.. note::

    This roster requires that the minion in question was created using at least
    the 2015.5.0 version of Salt Cloud.

Starting with the 2015.5.0 release, Salt Cloud maintains an index of minions
that it creates and deletes. This index tracks the provider and profile
configuration used to provision the minion, including authentication
information. So long as this configuration remains current, it can be used by
Salt SSH to log into any minion in the index.

To use the cloud roster, set the following config in the cloud configuration
file, usually located at ``/etc/salt/cloud``:

.. code-block:: yaml

    update_cachedir: True

and run the following command to create the cache:

.. code-block:: bash

    salt-cloud --full-query > /dev/null

All minions visible to Salt Cloud should be now accessible over Salt SSH.

.. code-block:: bash

    salt-ssh --roster cloud -i '*' test.ping

To connect as a user other than root, modify ``/etc/salt/cloud``. For example,
add the following:

.. code-block:: yaml

    ssh_username: my_user
    sudo: True
    tty: True

If a cloud minion has more than one IPv4 address attached to it, the cloud
roster will prioritize addresses in this order: public, private, local.  You
may override this ordering with the ``roster_order`` config in
``/etc/salt/cloud``:

.. code-block:: yaml

    roster_order:
      - private
      - public
      - local
'''

# Import python libs
from __future__ import absolute_import
import os.path

# Import Salt libs
import salt.loader
import salt.utils
import salt.utils.cloud
import salt.utils.validate.net
import salt.config
from salt import syspaths
from salt.exceptions import SaltRenderError

# Import 3rd-party libs
import msgpack
from salt.ext.six import string_types


def targets(tgt, tgt_type='glob', **kwargs):  # pylint: disable=W0613
    '''
    Return the targets from the cloud cache
    '''
    ret = {'tgt': {}}

    # Cloud cache index
    cache = os.path.join(syspaths.CACHE_DIR, 'cloud', 'index.p')
    if not os.path.exists(cache):
        raise SaltRenderError('Cloud cache index file, {0}, does not exist'.format(cache))

    with salt.utils.fopen(cache, 'r') as fh_:
        cache_data = msgpack.load(fh_)

    indexed_minion = cache_data.get(tgt, None)
    if indexed_minion is None:
        raise SaltRenderError('Could not find {0} in cloud cache'.format(tgt))

    # Provider, profile, and instance information
    client = salt.cloud.CloudClient(
            os.path.join(os.path.dirname(__opts__['conf_file']), 'cloud')
            )
    info = client.action('show_instance', names=[tgt])
    if not info:
        raise SaltRenderError('Could not find {0} instance information'.format(tgt))

    roster_order = __opts__.get('roster_order', (
        'public', 'private', 'local'
    ))

    roster_opts = CloudRosterOpts(tgt, indexed_minion, info, roster_order)

    # IPv4 address
    if roster_opts.host:
        ret['tgt']['host'] = roster_opts.host
    else:
        raise SaltRenderError('Could not find IPv4 address for {0}'.format(tgt))

    # ssh user name
    if roster_opts.user:
        ret['tgt']['user'] = roster_opts.user
    else:
        raise SaltRenderError('Could not find ssh user for {0}'.format(tgt))

    # ssh secret key file or password
    if roster_opts.priv:
        ret['tgt']['priv'] = roster_opts.priv
    elif roster_opts.password:
        ret['tgt']['password'] = roster_opts.password
    else:
        raise SaltRenderError('Could not find ssh key or password for {0}'.format(tgt))

    # sudo
    if roster_opts.sudo:
        ret['tgt']['sudo'] = roster_opts.sudo

    # tty
    if roster_opts.tty:
        ret['tgt']['tty'] = roster_opts.tty

    return ret


class CloudRosterOpts(object):
    '''
    Extract roster configs from provider, profile, and instance data
    '''
    def __init__(self, tgt, indexed_minion, info, roster_order):
        '''
        Add provider, profile, and instance data to self
        '''
        self.provider = indexed_minion.get('provider', None)
        self.profile = indexed_minion.get('profile', None)
        self.driver = indexed_minion.get('driver', None)
        self.vm_ = {
            'provider': self.provider,
            'profile': self.profile,
        }

        self.full_info = info.get(self.provider, {}).get(self.driver, {}).get(tgt, {})
        self.cloud_opts = salt.config.cloud_config('/etc/salt/cloud')
        self.roster_order = roster_order

    def _normalize_list(self, arg):
        '''
        Return ``arg`` as a list of strings
        '''
        if isinstance(arg, (tuple, list)):
            return [str(item) for item in arg]
        else:
            return [str(arg)]

    def _extract_ipv4(self, ipv4):
        '''
        Extract the preferred IP address from the ipv4 grain
        '''
        for ip_type in self.roster_order:
            for ip_ in ipv4:
                if ':' in ip_:
                    continue
                if not salt.utils.validate.net.ipv4_addr(ip_):
                    continue
                if ip_type == 'local' and ip_.startswith('127.'):
                    return ip_
                elif ip_type == 'private' and not salt.utils.cloud.is_public_ip(ip_):
                    return ip_
                elif ip_type == 'public' and salt.utils.cloud.is_public_ip(ip_):
                    return ip_
        return None

    @property
    def host(self):
        '''
        Add IPv4 address to roster config
        '''
        # Amazon EC2
        if self.driver == 'ec2':
            public_ips = self._normalize_list(
                self.full_info.get('public_ips', [])
            )
            private_ips = self._normalize_list(
                self.full_info.get('private_ips', [])
            )
            ip_list = public_ips + private_ips
        # Digital Ocean
        elif self.driver == 'digital_ocean':
            nets = self.full_info.get('networks', {}).get('v4', [])
            ip_list = [net.get('ip_address', '') for net in nets]
        else:
            raise SaltRenderError('{0} provider not yet supported by cloud roster'.format(self.provider))

        return self._extract_ipv4(ip_list)

    @property
    def user(self):
        '''
        Add SSH user name to roster config
        '''
        ssh_username = salt.utils.cloud.ssh_usernames({}, self.cloud_opts)
        if isinstance(ssh_username, string_types):
            return ssh_username
        elif isinstance(ssh_username, list):
            return ssh_username[0]

    @property
    def password(self):
        '''
        Add password to roster config
        '''
        return salt.config.get_cloud_config_value(
            'password', self.vm_, self.cloud_opts, search_global=False, default=None
        )

    @property
    def priv(self):
        '''
        Add secret key to roster config
        '''
        private_key = salt.config.get_cloud_config_value(
            'private_key', self.vm_, self.cloud_opts, search_global=False, default=None
        )
        ssh_key_file = salt.config.get_cloud_config_value(
            'ssh_key_file', self.vm_, self.cloud_opts, search_global=False, default=None
        )
        if private_key:
            return private_key
        elif ssh_key_file:
            return ssh_key_file

    @property
    def sudo(self):
        '''
        Add sudo to roster config
        '''
        return salt.config.get_cloud_config_value(
            'sudo', self.vm_, self.cloud_opts, search_global=False, default=None
        )

    @property
    def tty(self):
        '''
        Add tty to roster config
        '''
        return salt.config.get_cloud_config_value(
            'tty', self.vm_, self.cloud_opts, search_global=False, default=None
        )
