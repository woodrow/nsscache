# Copyright 2007 Google Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""An implementation of a Conjur <https://conjur.net> source for nsscache."""

__author__ = ('woodrow@stripe.com',)

import conjur
import conjur.config

import os.path
import datetime

import calendar
import logging
import time
import urllib

from nss_cache import error
from nss_cache.maps import automount
from nss_cache.maps import group
from nss_cache.maps import netgroup
from nss_cache.maps import passwd
from nss_cache.maps import shadow
from nss_cache.maps import sshkey
from nss_cache.sources import source

def RegisterImplementation(registration_callback):
  registration_callback(ConjurSource)


class ConjurSource(source.Source):
  """Source for data from Conjur.

  """
  # conjur connection defaults
  CONJUR_URI = ''
  CONJUR_USERNAME = ''
  CONJUR_API_KEY = ''
  CONJUR_ACCOUNT = 'conjur'
  CONJUR_VERIFY_SSL = True
  CONJUR_CERT_FILE = None

  # conjur search defaults
  CONJUR_GROUP_POSIX_USERS = 'posix_users'
  CONJUR_GROUP_POSIX_GROUPS = 'posix_groups'

  # for registration
  name = 'conjur'

  def __init__(self, conf, client=None):
    """Initialise the LDAP Data Source.

    Args:
      conf: config.Config instance
      conn: An instance of ldap.LDAPObject that'll be used as the connection.
    """
    super(ConjurSource, self).__init__(conf)

    self._SetDefaults(conf)
    self._conf = conf

    self.pwmap_cache = None
    self.pwmap_cache_last_fetch = None

    if client is None:
      # ReconnectLDAPObject should handle interrupted ldap transactions.
      # also, ugh
      config = conjur.config.Config(
          appliance_url=conf['uri'],
          account=conf['account'],
          verify_ssl=False,#conf['verify_ssl'],
          cert_file=conf['cert_file'],
          )
      client = conjur.new_from_key(conf['username'],
                                   conf['api_key'],
                                   config)
    self.client = client

  def _SetDefaults(self, configuration):
    """Set defaults if necessary."""

    # conjur client params
    if not ('uri' in configuration and configuration['uri']):
      configuration['uri'] = self.CONJUR_URI
    if not configuration['uri'].startswith('https://'):
        raise error.ConfigurationError('conjur_uri must start with https://')

    if not 'username' in configuration:
      configuration['username'] = self.CONJUR_USERNAME
    if not 'api_key' in configuration:
      configuration['api_key'] = self.CONJUR_API_KEY
    if not 'account' in configuration:
      configuration['account'] = self.CONJUR_ACCOUNT
    if not 'verify_ssl' in configuration:
      configuration['verify_ssl'] = self.CONJUR_VERIFY_SSL
    if not 'cert_file' in configuration:
      configuration['cert_file'] = self.CONJUR_CERT_FILE

    # conjur group search params
    if not 'group_posix_users' in configuration:
      configuration['group_posix_users'] = self.CONJUR_GROUP_POSIX_USERS
    if not 'group_posix_groups' in configuration:
      configuration['group_posix_groups'] = self.CONJUR_GROUP_POSIX_GROUPS

  def GetSshkeyMap(self, since=None):
    """Return the sshkey map from this source.

    Args:
      since: Get data only changed since this timestamp (inclusive) or None
      for all data.

    Returns:
      instance of maps.SshkeyMap
    """

    sshmap = sshkey.SshkeyMap()

    if (self.pwmap_cache and
            (datetime.datetime.utcnow() - self.pwmap_cache_last_fetch) <
            datetime.timedelta(minutes=5)):
        pwmap = self.pwmap_cache
    else:
        pwmap = self.GetPasswdMap(since)

    for pw in pwmap:
        keys = [k for k in self.client.public_keys(pw.name).split('\n') if len(k) > 0]
        for k in keys:
            skey = sshkey.SshkeyMapEntry()
            skey.name = pw.name
            skey.sshkey = k
            sshmap.Add(skey)

    return sshmap

  def GetPasswdMap(self, since=None):
    """Return the passwd map from this source.

    Args:
      since: Get data only changed since this timestamp (inclusive) or None
      for all data.

    Returns:
      instance of maps.PasswdMap
    """

    pwmap = passwd.PasswdMap()
    members = self.client.group(self.conf['group_posix_users']).members()
    users = self.filter_group_members_by_kind(members, 'user')
    for u in users:
        parts = u['member'].split(':')
        assert(parts[0] == 'stripe' and parts[1] == 'user' and len(parts) == 3)
        conjur_user = self.client.user(parts[2])
        assert(conjur_user.exists())
        pw = passwd.PasswdMapEntry()
        pw.name = conjur_user.login
        pw.uid = conjur_user.uidnumber
        pw.gid = conjur_user.uidnumber  # this is a hack
        pw.gecos = conjur_user.login  # needs attrs
        pw.shell = '/bin/bash'  # needs attrs
        pw.dir = os.path.join('/pay/home/', pw.name)  # needs attrs
        pw.passwd = '!'

        pwmap.Add(pw)

    self.pwmap_cache = pwmap
    self.pwmap_cache_last_fetch = datetime.datetime.utcnow()

    return pwmap

  def filter_group_members_by_kind(self, members, kind):
      filtered = []
      resource_prefix = '{}:{}:'.format(self.conf['account'], kind)
      for m in members:
          if m['member'].startswith(resource_prefix):
              filtered.append(m)
      return filtered

  def GetGroupMap(self, since=None):
    """Return the group map from this source.

    Args:
      since: Get data only changed since this timestamp (inclusive) or None
      for all data.

    Returns:
      instance of maps.GroupMap
    """
    gmap = group.GroupMap()
    members = self.client.group(self.conf['group_posix_groups']).members()
    groups = self.filter_group_members_by_kind(members, 'group')
    for g in groups:
        parts = g['member'].split(':')
        assert(parts[0] == 'stripe' and parts[1] == 'group' and len(parts) == 3)
        conjur_group = self.client.group(parts[2])
        #assert(group.exists())
        gr = group.GroupMapEntry()
        gr.name = conjur_group.id
        gr.gid = 50000  # needs attrs
        gr.members = []
        gr.passwd = '!'

        gmap.Add(gr)

    return gmap


#  def Verify(self, since=None):
#    """Verify that this source is contactable and can be queried for data."""
#    if since is None:
#      # one minute in the future
#      since = int(time.time() + 60)
#    results = self.GetPasswdMap(since=since)
#    return len(results)
