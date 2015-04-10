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

"""An implementation of an auth.yaml source for nsscache."""

__author__ = ('woodrow@stripe.com',)

import sys
import random
import re
import yaml
import os.path
import datetime
import collections

from nss_cache import error
from nss_cache.maps import group
from nss_cache.maps import passwd
from nss_cache.maps import sshkey
from nss_cache.sources import source

def RegisterImplementation(registration_callback):
  registration_callback(AuthYamlSource)


class AuthYamlSource(source.Source):
  """Source for data from auth.yaml.

  """
  AUTHYAML_PATH = '/etc/stripe/auth.yaml/'
  GROUP_NAME_MAX_LENGTH = 16
  USER_NAME_MAX_LENGTH = 16 # really 32 in debian, but if we're going to create
                            # per-user groups, it should be
                            # MIN(GROUP_NAME_MAX_LENGTH, USER_NAME_MAX_LENGTH)
  IS_VALID_NAME_REGEX = re.compile('^[^-:\s][^:\s]*$')

  MIN_DATETIME = datetime.datetime(datetime.MINYEAR, 1, 1)
  MAX_DATETIME = datetime.datetime(datetime.MAXYEAR, 1, 1)

  # for registration
  name = 'authyaml'

  def __init__(self, conf):
    """Initialise the Auth.yaml Data Source.

    Args:
      conf: config.Config instance
    """
    super(AuthYamlSource, self).__init__(conf)

    self._SetDefaults(conf)
    self._conf = conf

    self._group_cache = {}

  def _SetDefaults(self, configuration):
    """Set defaults if necessary."""

    # authyaml client params
    if not ('path' in configuration and configuration['path']):
      configuration['path'] = self.AUTHYAML_PATH

  def _load_yaml(self):
      with open(self._conf['path']) as yaml_file:
          return yaml.safe_load(yaml_file)

  def GetSshkeyMap(self, since=None):
    """Return the sshkey map from this source.

    Args:
      since: Get data only changed since this timestamp (inclusive) or None
      for all data.

    Returns:
      instance of maps.SshkeyMap
    """

    sshmap = sshkey.SshkeyMap()

    users = self._load_yaml()['users']
    active_users = {k: users[k] for k in users if users[k]['active'] is True}

    for user in active_users:
        keys = active_users[user].get('sshkeys', [])
        if keys:
            skey = sshkey.SshkeyMapEntry()
            skey.name = user
            skey.sshkey = ', '.join(keys)
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

    users = self._load_yaml()['users']
    active_users = {k: users[k] for k in users if users[k]['active'] is True}

    for user in active_users:
        user_details = active_users[user]
        assert(user_details['active'])

        pw = passwd.PasswdMapEntry()
        pw.name = user
        pw.uid = int(user_details['uid'])
        pw.gid = int(user_details['gid'])
        pw.gecos = user_details['gecos']
        pw.shell = user_details['shell']
        pw.dir = user_details['homedir']
        pw.passwd = 'x'

        pwmap.Add(pw)

    return pwmap

  def GetGroupMap(self, since=None):
    """Return the group map from this source.

    Args:
      since: Get data only changed since this timestamp (inclusive) or None
      for all data.

    Returns:
      instance of maps.GroupMap
    """

    authyaml = self._load_yaml()

    # build group graph beforehand

    # TODO INTEGRITY CHECKS
    # set of usernames and groupnames are disjoint
    # set of groupnames and short (posix) groupnames are disjoint
    # users and groups are not members of other users

    group_user_members = collections.defaultdict(lambda: set())
    group_group_members = collections.defaultdict(lambda: set())
    now = datetime.datetime.utcnow()

    users = self._load_yaml()['users']
    active_users = {k: users[k] for k in users if users[k]['active'] is True}
    for user in active_users:
        for membership in active_users[user]['group_memberships']:
            not_before = membership.get('not_before', self.MIN_DATETIME)
            not_after = membership.get('not_after', self.MAX_DATETIME)
            if not_before <= now <= not_after:
                group_user_members[membership['member_of']].add(user)

    groups = self._load_yaml()['groups']
    active_groups = {k: groups[k] for k in groups if groups[k]['active'] is True}
    for group_name in active_groups:
        for membership in active_groups[group_name]['group_memberships']:
            not_before = membership.get('not_before', self.MIN_DATETIME)
            not_after = membership.get('not_after', self.MAX_DATETIME)
            if not_before <= now <= not_after:
                group_group_members[membership['member_of']].add(group_name)


    gmap = group.GroupMap()

    posix_groups = {k: active_groups[k] for k in active_groups if active_groups[k]['posix_group'] is True }
    for group_name in posix_groups:
        group_details = posix_groups[group_name]
        assert(group_details['active'] and group_details['posix_group'])

        gr = group.GroupMapEntry()
        gr.name = group_details.get('posix_name', group_name)
        gr.gid = int(group_details['gid'])
        gr.members = self.expand_groups(group_name, group_group_members, group_user_members)
        gr.passwd = 'x'

        gmap.Add(gr)

    # per-user groups
    pwmap = self.GetPasswdMap(since)
    for pw in pwmap:
        gr = group.GroupMapEntry()
        gr.name = pw.name
        gr.gid = pw.gid
        gr.members = [pw.name]
        gr.passwd = 'x'
        gmap.Add(gr)

    return gmap

  def expand_groups(self, group_name, group_group_members, group_user_members):
      # FIXME currently doesn't check for cycles
      print("keys", self._group_cache.keys(), "group", group_name)
      if group_name in self._group_cache:
          members = self._group_cache[group_name]
      else:
          members = set()
          members.update(group_user_members[group_name])
          for child_group in group_group_members[group_name]:
              members.update(self.expand_groups(child_group, group_group_members, group_user_members))
          self._group_cache[group_name] = members

      return list(members)


#  def Verify(self, since=None):
#    """Verify that this source is contactable and can be queried for data."""
#    if since is None:
#      # one minute in the future
#      since = int(time.time() + 60)
#    results = self.GetPasswdMap(since=since)
#    return len(results)
