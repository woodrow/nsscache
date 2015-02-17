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

import calendar
import logging
import time
import ldap
import ldap.sasl
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
  CONJUR_URI = None
  CONJUR_USERNAME = ''
  CONJUR_API_KEY = ''
  CONJUR_ACCOUNT = 'conjur'
  CONJUR_VERIFY_SSL = True
  CONJUR_CERT_FILE = None

  # conjur search defaults
  CONJUR_POSIX_USER_GROUP = 'posix_users'
  CONJUR_POSIX_GROUP_GROUP = 'posix_groups'

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

    if client is None:
      # ReconnectLDAPObject should handle interrupted ldap transactions.
      # also, ugh
      config = conjur.config.Config({
          'appliance_url': conf['conjur_uri'],
          'account': conf['conjur_account'],
          'verify_ssl': conf['conjur_verify_ssl'],
          'cert_file': conf['conjur_cert_file'],
          })
      client = conjur.new_from_key(conf['conjur_username'],
                                   conf['conjur_api_key'],
                                   config)
    else:
      self.client = client

  def _SetDefaults(self, configuration):
    """Set defaults if necessary."""
    # LDAPI URLs must be url escaped socket filenames; rewrite if necessary.
    if 'conjur_uri' in configuration:
        if not configuration['conjur_uri'].startswith('https://'):
            raise error.ConfigurationError('conjur_uri must start with https://')
    else:
      configuration['conjur_uri'] = self.CONJUR_URI
    if not 'conjur_username' in configuration:
      configuration['conjur_username'] = self.CONJUR_USERNAME
    if not 'conjur_api_key' in configuration:
      configuration['conjur_api_key'] = self.CONJUR_API_KEY
    if not 'conjur_account' in configuration:
      configuration['conjur_account'] = self.CONJUR_ACCOUNT
    if not 'conjur_verify_ssl' in configuration:
      configuration['conjur_verify_ssl'] = self.CONJUR_VERIFY_SSL
    if not 'conjur_cert_file' in configuration:
      configuration['conjur_cert_file'] = self.CONJUR_CERT_FILE

  def GetSshkeyMap(self, since=None):
    """Return the sshkey map from this source.

    Args:
      since: Get data only changed since this timestamp (inclusive) or None
      for all data.

    Returns:
      instance of maps.SshkeyMap
    """
    return SshkeyUpdateGetter().GetUpdates(source=self,
                                           search_base=self.conf['base'],
                                           search_filter=self.conf['filter'],
                                           search_scope=self.conf['scope'],
                                           since=since)
  def GetPasswdMap(self, since=None):
    """Return the passwd map from this source.

    Args:
      since: Get data only changed since this timestamp (inclusive) or None
      for all data.

    Returns:
      instance of maps.PasswdMap
    """
    return PasswdUpdateGetter().GetUpdates(source=self,
                                           search_base=self.conf['base'],
                                           search_filter=self.conf['filter'],
                                           search_scope=self.conf['scope'],
                                           since=since)

  def GetGroupMap(self, since=None):
    """Return the group map from this source.

    Args:
      since: Get data only changed since this timestamp (inclusive) or None
      for all data.

    Returns:
      instance of maps.GroupMap
    """
    return GroupUpdateGetter(self.conf).GetUpdates(source=self,
                                          search_base=self.conf['base'],
                                          search_filter=self.conf['filter'],
                                          search_scope=self.conf['scope'],
                                          since=since)

#  def Verify(self, since=None):
#    """Verify that this source is contactable and can be queried for data."""
#    if since is None:
#      # one minute in the future
#      since = int(time.time() + 60)
#    results = self.GetPasswdMap(since=since)
#    return len(results)


class UpdateGetter(object):
  """Base class that gets updates from LDAP."""

  def FromLdapToTimestamp(self, ldap_ts_string):
    """Transforms a LDAP timestamp into the nss_cache internal timestamp.

    Args:
      ldap_ts_string: An LDAP timestamp string in the format %Y%m%d%H%M%SZ

    Returns:
      number of seconds since epoch.
    """
    t = time.strptime(ldap_ts_string, '%Y%m%d%H%M%SZ')
    return int(calendar.timegm(t))

  def FromTimestampToLdap(self, ts):
    """Transforms nss_cache internal timestamp into a LDAP timestamp.

    Args:
      ts: number of seconds since epoch

    Returns:
      LDAP format timestamp string.
    """
    t = time.strftime('%Y%m%d%H%M%SZ', time.gmtime(ts))
    return t

  def GetUpdates(self, source, search_base, search_filter,
                 search_scope, since):
    """Get updates from a source.

    Args:
      source: a data source
      search_base: the LDAP base of the tree
      search_filter: the LDAP object filter
      search_scope:  the LDAP scope filter, one of 'base', 'one', or 'sub'.
      since: a timestamp to get updates since (None for 'get everything')

    Returns:
      a tuple containing the map of updates and a maximum timestamp

    Raises:
      error.ConfigurationError: scope is invalid
      ValueError: an object in the source map is malformed
    """
    self.attrs.append('modifyTimestamp')

    if since is not None:
      ts = self.FromTimestampToLdap(since)
      # since openldap disallows modifyTimestamp "greater than" we have to
      # increment by one second.
      ts = int(ts.rstrip('Z')) + 1
      ts = '%sZ' % ts
      search_filter = ('(&%s(modifyTimestamp>=%s))' % (search_filter, ts))

    if search_scope == 'base':
      search_scope = ldap.SCOPE_BASE
    elif search_scope == 'one':
      search_scope = ldap.SCOPE_ONELEVEL
    elif search_scope == 'sub':
      search_scope = ldap.SCOPE_SUBTREE
    else:
      raise error.ConfigurationError('Invalid scope: %s' % search_scope)

    source.Search(search_base=search_base, search_filter=search_filter,
                  search_scope=search_scope, attrs=self.attrs)

    # Don't initialize with since, because we really want to get the
    # latest timestamp read, and if somehow a larger 'since' slips through
    # the checks in main(), we'd better catch it here.
    max_ts = None

    data_map = self.CreateMap()

    for obj in source:
      for field in self.essential_fields:
        if field not in obj:
          logging.warn('invalid object passed: %r not in %r', field, obj)
          raise ValueError('Invalid object passed: %r', obj)

      obj_ts = self.FromLdapToTimestamp(obj['modifyTimestamp'][0])

      if max_ts is None or obj_ts > max_ts:
        max_ts = obj_ts

      try:
        if not data_map.Add(self.Transform(obj)):
          logging.info('could not add obj: %r', obj)
      except AttributeError, e:
        logging.warning('error %r, discarding malformed obj: %r',
                        str(e), obj)

    data_map.SetModifyTimestamp(max_ts)

    return data_map


class PasswdUpdateGetter(UpdateGetter):
  """Get passwd updates."""

  def __init__(self):
    super(PasswdUpdateGetter, self).__init__()
    self.attrs = ['uid', 'uidNumber', 'gidNumber', 'gecos', 'cn',
                  'homeDirectory', 'loginShell', 'fullName']
    self.essential_fields = ['uid', 'uidNumber', 'gidNumber', 'homeDirectory']

  def CreateMap(self):
    """Returns a new PasswdMap instance to have PasswdMapEntries added to it."""
    return passwd.PasswdMap()

  def Transform(self, obj):
    """Transforms a LDAP posixAccount data structure into a PasswdMapEntry."""

    pw = passwd.PasswdMapEntry()

    if 'gecos' in obj:
      pw.gecos = obj['gecos'][0]
    elif 'cn' in obj:
      pw.gecos = obj['cn'][0]
    elif 'fullName' in obj:
      pw.gecos = obj['fullName'][0]
    else:
      raise ValueError('Neither gecos nor cn found')

    pw.gecos = pw.gecos.replace('\n','')

    pw.name = obj['uid'][0]
    if 'loginShell' in obj:
      pw.shell = obj['loginShell'][0]
    else:
      pw.shell = ''

    pw.uid = int(obj['uidNumber'][0])
    pw.gid = int(obj['gidNumber'][0])
    pw.dir = obj['homeDirectory'][0]

    # hack
    pw.passwd = 'x'

    return pw


class GroupUpdateGetter(UpdateGetter):
  """Get group updates."""

  def __init__(self,conf):
    super(GroupUpdateGetter, self).__init__()
    if conf.has_key('rfc2307bis') and conf['rfc2307bis']:
      self.attrs = ['cn', 'gidNumber', 'member']
    else:
      self.attrs = ['cn', 'gidNumber', 'memberUid']
    self.essential_fields = ['cn']

  def CreateMap(self):
    """Return a GroupMap instance."""
    return group.GroupMap()

  def Transform(self, obj):
    """Transforms a LDAP posixGroup object into a group(5) entry."""

    gr = group.GroupMapEntry()

    gr.name = obj['cn'][0]
    # group passwords are deferred to gshadow
    gr.passwd = '*'
    members = []
    if 'memberUid' in obj:
      members.extend(obj['memberUid'])
    elif 'member' in obj:
      for member_dn in obj['member']:
        member_uid = member_dn.split(',')[0].split('=')[1]
        members.append(member_uid)
    members.sort()

    gr.gid = int(obj['gidNumber'][0])
    gr.members = members

    return gr


class SshkeyUpdateGetter(UpdateGetter):
  """Fetches SSH keys."""

  def __init__(self):
    super(SshkeyUpdateGetter, self).__init__()
    self.attrs = ['uid', 'sshPublicKey']
    self.essential_fields = ['uid']

  def CreateMap(self):
    """Returns a new SshkeyMap instance to have SshkeyMapEntries added to it."""
    return sshkey.SshkeyMap()

  def Transform(self, obj):
    """Transforms a LDAP posixAccount data structure into a SshkeyMapEntry."""

    skey = sshkey.SshkeyMapEntry()

    skey.name = obj['uid'][0]

    if 'sshPublicKey' in obj:
      skey.sshkey = obj['sshPublicKey']
    else:
      skey.sshkey = ''

    return skey
