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

"""An implementation of a group map for nsscache.

GroupMap:  An implementation of NSS group maps based on the Map
class.

GroupMapEntry:  A group map entry based on the MapEntry class.
"""

__author__ = 'vasilios@google.com (Vasilios Hoffman)'

from nss_cache.maps import maps


class GroupMap(maps.Map):
  """This class represents an NSS group map.
  
  Map data is stored as a list of MapEntry objects, see the abstract
  class Map.
  """

  def __init__(self, iterable=None):
    """Construct a GroupMap object using optional iterable."""
    super(GroupMap, self).__init__(iterable)
    
  def Add(self, entry):
    """Add a new object, verify it is a GroupMapEntry object."""
    if not isinstance(entry, GroupMapEntry):
      raise TypeError
    return super(GroupMap, self).Add(entry)

  def Verify(self):
    # ensure gids are unique
    group_by_gid = {}
    for group in self:
      if group.gid not in group_by_gid:
        group_by_gid[group.gid] = group
      else:
        self.log.warn(
          ('GroupMap verify failed: '
          'Duplicate gidnumber {} for group {} and {}').format(
          group.gid, group_by_gid[group.gid].name, group.name))
        return False

    return True


class GroupMapEntry(maps.MapEntry):
  """This class represents NSS group map entries."""
  # Using slots saves us over 2x memory on large maps.
  __slots__ = ('name', 'passwd', 'gid', 'members')
  _KEY = 'name'
  _ATTRS = ('name', 'passwd', 'gid', 'members')
  
  def __init__(self, data=None):
    """Construct a GroupMapEntry, setting reasonable defaults."""
    self.name = None
    self.passwd = None
    self.gid = None
    self.members = None
    
    super(GroupMapEntry, self).__init__(data)
    
    # Seed data with defaults if needed
    if self.passwd is None: self.passwd = 'x'
    if self.members is None: self.members = []
