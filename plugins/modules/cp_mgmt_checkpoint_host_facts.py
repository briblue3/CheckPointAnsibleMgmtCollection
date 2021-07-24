#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: cp_mgmt_checkpoint_host_facts
short_description: Get checkpoint-host objects facts on Check Point over Web Services API
description:
    - Get checkpoint-host objects facts on Check Point devices.
    - All operations are performed over Web Services API.
version_added: "2.9"
author: Brianna Hill (@briblue3)
options:
  name:
    description:
        - Name of the checkpoint-host object.
          This parameter is only relevant for getting a specific object.
    type: str
  details_level:
        - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
          representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
 limit:
   description:
        - The maximum number of returned results.
          Value must be between 1-500.
   type: int
 offset:
   description:
        - Number of the results to initially skip.
   type: int
 order:
   description:
        - Sorts the results by search criteria. Automatically sorts the results by Name, in ascending order.
   type: list
   suboptions:
     ASC:
       description:
            - Sorts results by the given field in ascending order.
       type: str
       choices: ['name']
     DESC:
       description:
            - Sorts results by the given field in descending order.
       type: str
       choices: ['name']

  uid:
    description:
        - UID of the checkpoint-host object.
          This parameter is only relevant for getting a specific object.
    type: str
"""

EXAMPLES = """
- name: Get checkpoint-host-object facts
  cp_mgmt_checkpoint_host_facts:
    name: attacker
    details_level: full

- name: Get checkpoint-host object facts
  cp_mgmt_checkpoint_host_facts:
    limit: 10
"""

RETURN = """
ansible_hosts:
  description: The checkpoint host object facts.
  returned: always.
  type: dict
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_facts, api_call_facts


def main():
    argument_spec = dict(
        name=dict(type="str"),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        limit=dict(type='int'),
        offset=dict(type='int'),
        order=dict(type='list', options=dict(
            ASC=dict(type='str', choices=['name']),
            DESC=dict(type='str', choices=['name'])
        )),
        uid=dict(type="str")
    )

    argument_spec.update(checkpoint_argument_spec_for_facts)

    module = AnsibleModule(argument_spec=argument_spec)

    connection = Connection(module._socket_path)

    api_call_object = "checkpoint-host"
    api_call_object_plural_version = "checkpoint-hosts"

    result = api_call_facts(module, api_call_object, api_call_object_plural_version)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
