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

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_set_ips_update_schedule
short_description: Set IPS update schedule on Check Point over Web Services API
description:
  - Sets IPS update schedule on Check Point devices
  - All operations are performed over Web Services API.
version_added: "2.9"
author: Brianna Hill (@briblue3)
options:
  enabled:
    description:
      - Enable/Disable IPS update schedule.
    type: bool
  time:
    description:
      - Time IPS updates will run, in HH:MM format.
    type: str
  recurrence:
    description:
      - Frequency of IPS updates.
    type: dict
    suboptions:
      days:
        description:
          - Days of the month to run IPS updates. EX: ["1","3","9-20"].
        type: list
      minutes:
        description:
          - Interval of time (in minutes) between updates.
            Value must be between 120-12119.
        type: int
      pattern:
        description:
          - N/A
        type: str
        choices: ['Interval', 'Daily', 'Weekly', 'Monthly']
      weekdays:
        description:
          - Days of week to run updates. EX: "Sun", "Mon"..."Sat".
        type: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: schedule daily IPS updates
  cp_mgmt_set_ips_update_schedule:
    enabled: true
    time: "08:00"
    recurrence:
      pattern: "Daily"

- name: disable IPS updates
  cp_mgmt_set_ips_update_schedule:
    enabled: false
"""

RETURN = """
cp_mgmt_set_ips_update_schedule:
  description: The checkpoint set ips-update-schedule output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        enabled=dict(type='bool'),
        time=dict(type='str'),
        recurrence=dict(type='dict', options=dict(
            days=dict(type='list'),
            minutes=dict(type='int'),
            pattern=dict(type='str', choices=['Interval', 'Daily', 'Weekly', 'Monthly']),
            weekdays=dict(type='str')
        ))
    )

    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    api_call_object = "ips-update-schedule"

    result = api_command(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
