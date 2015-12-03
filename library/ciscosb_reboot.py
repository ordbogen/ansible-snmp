#!/usr/bin/python
# -*- coding: utf-8 -*-

# SNMP modules for Ansible
# Copyright (C) 2015  Peter Nørlund
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = """
module: ciscosb_reboot
short_description: Reboot CiscoSB switches
description:
    - Reboot CiscoSB switch
author: "Peter Nørlund, @pchri03"
"""

import snmp

OID_RND_ACTION = '1.3.6.1.4.1.9.6.1.101.1.2.0'

def main():
    module = AnsibleModule(
        argument_spec = dict()
    )

    try:
        client = snmp.SnmpClient()

        var_binds = dict()
        var_binds[OID_RND_ACTION] = snmp.Integer32(1)
        client.set(var_binds)

        module.exit_json(changed=True)
    except snmp.SnmpError as e:
        module.fail_json(msg=str(e))

from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
