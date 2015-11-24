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

DOCUMENTATION='''
module: snmp_sysinfo
short_description: Set basic system info through SNMP
description:
    - Set basic system info through SNMP
    - Requires the snmp connection plugin
author: "Peter Nørlund, @pchri03"
options:
    descr:
        description:
            - Textual description of SNMP device.
        required: false
    contact:
        description:
            - Contact person for SNMP device.
        required: false
    name:
        description:
            - Name of SNMP device.
        required: false
    location:
        description:
            - Physical location of SNMP device.
        required: false
'''

from ansible.module_utils.basic import *

import snmp

OID_SYS_DESCR    = '1.3.6.1.2.1.1.1.0'
OID_SYS_CONTACT  = '1.3.6.1.2.1.1.4.0'
OID_SYS_NAME     = '1.3.6.1.2.1.1.5.0'
OID_SYS_LOCATION = '1.3.6.1.2.1.1.6.0'

def main():
    module = AnsibleModule(
        argument_spec = dict(
            descr     = dict(required=False),
            contact   = dict(required=False),
            name      = dict(required=False),
            location  = dict(required=False)
        ),
        required_one_of=[['descr', 'contact', 'name', 'location']],
        supports_check_mode=True
    )

    params = module.params
    descr = params['descr']
    contact = params['contact']
    name = params['name']
    location = params['location']

    var_names = [];
    if descr is not None:
        var_names.append(OID_SYS_DESCR)
    if contact is not None:
        var_names.append(OID_SYS_CONTACT)
    if name is not None:
        var_names.append(OID_SYS_NAME)
    if location is not None:
        var_names.append(OID_SYS_LOCATION)

    try:
        client = snmp.SnmpClient()
        values = client.get(*var_names)

        var_binds = dict()

        if descr is not None:
            value = str(values.pop(0))
            if value != descr:
                var_binds[OID_SYS_DESCR] = snmp.OctetString(descr)

        if contact is not None:
            value = str(values.pop(0))
            if value != contact:
                var_binds[OID_SYS_CONTACT] = snmp.OctetString(contact)

        if name is not None:
            value = str(values.pop(0))
            if value != name:
                var_binds[OID_SYS_NAME] = snmp.OctetString(name)

        if location is not None:
            value = str(values.pop(0))
            if value != name:
                var_binds[OID_SYS_LOCATION] = snmp.OctetString(name)

        if len(var_binds) == 0:
            module.exit_json(changed=False)

        if module.check_mode:
            module.exit_json(changed=True)

        client.set(var_binds)
        module.exit_json(changed=True)
    except snmp.SnmpError as e:
        module.fail_json(msg=str(e))

if __name__ == '__main__':
    main()
