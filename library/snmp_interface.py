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
author: "Peter Nørlund, @pchri03"
requirements:
    - pysnmp
options:
    name:
        description:
            - Interface name
        required: false
    index:
        description:
            - Interface index
        required: false
    alias:
        description:
            - Set interface alias
        required: false
    status:
        description:
            - Set status of interface
        choices: [ 'up', 'down' ]
        required: false
    traps:
        description:
            - Toggle SNMP traps on interface
        required: false
    promisc:
        description:
            - Toggle promisicous mode
        required: false
'''

from ansible.module_utils.basic import *

import snmp

OID_IF_X_ENTRY = '1.3.6.1.2.1.31.1.1.1'
OID_IF_ENTRY   = '1.3.6.1.2.1.2.2.1'

OID_IF_NAME = OID_IF_X_ENTRY + '.1'
OID_IF_ADMIN_STATUS = OID_IF_ENTRY + '.7'
OID_IF_LINK_UP_DOWN_TRAP_ENABLE = OID_IF_X_ENTRY + '.14'
OID_IF_PROMISCUOUS_MODE = OID_IF_X_ENTRY + '.16'
OID_IF_ALIAS = OID_IF_X_ENTRY + '.18'

IF_ADMIN_STATUS_UP = 1
IF_ADMIN_STATUS_DOWN = 2
IF_ADMIN_STATUS_TESTING = 3

IF_LINK_UP_DOWN_TRAP_ENABLE_ENABLED = 1
IF_LINK_UP_DOWN_TRAP_ENABLE_DISABLED = 2

SNMP_TRUE = 1
SNMP_FALSE = 2

def get_ifindex(client, name):
    names = client.walk(OID_IF_NAME)
    for if_index, if_name in names.iteritems():
        if str(if_name) == name:
            return if_index
    return None    

def main():
    module = AnsibleModule(
        argument_spec = dict(
            name      = dict(required=False),
            index     = dict(required=False),

            alias     = dict(required=False),
            status     = dict(required=False, choices=['up', 'down']),
            traps     = dict(required=False, choices=BOOLEANS),
            promisc   = dict(required=False, choices=BOOLEANS)
        ),
        mutually_exclusive=[['name', 'index']],
        required_one_of=[['name', 'index'],
                         ['alias', 'status', 'traps', 'promisc']],
        supports_check_mode=True
    )

    params = module.params

    name = params['name']
    index = params['index']
    alias = params['alias']
    status = params['status']
    traps = params['traps']
    promisc = params['promisc']

    try:
        client = snmp.SnmpClient()

        if not index:
            index = get_ifindex(client, name)
            if not index:
                module.fail_json(msg="No such interface")

        var_names = []
        if alias is not None:
            var_names.append(OID_IF_ALIAS + '.' + str(index))
        if status is not None:
            var_names.append(OID_IF_ADMIN_STATUS + '.' + str(index))
        if traps is not None:
            var_names.append(OID_IF_LINK_UP_DOWN_TRAP_ENABLE + '.' + str(index))
        if promisc is not None:
            var_names.append(OID_IF_PROMISCUOUS_MODE + '.' + str(index))

        values = client.get(*var_names)

        var_binds = dict()

        if alias:
            value = str(values.pop(0))
            if value != alias:
                var_binds[OID_IF_ALIAS + '.' + str(index)] = snmp.OctetString(alias)

        if status:
            if_status = int(values.pop(0))
            if status == 'up' and if_status != IF_ADMIN_STATUS_UP:
                var_binds[OIF_IF_ADMIN_STATUS + '.' + str(index)] = IF_ADMIN_STATUS_UP
            elif status == 'down' and if_status != IF_ADMIN_STATUS_DOWN:
                var_binds[OID_IF_ADMIN_STATUS + '.' + str(index)] = IF_ADMIN_STATUS_DOWN

        if traps:
            traps = module.boolean(traps)
            if_link_up_down_trap_enable = int(values.pop(0))
            if traps and if_link_up_down_trap_enable != IF_LINK_UP_DOWN_TRAP_ENABLE_ENABLED:
                var_binds[OID_IF_LINK_UP_DOWN_TRAP_ENABLE + '.' + str(index)] = IF_LINK_UP_DOWN_TRAP_ENABLE_ENABLED
            elif not traps and if_link_up_down_trap_enable != IF_LINK_UP_DOWN_TRAP_ENABLE_DISABLED:
                var_binds[OID_IF_LINK_UP_DOWN_TRAP_ENABLE + '.' + str(index)] = IF_LINK_UP_DOWN_TRAP_ENABLE_DISABLED

        if promisc:
            promisc = module.boolean(promisc)
            if_promiscuous_mode = int(values.pop(0))
            if promisc and if_promiscuous_mode != SNMP_TRUE:
                var_binds[OID_IF_PROMISCUOUS_MODE + '.' + str(index)] = SNMP_TRUE
            elif not promisc and if_promiscuous_mode != SNMP_FALSE:
                var_binds[OID_IF_PROMISCUOUS_MODE + '.' + str(index)] = SNMP_FALSE

        if not var_binds:
            module.exit_json(changed=False)

        if module.check_mode:
            module.exit_json(changed=True, var_binds=var_binds.keys())

        module.exit_json(changed=True)
    except snmp.SnmpError as e:
        module.fail_json(msg=str(e))

if __name__ == '__main__':
    main()
