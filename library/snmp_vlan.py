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
module: snmp_vlan
short_description: Set bridge settings through SNMP
description:
    - Set up bridge settings such as VLAN and spanning tree
    - Requires the snmp connection plugin
author: "Peter Nørlund, @pchri03"
options:
    ifname:
        description:
            - Interface name
        required: false
    ifindex:
        description:
            - Interface index
        required: false
    port:
        description:
            - Port index
        required: false
    gvrp:
        description:
            - Toggle GVRP.
            - If ifname, ifindex, or port is defined, GVRP is toggled on the port. Otherwise it toggle GVRP globally.
        required: false
    vlan:
        description:
            - VLAN id
        required: false
    state:
        description:
            - State of VLAN
        choices: [ 'present' | 'absent' ]
        required: false
    name:
        description:
            - Name of VLAN
        required: false
    pvid:
        description:
            - Port VLAN id
        required: false
'''

EXAMPLES='''
# Enable GVRP globally
- snmp_vlan: gvrp=on

# Create VLAN
- snmp_vlan: vlan=200 state=present name="Test"

# Delete VLAN
- snmp_vlan: vlan=201 state=absent

# Map VLAN 200 to port gi1
- snmp_vlan: ifname="gi1" vlan=200 state=present

# Remove VLAN 201 from port gi1
- snmp_vlan: ifname="gi1" vlan=201 state=absent

# Enable GVRP on port gi1
- snmp_vlan: ifname="gi1" gvrp=on
'''

import snmp

OID_MIB_2 = '1.3.6.1.2.1'

OID_IF_NAME = OID_MIB_2 + '.31.1.1.1.1'

OID_DOT1D_BRIDGE = OID_MIB_2 + '.17'
OID_DOT1D_BASE_PORT_IF_INDEX = OID_DOT1D_BRIDGE + '.1.4.1.2'

OID_Q_BRIDGE_MIB = OID_DOT1D_BRIDGE + '.7'
OID_Q_BRIDGE_MIB_OBJECTS = OID_Q_BRIDGE_MIB + '.1'
OID_DOT1Q_BASE = OID_Q_BRIDGE_MIB_OBJECTS + '.1'
OID_DOT1Q_GVRP_STATUS = OID_DOT1Q_BASE + '.5.0'

OID_DOT1Q_VLAN = OID_Q_BRIDGE_MIB_OBJECTS + '.4'

OID_DOT1Q_PORT_VLAN_TABLE = OID_DOT1Q_VLAN + '.5'
OID_DOT1Q_PORT_VLAN_ENTRY = OID_DOT1Q_PORT_VLAN_TABLE + '.1'
OID_DOT1Q_PORT_GVRP_STATUS = OID_DOT1Q_PORT_VLAN_ENTRY + '.4'

SNMP_ENABLED = 1
SNMP_DISABLED = 2

def ifindex_to_port(client, ifindex):
    ifindexes = client.walk(OID_DOT1D_BASE_PORT_IF_INDEX)
    for port, _ifindex in ifindexes.iteritems():
        if int(_ifindex) == ifindex:
            return int(port)
    return None

def ifname_to_ifindex(client, ifname):
    ifnames = client.walk(OID_IF_NAME)
    for ifindex, _ifname in ifnames.iteritems():
        if str(_ifname) == ifname:
            return int(ifindex)
    return None

def ifname_to_port(client, ifname):
    ifindex = ifname_to_ifindex(client, ifname)
    if ifindex:
        return ifindex_to_port(client, ifindex)
    else:
        return None

def main():
    module = AnsibleModule(
        argument_spec = dict(
            ifname  = dict(required=False),
            ifindex = dict(required=False),
            port = dict(required=False),

            gvrp = dict(required=False, choices=BOOLEANS),
            vlan = dict(required=False),
            state = dict(required=False, choices=['present', 'absent']),
            name = dict(required=False),
            pvid = dict(required=False)
        ),
        supports_check_mode=True
    )

    params = module.params

    ifname = params['ifname']
    ifindex = params['ifindex']
    port = params['port']
    gvrp = params['gvrp']
    vlan = params['vlan']
    state = params['state']
    name = params['name']
    pvid = params['pvid']

    has_selector = ifname or ifindex or port

    var_names = []

    client = snmp.SnmpClient()

    if has_selector:
        var_binds = dict()

        if not port:
            if ifindex:
                port = ifindex_to_port(client, ifindex)
            elif ifname:
                port = ifname_to_port(client, ifname)
            if not port:
                module.fail_json(msg="No such port/interface")

        oid_dot1q_port_gvrp_status = OID_DOT1Q_PORT_GVRP_STATUS + '.' + str(port)

        if gvrp:
            var_names.append(oid_dot1q_port_gvrp_status)
    
        values = client.get(*var_names)

        if gvrp:
            gvrp = module.boolean(gvrp)
            if gvrp and int(values[oid_dot1q_port_gvrp_status]) != SNMP_ENABLED:
                var_binds[oid_dot1q_port_gvrp_status] = snmp.Integer32(SNMP_ENABLED)
            elif not gvrp and int(values[oid_dot1q_port_gvrp_status]) != SNMP_DISABLED:
                var_binds[oid_dot1q_port_gvrp_status] = snmp.Integer32(SNMP_DISABLED)

    else:
        var_binds = dict()

        if gvrp:
            var_names.append(OID_DOT1Q_GVRP_STATUS)

        values = client.get(*var_names)

        if gvrp:
            gvrp = module.boolean(gvrp)
            if gvrp and int(values[OID_DOT1Q_GVRP_STATUS]) != SNMP_ENABLED:
                var_binds[OID_DOT1Q_GVRP_STATUS] = snmp.Integer32(SNMP_ENABLED)
            elif not gvrp and int(values[OID_DOT1Q_GVRP_STATUS]) != SNMP_DISABLED:
                var_binds[OID_DOT1Q_GVRP_STATUS] = snmp.Integer32(SNMP_DISABLED)

    if not var_binds:
        module.exit_json(changed=False)

    if module.check_mode:
        module.exit_json(changed=True)

    client.set(var_binds)                
    module.exit_json(changed=True)

from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
            
