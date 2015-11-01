#!/usr/bin/python
# -*- coding: utf-8 -*-

# SNMP modules for Ansible
# Copyright (C) 2015  Peter Nørlund
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

DOCUMENTATION='''
module: snmp_sysinfo
short_description: Set basic system info through SNMP
description:
    - Set basic system info through SNMP
author: "Peter Nørlund, @pchri03"
requirements:
    - pysnmp
options:
    host:
        description:
            - Set to SNMP hostname (normally {{inventory_hostname}})
        required: true
    version:
        description:
            - SNMP version to use.
            - If omitted, v2c is used if community is set and v3 is used if username is set.
        required: false
        choices: [ 'v1', 'v2c', 'v3' ]
    community:
        description:
            - SNMP community string (SNMPv1/SNMPv2c only).
        required: false
    username:
        description:
            - SNMP user name (SNMPv3 only).
        required: false
    auth:
        description:
            - Authentication protocol to use if authkey is set (SNMPv3 only).
        required: false
        default: md5
        choices: [ 'md5', 'sha' ]
    priv:
        description:
            - Encryption protocol to use if privkey is set (SNMPv3 only).
        required: false
        default: des
        choices: [ 'des', 'aes' ]
    authkey:
        description:
            - Authentication key (SNMPv3 only).
            - When set, the security level is automatically set to either authNoPriv or authPriv.
        required: false
    privkey:
        description:
            - Encryption key (SNMPv3 only).
            - When set, the security level is automatically set to authPriv.
        required: false
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
try:
    from pysnmp.entity.rfc3413.oneliner import cmdgen
    has_pysnmp = True
except:
    has_pysnmp = False

def snmp_get_auth(module):
    params = module.params

    version = params['version']
    username = params['username']    
    community = params['community']

    # Detect version
    if version == None:
        if not username == None:
            version = 'v3'
        elif not community == None:
            version = 'v2c'

    # SNMPv1 and SNMPv2c
    if version == 'v2c' or version == 'v1':
        if community == None:
            module.fail_json(msg='Community not set when using SNMP version 1/2c')

        return cmdgen.CommunityData(community)

    # SNMPv3
    username = params['username']
    if username == None:
        module.fail_json(msg='Username not set when using SNMP version 3')

    authkey = params['authkey']
    privkey = params['privkey']

    if params['auth'] == 'sha':
        auth = cmdgen.usmHMACSHAAuthProtocol
    else:
        auth = cmdgen.usmHMACMD5AuthProtocol

    if params['priv'] == 'aes':
        priv = cmdgen.usmAesCfb128Protocol
    else:
        priv = cmdgen.usmDESPrivProtocol

    # noAuthNoPriv
    if authkey == None:
        return cmdgen.UsmUserData(username)

    # authNoPriv
    if privkey == None:
        return cmdgen.UsmUserData(username, authKey=authkey, authProtocol=auth)
    
    # authPriv
    return cmdgen.UsmUserData(username, authKey=authkey, authProtocol=auth, privKey=privkey, privProtocol=priv)

def main():
    module = AnsibleModule(
        argument_spec = dict(
            host      = dict(required=True),
            version   = dict(required=False, choices=['v1', 'v2c', 'v3']),
            community = dict(required=False),
            username  = dict(required=False),
            auth      = dict(required=False, choices=['md5', 'sha'], default='md5'),
            priv      = dict(required=False, choices=['des', 'aes'], default='des'),
            authkey   = dict(required=False),
            privkey   = dict(required=False),

            descr     = dict(required = False),
            contact   = dict(required = False),
            name      = dict(required = False),
            location  = dict(required = False)
        ),
        mutually_exclusive=[['community', 'username']],
        required_one_of=[['version', 'community', 'username'],['descr', 'contact', 'name', 'location']],
        supports_check_mode=True
    )

    if not has_pysnmp:
        module.fail_json(msg='Missing required pysnmp module')
    
    snmp_auth = snmp_get_auth(module)

    params = module.params;

    descr = params['descr']
    contact = params['contact']
    name = params['name']
    location = params['location']

    oid_sys_descr    = '1.3.6.1.2.1.1.1.0'
    oid_sys_contact  = '1.3.6.1.2.1.1.4.0'
    oid_sys_name     = '1.3.6.1.2.1.1.5.0'
    oid_sys_location = '1.3.6.1.2.1.1.6.0'

    get_varbinds = []
    if not descr == None:
        get_varbinds.append(cmdgen.MibVariable(oid_sys_descr,))
    if not contact == None:
        get_varbinds.append(cmdgen.MibVariable(oid_sys_contact,))
    if not name == None:
        get_varbinds.append(cmdgen.MibVariable(oid_sys_name,))
    if not location == None:
        get_varbinds.append(cmdgen.MibVariable(oid_sys_location,))

    transport = cmdgen.UdpTransportTarget((params['host'], 161))
    generator = cmdgen.CommandGenerator()

    error_indication, error_status, error_index, varbinds = generator.getCmd(snmp_auth, transport, *get_varbinds)

    if error_indication:
        module.fail_json(msg=error_indication)
    if error_status:
        module.fail_json(msg=error_status.prettyPrint())

    set_varbinds = []
    for oid, var in varbinds:
        cur_oid = oid.prettyPrint()
        if cur_oid == oid_sys_descr and not descr == None and not var == descr:
            set_varbinds.append((cmdgen.MibVariable(oid_sys_descr,), descr))
        elif cur_oid == oid_sys_contact and not contact == None and not var == contact:
            set_varbinds.append((cmdgen.MibVariable(oid_sys_contact,), contact))
        elif cur_oid == oid_sys_name and not name == None and not var == name:
            set_varbinds.append((cmdgen.MibVariable(oid_sys_name,), name))
        elif cur_oid == oid_sys_location and not location == None and not var == location:
            set_varbinds.append((cmdgen.MibVariable(oid_sys_location,), location))
   
    if len(set_varbinds) == 0:
        module.exit_json(changed = False)

    if module.check_mode:
       module.exit_json(changed = True)

    error_indication, error_status, error_index, varbinds = generator.setCmd(snmp_auth, transport, *set_varbinds)

    if error_indication:
        module.fail_json(msg=error_indication)
    if error_status:
        module.fail_json(msg=error_status.prettyPrint())

    module.exit_json(changed = True)

if __name__ == '__main__':
    main()