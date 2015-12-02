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
module: ciscosb_firmware
short_description: Set active firmware on CiscoSB switches
description:
    - Set active firmware
    - Requires the snmp connection plugin
author: "Peter Nørlund, pchri03"
options:
    version:
        description:
            - Firmware version to set as active
        required: false
    image:
        description:
            - Image to set as active
        required: false
    gather_facts:
        description:
            - Acquire current versions
        default: false
        required: false
    unit:
        description:
            - Stack unit
        default: 1
        required: false
"""

EXAMPLES = """
# Set version 1.4.0.59 as active firmware
- ciscosb_firmware: version=1.4.0.59

# Set image 2 as active firmware
- ciscosb_firmware: image=2

# Query facts about current firmware
- ciscosb_firmware: gather_facts=yes
"""

import snmp

OID_RND_DEVICE_PARAMS = '1.3.6.1.4.1.9.6.1.101.2'

OID_RND_ACTIVE_SOFTWARE_FILE_ENTRY = OID_RND_DEVICE_PARAMS + '.13.1.1'
OID_RND_ACTIVE_SOFTWARE_FILE = OID_RND_ACTIVE_SOFTWARE_FILE_ENTRY + '.2'
OID_RND_ACTIVE_SOFTWARE_FILE_AFTER_RESET = OID_RND_ACTIVE_SOFTWARE_FILE_ENTRY + '.3'

OID_RND_IMAGE_INFO_ENTRY = OID_RND_DEVICE_PARAMS + '.16.1.1'
OID_RND_IMAGE1_VERSION = OID_RND_IMAGE_INFO_ENTRY + '.4'
OID_RND_IMAGE2_VERSION = OID_RND_IMAGE_INFO_ENTRY + '.5'

IMAGE1 = 1
IMAGE2 = 2
INVALID_IMAGE = 3

def main():
    module = AnsibleModule(
        argument_spec = dict(
            version = dict(required=False),
            image = dict(required=False, choices=['1', '2']),
            gather_facts = dict(required=False, type='bool', choices=BOOLEANS, default=False),
            unit = dict(required=False, type='int', default=1)
        ),
        mutually_exclusive=[['version', 'image']],
        required_one_of=[['version', 'image', 'gather_facts']],
        supports_check_mode=True
    )

    params = module.params

    version = params['version']
    image = params['image']
    gather_facts = params['gather_facts']
    unit = params['unit']

    try:
        client = snmp.SnmpClient()

        oid_rnd_active_software_file = OID_RND_ACTIVE_SOFTWARE_FILE + '.' + str(unit)
        oid_rnd_active_software_file_after_reset = OID_RND_ACTIVE_SOFTWARE_FILE_AFTER_RESET + '.' + str(unit)
        oid_rnd_image1_version = OID_RND_IMAGE1_VERSION + '.' + str(unit)
        oid_rnd_image2_version = OID_RND_IMAGE2_VERSION + '.' + str(unit)

        """ Gather facts """
        values = client.get(
                            oid_rnd_active_software_file,
                            oid_rnd_active_software_file_after_reset,
                            oid_rnd_image1_version,
                            oid_rnd_image2_version
                           )
        
        active_image = int(values[oid_rnd_active_software_file])
        reset_image = int(values[oid_rnd_active_software_file_after_reset])
        version1 = str(values[oid_rnd_image1_version])
        version2 = str(values[oid_rnd_image2_version])

        """ Prepare to change image file after reset """
        var_binds = dict()
        if image:
            if reset_image != int(image):
                var_binds[oid_rnd_active_software_file_after_reset] = snmp.Integer32(image)
        elif version:
            if version1 == version:
                if reset_image != IMAGE1:
                    var_binds[oid_rnd_active_software_file_after_reset] = snmp.Integer32(IMAGE1)
            elif version2 == version:
                if reset_image != IMAGE2:
                    var_binds[oid_rnd_active_software_file_after_reset] = snmp.Integer32(IMAGE2)
            else:
                module.fail_json(msg="No firmware with that version found")

        """ Generate facts """
        if gather_facts:
            facts = dict(
                ciscosb_firmware_active_image = active_image,
                ciscosb_firmware_reset_image = reset_image,
                ciscosb_firmware_version1 = version1,
                ciscosb_firmware_version2 = version2
            )

            if active_image == IMAGE1:
                facts['ciscosb_firmware_active_version'] = version1
            elif active_image == IMAGE2:
                facts['ciscosb_firmware_active_version'] = version2
            else:
                facts['ciscosb_firmware_active_version'] = 'unknown'

            if reset_image == IMAGE1:
                facts['ciscosb_firmware_reset_version'] = version1
            elif reset_image == IMAGE2:
                facts['ciscosb_firmware_reset_version'] = version2
            else:
                facts['ciscosb_firmware_reset_version'] = 'unknown'

        """ Finalize """
        if var_binds:
            changed = True
        else:
            changed = False

        if not module.check_mode:
            client.set(var_binds)
 
        if gather_facts:
            module.exit_json(changed=changed, ansible_facts=facts)
        else:
            module.exit_json(changed=changed)

    except snmp.SnmpError as e:
        module.fail_json(msg=str(e))

from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
