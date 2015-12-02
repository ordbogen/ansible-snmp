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

DOCUMENATION = """
module: ciscosb_copy
short_description: Copy files to/from CiscoSB switches
description:
    - Copy files to or from CiscoSB switches
    - Requires the snmp connection plugin
author: "Peter Nørlund, @pchri03"
options:
    src:
        description:
            - URL to copy from. Supports multiple URL schemes:
            - local:///runnning-config
            - local:///startup-config
            - local:///backup-config
            - local:///image
            - local:///boot
            - local:///logging
            - local:///mirror-config
            - another-unit://UNIT/PATH where UNIT is the unit number in a multi stack environmenent and PATH is the same kind of path as with local://
            - tftp://IP/FILE
            - scp://IP/FILE
            - http://IP/FILE
            - https://IP/FILE
        required: true
    dest:
        description:
            - URL to copy to. See src
        required: true
    secure-data:
        description:
            - Specify how to handle secure data
        choices: [ 'exclude', 'include-encrypted', 'include-decrypted', 'default' ]
        default: default
"""

import snmp
import urlparse
import random
import time

OID_RL_COPY = '1.3.6.1.4.1.9.6.1.101.87'

OID_RL_COPY_ENTRY = OID_RL_COPY + '.2.1'

OID_RL_COPY_ROW_STATUS = OID_RL_COPY_ENTRY + '.17'
OID_RL_COPY_HISTORY_INDEX = OID_RL_COPY_ENTRY + '.18'

OID_RL_COPY_HISTORY_ENTRY = OID_RL_COPY + '.4.1'

OID_RL_COPY_HISTORY_OPERATION_STATE = OID_RL_COPY_HISTORY_ENTRY + '.14'
OID_RL_COPY_HISTORY_ROW_STATUS = OID_RL_COPY_HISTORY_ENTRY + '.17'
OID_RL_COPY_HISTORY_ERROR_MESSAGE = OID_RL_COPY_HISTORY_ENTRY + '.18'

""" Values for rlCopySourceLocation and rlCopyDestinationLocation """
LOCATION_LOCAL = 1
LOCATION_ANOTHER_UNIT = 2
LOCATION_TFTP = 3
LOCATION_XMODEM = 4
LOCATION_SCP = 5
LOCATION_SERIAL = 6
LOCATION_HTTP = 7
LOCATION_HTTPS = 8
LOCATION_HTTP_XML = 9
LOCATION_HTTPS_XML = 10

""" Relative index of columns in rlCopyTable """
OFFSET_LOCATION = 0
OFFSET_IP_ADDRESS = 1
OFFSET_UNIT_NUMBER = 2
OFFSET_FILE_NAME = 3
OFFSET_FILE_TYPE = 4

""" Values for rlCopyRowStatus and rlCopyHistoryRowStatus """
ROW_STATUS_ACTIVE = 1
ROW_STATUS_NOT_IN_SERVICE = 2
ROW_STATUS_NOT_READY = 3
ROW_STATUS_CREATE_AND_GO = 4
ROW_STATUS_CREATE_AND_WAIT = 5
ROW_STATUS_DESTROY = 6

""" Values for rlCopyHistoryOperationState """
STATE_UPLOAD_IN_PROGRESS = 1
STATE_DOWNLOAD_IN_PROGRESS = 2
STATE_COPY_FAILED = 3
STATE_COPY_TIMEDOUT = 4
STATE_COPY_FINISHED = 5

def path_to_file_type(path):
    if path == '/running-config':
        return 2
    elif path == '/startup-config':
        return 3
    elif path == '/backup-config':
        return 4
    elif path == '/image':
        return 8
    elif path == '/boot':
        return 9
    elif path == '/logging':
        return 11
    elif path == '/mirror-config':
        return 12
    else:
        return None

def url_to_var_binds(url, copy_index, offset, var_binds):
    url_info = urlparse.urlparse(url)

    oid_copy_location    = OID_RL_COPY_ENTRY + '.' + str(offset + OFFSET_LOCATION) + '.' + str(copy_index)
    oid_copy_ip_address  = OID_RL_COPY_ENTRY + '.' + str(offset + OFFSET_IP_ADDRESS) + '.' + str(copy_index)
    oid_copy_unit_number = OID_RL_COPY_ENTRY + '.' + str(offset + OFFSET_UNIT_NUMBER) + '.' + str(copy_index)
    oid_copy_file_name   = OID_RL_COPY_ENTRY + '.' + str(offset + OFFSET_FILE_NAME) + '.' + str(copy_index)
    oid_copy_file_type   = OID_RL_COPY_ENTRY + '.' + str(offset + OFFSET_FILE_TYPE) + '.' + str(copy_index)

    scheme = url_info[0]
    if scheme in ('local', 'another-unit'):
        file_type = path_to_file_type(url_info[2])
        if not file_type:
            return False

        var_binds[oid_copy_location] = snmp.Integer32(LOCATION_LOCAL)
        if scheme == 'another-unit':
            var_binds[oid_copy_unit_number] = snmp.Integer32(int(url_info[1]))
        var_binds[oid_copy_file_type] = snmp.Integer32(file_type)
        return True

    if scheme in ('tftp', 'scp', 'http', 'https'):
        ip = url_info[1]
        path = url_info[2]

        if scheme == 'tftp':
            var_binds[oid_copy_location] = snmp.Integer32(LOCATION_TFTP)
        elif scheme == 'scp':
            var_binds[oid_copy_location] = snmp.Integer32(LOCATION_SCP)
        elif scheme == 'http':
            var_binds[oid_copy_location] = snmp.Integer32(LOCATION_HTTP)
        elif scheme == 'https':
            var_binds[oid_copy_location] = snmp.Integer32(LOCATION_HTTPS)

        var_binds[oid_copy_ip_address] = snmp.IpAddress(ip)
        var_binds[oid_copy_file_name] = snmp.OctetString(path)
        return True

    return False

def main():
    module = AnsibleModule(
        argument_spec = dict(
            src = dict(required=True),
            dest = dict(required=True),
            secure_data = dict(required=False, choices=['exclude', 'include-encrypted', 'include-decrypted', 'default'], default='default')
        )
    )

    params = module.params

    src = params['src']
    dest = params['dest']
    secure_data = params['secure_data']

    try:
        client = snmp.SnmpClient()

        copy_index = random.randint(1, 2147483647)
        copy_history_index = copy_index

        oid_rl_copy_row_status = OID_RL_COPY_ROW_STATUS + '.' + str(copy_index)
        oid_rl_copy_history_index = OID_RL_COPY_HISTORY_INDEX + '.' + str(copy_index)
        
        oid_rl_copy_history_operation_state = OID_RL_COPY_HISTORY_OPERATION_STATE + '.' + str(copy_history_index)
        oid_rl_copy_history_row_status = OID_RL_COPY_HISTORY_ROW_STATUS + '.' + str(copy_history_index)
        oid_rl_copy_history_error_message = OID_RL_COPY_HISTORY_ERROR_MESSAGE + '.' + str(copy_history_index)

        var_binds = dict()
        if not url_to_var_binds(src, copy_index, 3, var_binds):
            module.fail_json(msg='Invalid source url')
        if not url_to_var_binds(dest, copy_index, 8, var_binds):
            module.fail_json(msg='Invalid destination url')
        var_binds[oid_rl_copy_row_status] = snmp.Integer32(ROW_STATUS_CREATE_AND_GO)
        var_binds[oid_rl_copy_history_index] = snmp.Integer32(copy_history_index)

        client.set(var_binds)

        while True:
            values = client.get(oid_rl_copy_history_operation_state)
            state = int(values[oid_rl_copy_history_operation_state])
            if state != STATE_UPLOAD_IN_PROGRESS and state != STATE_DOWNLOAD_IN_PROGRESS:
                break
            time.sleep(5)

        if state != STATE_COPY_FINISHED:
            try:
                values = client.get(oid_rl_copy_history_error_message)
                error_message = str(values[oid_rl_copy_history_error_message])
            except snmp.SnmpError as e:
                error_message = None

        var_binds = dict();
        var_binds[oid_rl_copy_history_row_status] = snmp.Integer32(ROW_STATUS_DESTROY)
        client.set(var_binds)

        if state == STATE_COPY_FINISHED:
            module.exit_json(changed=True)
        elif error_message:
            module.fail_json(msg=error_message)
        elif state == STATE_COPY_TIMEDOUT:
            module.fail_json(msg='Copy timed out')
        else:
            module.fail_json(msg='Copy failed')

    except snmp.SnmpError as e:
        module.fail_json(msg=str(e))

from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
