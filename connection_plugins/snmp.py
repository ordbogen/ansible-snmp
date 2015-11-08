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

import subprocess
import shutil
import os

from ansible import utils, constants, errors
from ansible.callbacks import vvv
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pyasn1.type import univ

snmp_connection_cache = dict()
snmp_constants = None

class Connection(object):
    ''' SNMP based connections '''

    def __init__(self, runner, host, port, *args, **kwargs):
        self.runner = runner
        self.host = host
        self.port = port if port else 161
        self.has_pipelining = False
        self.snmp_pipe_in = None
        self.snmp_pipe_out = None

        p = constants.load_config_file()
        self.SNMP_AUTH_PROTOCOL = constants.get_config(p, 'snmp', 'auth_protocol', 'SNMP_AUTH_PROTOCOL', 'none').lower()
        self.SNMP_PRIV_PROTOCOL = constants.get_config(p, 'snmp', 'priv_protocol', 'SNMP_PRIV_PROTOCOL', 'none').lower()
        self.SNMP_ENGINE_ID     = constants.get_config(p, 'snmp', 'engine_id', 'SNMP_ENGINE_ID', None)
        self.SNMP_COMMUNITY     = constants.get_config(p, 'snmp', 'community', 'SNMP_COMMUNITY', None)
        self.SNMP_AUTH_KEY      = constants.get_config(p, 'snmp', 'auth_key', 'SNMP_AUTH_KEY', None)
        self.SNMP_PRIV_KEY      = constants.get_config(p, 'snmp', 'priv_key', 'SNMP_PRIV_KEY', None)

    def _get_snmp_auth(self):
        ''' Get SNMP auth object '''

        # If become_method is snmp we assume SNMPv3
        if not self.runner.become or self.runner.become_method != 'snmp':
            if self.SNMP_COMMUNITY is None:
                raise errors.AnsibleError('Missing SNMP community or become_method is not snmp')

            return cmdgen.CommunityData(self.SNMP_COMMUNITY)

        if self.runner.become_user is None:
            raise errors.AnsibleError('Missing become_user setting')

        # Authentication protocol
        auth_key = self.SNMP_AUTH_KEY
        if auth_key is None:
            auth_key = self.runner.become_pass
        if self.SNMP_AUTH_PROTOCOL == 'md5':
            auth_protocol = cmdgen.usmHMACMD5AuthProtocol
        elif self.SNMP_AUTH_PROTOCOL == 'sha':
            auth_protocol = cmdgen.usmHMACSHAAuthProtocol
        elif self.SNMP_AUTH_PROTOCOL == 'none':
            auth_protocol = cmdgen.usmNoAuthProtocol
            auth_key = None
        else:
            raise errors.AnsibleError('Unsupported SNMP authentication protocol: %s' % self.SNMP_AUTH_PROTOCOL)

        # Privacy protocol
        priv_key = self.SNMP_PRIV_KEY
        if priv_key is None:
            priv_key = self.runner.become_pass
        if self.SNMP_PRIV_PROTOCOL == 'des':
            priv_protocol = cmdgen.usmDESPrivProtocol
        elif self.SNMP_PRIV_PROTOCOL == 'aes':
            priv_protocol = cmdgen.usmAesCfb128Protocol
        elif self.SNMP_PRIV_PROTOCOL == 'none':
            priv_protocol = cmdgen.usmNoPrivProtocol
            priv_key = None
        else:
            raise errors.AnsibleError('Unsupported SNMP privacy protocol: %s' % self.SNMP_PRIV_PROTOCOL)

        return cmdgen.UsmUserData(self.runner.become_user,
                                  authProtocol=auth_protocol, authKey=auth_key,
                                  privProtocol=priv_protocol, privKey=priv_key,
                                  securityEngineId=self.SNMP_ENGINE_ID)

    def _snmp_server(self, pipe_in, pipe_out):
        transport = cmdgen.UdpTransportTarget((self.host, self.port))
        generator = cmdgen.CommandGenerator()

        stream_in = os.fdopen(pipe_in, 'r')
        stream_out = os.fdopen(pipe_out, 'w')
        while True:
            line = stream_in.getline()
            if line is None:
                break

            # TODO

            stream_out.write(line)

    def connect(self, port=None):
        key = self.host + ':' + str(port if port else self.port)
        if key not in snmp_connection_cache:
            self.snmp_auth = self._get_snmp_auth()

            pipe_to_server = os.pipe()
            pipe_from_server = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(pipe_to_server[1])
                os.close(pipe_from_server[0])
                fd = os.open(os.devnull, os.O_RDWR)
                if fd != 0:
                    os.dup2(fd, 0)
                if fd != 1:
                    os.dup2(fd, 1)
                if fd != 2:
                    os.dup2(fd, 2)
                if fd not in (0, 1, 2):
                    os.close(fd)

                os.setsid()
                os.chdir('/')

                self._snmp_server(pipe_to_server[0], pipe_from_server[1])
                os._exit(0)
            elif pid == -1:
                raise errors.AnsibleError('Unable to fork')
            else:
                os.close(pipe_to_server[0])
                os.close(pipe_from_server[1])
                self.snmp_auth = None

                snmp_connection_cache[key] = (pipe_from_server[0], pipe_to_server[1])

        self.snmp_pipe_in = snmp_connection_cache[key][0]
        self.snmp_pipe_out = snmp_connection_cache[key][1]
        return self

    def exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable='/bin/sh', in_data=None):
        if in_data:
            raise errors.AnsibleError('Internal Error: this modules does not support optimized module pipelining')
       
        if executable:
            local_cmd = executable.split() + ['-c', cmd]
        else:
            local_cmd = cmd
        executable = executable.split()[0] if executable else None

        env = os.environ
        env['SNMP_PIPE_IN'] = str(self.snmp_pipe_in)
        env['SNMP_PIPE_OUT'] = str(self.snmp_pipe_out)

        vvv('EXEC %s' % (local_cmd), host=self.host)
        p = subprocess.Popen(local_cmd,
                             shell=isinstance(local_cmd, basestring),
                             cwd=self.runner.basedir,
                             executable=executable,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             env=env)
        stdout, stderr = p.communicate()
        return (p.returncode, '', stdout, stderr)

    def _transfer_file(self, in_path, out_path):
        ''' transfer a file from local to local '''
        if not os.path.exists(in_path):
            raise errors.AnsibleFileNotFound('file or modules does not exist: %s' % in_path)

        try:
            shutil.copyfile(in_path, out_path)
        except shutil.Error:
            raise errors.AnsibleError('failed to copy: %s and %s are the same' % (in_path, outpath))
        except IOError:
            raise errors.AnsibleError('failed to transfer file to %s' % out_path)

    def put_file(self, in_path, out_path):
        vvv('PUT %s to %s' % (in_path, out_path), host=self.host)
        self._transfer_file(in_path, out_path)

    def fetch_file(self, in_path, out_path):
        vvv('FETCH %s to %s' % (in_path, out_path), host=self.host)
        self._transfer_file(in_path, out_path)

    def close(self):
        pass
