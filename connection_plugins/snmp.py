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
import json
import syslog
import traceback
import base64

from ansible import utils, constants, errors
from ansible.callbacks import vvv
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.entity.rfc3413.oneliner import mibvar
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905

__all__ = ['Connection',
           'SnmpValue', 'OctetString', 'ObjectIdentifier', 'Integer32', 'Counter32', 'IpAddress', 'Gauge32', 'TimeTicks', 'Opaque', 'Counter64',
           'SnmpPeer', 'SnmpClient', 'SnmpError']

snmp_connection_cache = dict()
snmp_constants = None

class Connection(object):
    """ SNMP based connections """

    def __init__(self, runner, host, port, *args, **kwargs):
        self.runner = runner
        self.host = host
        self.port = port if port else 161
        self.has_pipelining = False

        p = constants.load_config_file()
        self.SNMP_AUTH_PROTOCOL = constants.get_config(p, 'snmp', 'auth_protocol', 'SNMP_AUTH_PROTOCOL', 'none').lower()
        self.SNMP_PRIV_PROTOCOL = constants.get_config(p, 'snmp', 'priv_protocol', 'SNMP_PRIV_PROTOCOL', 'none').lower()
        self.SNMP_ENGINE_ID     = constants.get_config(p, 'snmp', 'engine_id', 'SNMP_ENGINE_ID', None)
        self.SNMP_COMMUNITY     = constants.get_config(p, 'snmp', 'community', 'SNMP_COMMUNITY', None)
        self.SNMP_AUTH_KEY      = constants.get_config(p, 'snmp', 'auth_key', 'SNMP_AUTH_KEY', None)
        self.SNMP_PRIV_KEY      = constants.get_config(p, 'snmp', 'priv_key', 'SNMP_PRIV_KEY', None)

    def _get_snmp_auth(self):
        """ Get SNMP auth object """

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
        server = SnmpServer(pipe_in, pipe_out, self.host, self.port, self.snmp_auth)
        server.run()

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

                server = SnmpServer(pipe_to_server[0], pipe_from_server[1], self.host, self.port, self.snmp_auth)
                server.run()
                os._exit(0)
            elif pid == -1:
                raise errors.AnsibleError('Unable to fork')
            else:
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

        # os.environ is special, so we copy it into a dictionary and modify the dictionary instead
        env = dict()
        for key in os.environ.keys():
            env[key] = os.environ[key]
        env['SNMP_PIPE_IN'] = str(self.snmp_pipe_in)
        env['SNMP_PIPE_OUT'] = str(self.snmp_pipe_out)

        if 'PYTHONPATH' in env:
            env['PYTHONPATH'] = os.path.dirname(__file__) + ':' + env['PYTHONPATH']
        else:
            env['PYTHONPATH'] = os.path.dirname(__file__)

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
        """ transfer a file from local to local """
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

class SnmpError(Exception):
    pass

class SnmpValue(object):
    def __str__(self):
        return str(self.value)

class OctetString(SnmpValue):
    def __init__(self, value):
        self.value = str(value)

class ObjectIdentifier(SnmpValue):
    def __init__(self, value):
        subids = []
        for subid in str(value).split('.'):
            subids.append(str(int(subid)))
        self.value = '.'.join(subids)

class Integer32(SnmpValue):
    pass

class Counter32(SnmpValue):
    pass

class IpAddress(SnmpValue):
    pass

class Gauge32(SnmpValue):
    pass

class TimeTicks(SnmpValue):
    pass

class Opaque(SnmpValue):
    pass

class Counter64(SnmpValue):
    pass

class SnmpPeer(object):
    def __init__(self, fd_in, fd_out):
        self.stream_in = os.fdopen(fd_in, 'rU')
        self.stream_out = os.fdopen(fd_out, 'w')

    def _send(self, data):
        line = '%s\n' % json.dumps(data, default=self._default_hook)
        syslog.syslog('_send: %s' % line)
        self.stream_out.write(line)
        self.stream_out.flush()

    def _recv(self):
        line = self.stream_in.readline()
        syslog.syslog('_recv: %s' % line)
        return json.loads(line, object_hook=self._object_hook)

    def _default_hook(self, o):
        if isinstance(o, OctetString):
            return dict(__jsonclass__=['OctetString', base64.b64encode(o.value)])
        if isinstance(o, Opaque):
            return dict(__jsonclass__=['Opaque', self._default_hook(o.value)])
        if isinstance(o, NoSuchObject):
            return None
        if isinstance(o, NoSuchInstance):
            return None
        if isinstance(o, EndOfMibView):
            return None
        if isinstance(o, SnmpValue):
            return dict(__jsonclass__=[type(o).__name__, o.value])
        raise ValueError('Unsupported object type')

    def _object_hook(self, o):
        if not isinstance(o, dict):
            return o
        if '__jsonclass__' in o:
            data = o['__jsonclass__']
            constructor = data[0]
            if constructor == 'OctetString':
                return OctetString(base64.b64decode(data[1]))
            if constructor == 'ObjectIdentifier':
                return ObjectIdentifier(data[1])
            if constructor == 'Integer32':
                return Integer32(data[1])
            if constructor == 'IpAddress':
                return IpAddress(data[1])
            if constructor == 'Gauge32':
                return Gauge32(data[1])
            if constructor == 'TimeTicks':
                return TimeTicks(data[1])
            if constructor == 'Opaque':
                return Opaque(self._object_hook(data[1]))
            if constructor == 'Counter64':
                return Counter64(data[1])
            raise ValueError('Unsupported object type')
        return o

class SnmpServer(SnmpPeer):
    def __init__(self, fd_in, fd_out, host, port, auth):
        super(SnmpServer, self).__init__(fd_in, fd_out)
        self.auth = auth
        self.transport = cmdgen.UdpTransportTarget((host, port))
        self.generator = cmdgen.CommandGenerator()

    def run(self):
        try:
            while True:
                request = self._recv()

                method_name = request['method']
                params = request['params']

                method = getattr(self, method_name)
                try:
                    result = method(*params)
                    self._send(dict(jsonrpc='2.0', result=result, id=request['id']))
                except Exception as e:
                    trace = traceback.format_exc().splitlines()
                    syslog.syslog(str(e))
                    for line in trace:
                        syslog.syslog(line)
                    self._send(dict(jsonrpc='2.0', error=dict(code=0, message=str(e)), id=request['id']))
        except Exception as e:
            trace = traceback.format_exc().splitlines()
            syslog.syslog(str(e))
            for line in trace:
                syslog.syslog(trace)

    def _to_pysnmp(self, value):
        """ Convert connection plugin object into pysnmp objects """
        if value is None:
            return None
        if isinstance(value, OctetString):
            return rfc1902.OctetString(str(value.value))
        if isinstance(value, ObjectIdentifier):
            return rfc1902.ObjectName(str(value.value))
        if isinstance(value, Integer32):
            return rfc1902.Integer32(int(value.value))
        if isinstance(value, Counter32):
            return rfc1902.Counter32(long(value.value))
        if isinstance(value, IpAddress):
            return rfc1902.IpAddress(str(value.value))
        if isinstance(value, Gauge32):
            return rfc1902.Gauge32(long(value.value))
        if isinstance(value, TimeTicks):
            return rfc1902.TimeTicks(long(value.value))
        if isinstance(value, Opaque):
            return rfc1902.Opaque(value.value) # FIXME
        if isinstance(value, Counter64):
            return rfc1902.Counter64(str(value.value))
        raise SnmpError('Invalid type: %s' % type(value).__name__)

    def _from_pysnmp(self, value):
        """ Convert pysnmp objects into connection plugin objects """
        if value is None:
            return None
        if isinstance(value, rfc1902.OctetString):
            return OctetString(str(value))
        if isinstance(value, rfc1902.ObjectName):
            return ObjectIdentifier(str(value))
        if isinstance(value, rfc1902.Integer32):
            return Integer32(int(value))
        if isinstance(value, rfc1902.Counter32):
            return Counter32(long(value))
        if isinstance(value, rfc1902.IpAddress):
            return IpAddress(str(value))
        if isinstance(value, rfc1902.Gauge32):
            return Gauge32(long(value))
        if isinstance(value, rfc1902.TimeTicks):
            return TimeTicks(long(value))
        if isinstance(value, Opaque):
            return Opaque(str(value)) # FIXME
        if isinstance(value, rfc1905.NoSuchObject):
            return None
        if isinstance(value, rfc1905.NoSuchInstance):
            return None
        if isinstance(value, rfc1905.EndOfMibView):
            return None
        raise SnmpError('Invalid type: %s' % type(value).__name__)

    def get(self, *object_ids):
        """ Fetch SNMP variables """
        var_names = []
        for object_id in object_ids:
            var_names.append(rfc1902.ObjectName(str(object_id)))
        error_indication, error_status, error_index, varbinds = self.generator.getCmd(self.auth, self.transport, *var_names)

        if error_indication:
            raise SnmpError(error_indication)
        if error_status:
            raise SnmpError(error_status.prettyPrint())

        res = list()
        for varbind in varbinds:
            res.append(self._from_pysnmp(varbind[1]))

        return res

    def set(self, var_binds):
        """ Set SNMP variables """
        pysnmp_var_binds = []
        for object_id, value in var_binds.items():
            pysnmp_var_binds.append((rfc1902.ObjectName(str(object_id)), self._to_pysnmp(value)))
        error_indication, error_status, error_index, varbinds = self.generator.setCmd(self.auth, self.transport, *pysnmp_var_binds)

        if error_indication:
            raise SnmpError(error_indication)
        if error_status:
            raise SnmpError(error_status.prettyPrint())

    def walk(self, var_names):
        """ Iterate SNMP variables """
        # TODO
        return None

class SnmpClient(SnmpPeer):
    """ SNMP API for the modules """

    def __init__(self):
        super(SnmpClient, self).__init__(int(os.getenv('SNMP_PIPE_IN')), int(os.getenv('SNMP_PIPE_OUT')))

    def _call(self, method, *params):
        self._send(dict(jsonrpc='2.0', method=method, params=params, id=1))
        result = self._recv()

        if 'error' in result:
            raise SnmpError(result['error']['message'])

        if 'result' in result:
            return result['result']

        return None

    def get(self, *var_names):
        """ Fetch SNMP variables """
        return self._call('get', *var_names)

    def set(self, var_binds):
        """ Set SNMP variables """
        self._call('set', var_binds)

    def walk(self, *var_names):
        """ Iterate SNMP variables """
        return self._call('walk', *var_names)

