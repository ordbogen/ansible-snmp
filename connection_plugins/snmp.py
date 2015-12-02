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
import select
import fcntl
import json
import syslog
import traceback
import base64
import asyncore
import time

from ansible import utils, constants, errors
from ansible.callbacks import vvv
from pysnmp.carrier.asynsock import dispatch
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.entity.rfc3413 import mibvar
from pysnmp.entity import engine
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905
from pyasn1.type import univ
from pysnmp.carrier.asynsock.dgram import udp

__all__ = ['Connection',
           'SnmpValue', 'OctetString', 'ObjectIdentifier', 'Integer32', 'Counter32', 'IpAddress', 'Gauge32', 'TimeTicks', 'Opaque', 'Counter64',
           'SnmpClient', 'SnmpError']

_cache = dict()
_snmp_engine = None

p = constants.load_config_file()
SNMP_AUTH_PROTOCOL = constants.get_config(p, 'snmp', 'auth_protocol', 'SNMP_AUTH_PROTOCOL', 'none').lower()
SNMP_PRIV_PROTOCOL = constants.get_config(p, 'snmp', 'priv_protocol', 'SNMP_PRIV_PROTOCOL', 'none').lower()
SNMP_ENGINE_ID     = constants.get_config(p, 'snmp', 'engine_id', 'SNMP_ENGINE_ID', None)
SNMP_COMMUNITY     = constants.get_config(p, 'snmp', 'community', 'SNMP_COMMUNITY', None)
SNMP_AUTH_KEY      = constants.get_config(p, 'snmp', 'auth_key', 'SNMP_AUTH_KEY', None)
SNMP_PRIV_KEY      = constants.get_config(p, 'snmp', 'priv_key', 'SNMP_PRIV_KEY', None)

class Connection(object):
    """ SNMP based connections """

    def __init__(self, runner, host, port, *args, **kwargs):
        self.runner = runner
        self.host = host
        self.port = port if port else 161
        self.has_pipelining = False

    def _get_snmp_auth(self):
        """ Get SNMP auth object """

        # If become_method is snmp we assume SNMPv3
        if not self.runner.become or self.runner.become_method != 'snmp':
            if SNMP_COMMUNITY is None:
                raise errors.AnsibleError('Missing SNMP community or become_method is not snmp')

            return cmdgen.CommunityData(SNMP_COMMUNITY)

        if self.runner.become_user is None:
            raise errors.AnsibleError('Missing become_user setting')

        # Authentication protocol
        auth_key = SNMP_AUTH_KEY
        if auth_key is None:
            auth_key = self.runner.become_pass
        if SNMP_AUTH_PROTOCOL == 'md5':
            auth_protocol = cmdgen.usmHMACMD5AuthProtocol
        elif SNMP_AUTH_PROTOCOL == 'sha':
            auth_protocol = cmdgen.usmHMACSHAAuthProtocol
        elif SNMP_AUTH_PROTOCOL == 'none':
            auth_protocol = cmdgen.usmNoAuthProtocol
            auth_key = None
        else:
            raise errors.AnsibleError('Unsupported SNMP authentication protocol: %s' % SNMP_AUTH_PROTOCOL)

        # Privacy protocol
        priv_key = SNMP_PRIV_KEY
        if priv_key is None:
            priv_key = self.runner.become_pass
        if SNMP_PRIV_PROTOCOL == 'des':
            priv_protocol = cmdgen.usmDESPrivProtocol
        elif SNMP_PRIV_PROTOCOL == 'aes':
            priv_protocol = cmdgen.usmAesCfb128Protocol
        elif SNMP_PRIV_PROTOCOL == 'none':
            priv_protocol = cmdgen.usmNoPrivProtocol
            priv_key = None
        else:
            raise errors.AnsibleError('Unsupported SNMP privacy protocol: %s' % SNMP_PRIV_PROTOCOL)

        return cmdgen.UsmUserData(self.runner.become_user,
                                  authProtocol=auth_protocol, authKey=auth_key,
                                  privProtocol=priv_protocol, privKey=priv_key,
                                  contextEngineId=SNMP_ENGINE_ID)

    def _get_snmp_connection(self):
        key = '%s:%d' % (self.host, self.port)
        if key in _cache:
            return _cache[key]

        conn = _SnmpConnection(self.host, self.port, self._get_snmp_auth())
        _cache[key] = conn
        return conn

    def connect(self, port=None):
        return self

    def exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable='/bin/sh', in_data=None):
        if in_data:
            raise errors.AnsibleError('Internal Error: this modules does not support optimized module pipelining')
       
        if executable:
            local_cmd = executable.split() + ['-c', cmd]
        else:
            local_cmd = cmd
        executable = executable.split()[0] if executable else None

        pipe_to_server = os.pipe()
        pipe_from_server = os.pipe()

        # os.environ is special, so we copy it into a dictionary and modify the dictionary instead
        env = dict()
        for key in os.environ.keys():
            env[key] = os.environ[key]
        env['SNMP_PIPE_IN'] = str(pipe_from_server[0])
        env['SNMP_PIPE_OUT'] = str(pipe_to_server[1])

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

        # pysnmp insist on using its own socket map, so we use that instead
        conn = self._get_snmp_connection()
        sock_map = conn.dispatcher.getSocketMap()
        stdout = _BufferedDispatcher(asyncore.file_wrapper(p.stdout.fileno()), map=sock_map)
        stderr = _BufferedDispatcher(asyncore.file_wrapper(p.stderr.fileno()), map=sock_map)
        server = _Server(conn, pipe_to_server[0], pipe_from_server[1], map=sock_map)

        while stdout.readable() or stderr.readable():
            asyncore.poll(0.5, map=sock_map)
            conn.dispatcher.handleTimerTick(time.time())

        p.wait()

        os.close(pipe_to_server[0])
        os.close(pipe_to_server[1])
        os.close(pipe_from_server[0])
        os.close(pipe_from_server[1])
        
        return (p.returncode, '', stdout.data, stderr.data)

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

class _SnmpConnection(object):
    def __init__(self, host, port, auth):
        self.dispatcher = dispatch.AsynsockDispatcher()
        self.engine = engine.SnmpEngine()
        self.engine.registerTransportDispatcher(self.dispatcher)
        self.generator = cmdgen.AsynCommandGenerator(self.engine)
        self.auth = auth
        self.transport = cmdgen.UdpTransportTarget((host, port))

    def get(self, object_ids, callback):
        self.generator.getCmd(self.auth, self.transport, object_ids, callback)

    def set(self, var_binds, callback):
        self.generator.setCmd(self.auth, self.transport, var_binds, callback)

    def get_bulk(self, var_names, callback, non_repeaters=0, max_repetitions=10):
        self.generator.bulkCmd(self.auth, self.transport, non_repeaters, max_repetitions, var_names, callback)

class _BufferedDispatcher(asyncore.file_dispatcher):
    def __init__(self, fd, map=None):
        asyncore.file_dispatcher.__init__(self, fd, map)
        self.data = ''
        self._finished = False

    def handle_expt(self):
        pass

    def handle_read(self):
        chunk = self.recv(1024)
        if chunk:
            self.data = self.data + chunk
        else:
            self._finished = True

    def readable(self):
        return not self._finished

    def writable(self):
        return False


class _ReceiveDispatcher(asyncore.file_dispatcher):
    def __init__(self, fd, server, map=None):
        asyncore.file_dispatcher.__init__(self, fd, map)
        self._server = server
        self._buffer = ''
        self._finished = False

    def readable(self):
        return not self._finished

    def writable(self):
        return False

    def handle_expt(self):
        pass

    def handle_read(self):
        chunk = self.recv(1024)
        if not chunk:
            self._finished = True
            return

        self._buffer = self._buffer + chunk
        while True:
            pos = self._buffer.find('\n')
            if pos == -1:
                break
            line = self._buffer[:pos]
            pos = pos + 1
            self._buffer = self._buffer[pos:]

            self._server.handle_line(line)

class _TransmitDispatcher(asyncore.file_dispatcher):
    def __init__(self, fd, map=None):
        asyncore.file_dispatcher.__init__(self, fd, map)
        self._buffer = ''

    def send_line(self, line):
        self._buffer = self._buffer + line + '\n'

    def readable(self):
        return False

    def writable(self):
        if self._buffer:
            return True
        else:
            return False

    def handle_expt(self):
        pass

    def handle_write(self):
        cnt = self.send(self._buffer)
        self._buffer = self._buffer[cnt:]
        pass

class _JsonRpcPeer(object):
    def __init__(self):
        pass

    def transmit(self, json):
        pass

    def serialize(self, value):
        return json.dumps(value, default=self._default_hook)

    def unserialize(self, data):
        return json.loads(data, object_hook=self._object_hook)

    def send(self, **kwargs):
        self.transmit(self.serialize(kwargs) + '\n')

    def _default_hook(self, o):
        """ Convert object into JSON compatible objects """
        if isinstance(o, OctetString):
            return dict(__jsonclass__=['OctetString', base64.b64encode(o.value)])
        if isinstance(o, Opaque):
            return dict(__jsonclass__=['Opaque', self._default_hook(o.value)])
        if isinstance(o, Integer32):
            return dict(__jsonclass__=['Integer32', o.value])
        if isinstance(o, SnmpValue):
            return dict(__jsonclass__=[type(o).__name__, o.value])
        raise ValueError('Unsupported object type: %s' % o.__class__.__name__)

    def _object_hook(self, o):
        """ Convert JSON data into objects """
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
            raise ValueError('Unsupported object type: %s' % constructor)
        return o

class _Server(_JsonRpcPeer):
    def __init__(self, conn, pipe_in, pipe_out, map=None):
        self._conn = conn
        self._receiver = _ReceiveDispatcher(pipe_in, self, map)
        self._transmitter = _TransmitDispatcher(pipe_out, map)

    def transmit(self, json):
        self._transmitter.send(json)

    def handle_line(self, line):
        request = self.unserialize(line)
        method = request['method']
        params = request['params']
        id = request['id']
        
        method_name = 'rpc_' + method

        method = getattr(self, method_name)
        method(id, *params)

    def _send_result(self, id, result):
        self.send(jsonrpc='2.0', result=result, id=id)

    def _send_error(self, id, error):
        self.send(jsonrpc='2.0', error=dict(code=0, message=error), id=id)

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
        raise SnmpError('Invalid type: %s' % value.__class__.__name__)

    def _from_pysnmp(self, value):
        """ Convert pysnmp objects into connection plugin objects """
        if value is None:
            return None
        if isinstance(value, rfc1902.OctetString):
            return OctetString(str(value))
        if isinstance(value, rfc1902.ObjectName):
            return ObjectIdentifier(str(value))
        if isinstance(value, univ.Integer):
            return Integer32(int(value))
        if isinstance(value, rfc1902.Counter32):
            return Counter32(long(value))
        if isinstance(value, rfc1902.IpAddress):
            return IpAddress(str(value))
        if isinstance(value, rfc1902.Gauge32):
            return Gauge32(long(value))
        if isinstance(value, rfc1902.TimeTicks):
            return TimeTicks(long(value))
        if isinstance(value, rfc1902.Opaque):
            return Opaque(str(value)) # FIXME
        if isinstance(value, rfc1905.NoSuchObject):
            return None
        if isinstance(value, rfc1905.NoSuchInstance):
            return None
        if isinstance(value, rfc1905.EndOfMibView):
            return None
        raise SnmpError('Invalid type: %s' % type(value).__name__)

    def rpc_get(self, id, *object_ids):
        pysnmp_var_names = []
        for object_id in object_ids:
            pysnmp_var_names.append(rfc1902.ObjectName(str(object_id)))
        self._conn.get(pysnmp_var_names, (self._on_rpc_get, id))

    def _on_rpc_get(self, handle, error_indication, error_status, error_index, var_binds, ctx):
        id = ctx
        if error_indication:
            self._send_error(id, str(error_indication))
        elif error_status:
            self._send_error(id, error_status.prettyPrint())
        else:
            res = dict()
            for var_bind in var_binds:
                object_id = str(self._from_pysnmp(var_bind[0]))
                res[object_id] = self._from_pysnmp(var_bind[1])
            self._send_result(id, res)

    def rpc_set(self, id, var_binds):
        pysnmp_var_binds = []
        for object_id, value in var_binds.items():
            pysnmp_var_binds.append((rfc1902.ObjectName(str(object_id)), self._to_pysnmp(value)))
        self._conn.set(pysnmp_var_binds, (self._on_rpc_set, id))

    def _on_rpc_set(self, handle, error_indication, error_status, error_index, var_binds, ctx):
        id = ctx
        if error_indication:
            self._send_error(id, str(error_indication))
        elif error_status:
            self._send_error(id, error_status.prettyPrint())
        else:
            self._send_result(id, None)

    def rpc_walk(self, id, object_id):
        self._do_rpc_walk(id, str(object_id), str(object_id), dict())

    def _do_rpc_walk(self, id, request_object_id, object_id, res):
        pysnmp_var_names = [rfc1902.ObjectName(object_id)]
        self._conn.get_bulk(pysnmp_var_names, (self._on_rpc_walk, (id, request_object_id, res)))

    def _on_rpc_walk(self, handle, error_indication, error_status, error_index, var_bind_table, ctx):
        (id, request_object_id, res) = ctx
        if error_indication:
            self._send_error(id, str(error_indication))
        elif error_status:
            self._send_error(id, error_status.prettyPrint())
        else:
            prefix_len = len(request_object_id)
            last_object_id = None
            for var_binds in var_bind_table:
                for var_bind in var_binds:
                    object_id = str(self._from_pysnmp(var_bind[0]))
                    if object_id[:prefix_len] != request_object_id:
                        self._send_result(id, res)
                        return

                    idx = object_id[(prefix_len + 1):]
                    res[idx] = self._from_pysnmp(var_bind[1])
                    last_object_id = object_id

            if last_object_id is None:
                self._send_result(id, res)
            else:
                self._do_rpc_walk(id, request_object_id, last_object_id, res)

class SnmpError(Exception):
    pass

class SnmpValue(object):
    def __init__(self, value):
        self.value = value

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
    def __init__(self, value):
        self.value = int(value)

    def __int__(self):
        return self.value

    def __long__(self):
        return self.value

class Counter32(SnmpValue):
    def __init__(self, value):
        self.value = long(value)

    def __int__(self):
        return self.value

    def __long__(self):
        return self.value

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

class SnmpClient(_JsonRpcPeer):
    """ SNMP API for the modules """

    def __init__(self):
        self._pipe_in = os.fdopen(int(os.getenv('SNMP_PIPE_IN')), 'rU')
        self._pipe_out = os.fdopen(int(os.getenv('SNMP_PIPE_OUT')), 'w')

    def transmit(self, json):
        self._pipe_out.write(json)
        self._pipe_out.flush()

    def _call(self, method, *params):
        self.send(jsonrpc='2.0', method=method, params=params, id=1)
        line = self._pipe_in.readline()
        result = self.unserialize(line)

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

    def walk(self, var_name):
        """ Iterate SNMP variables """
        return self._call('walk', var_name)

