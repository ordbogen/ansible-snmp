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

from ansible import utils
from ansible.errors import AnsibleError
from ansible.callbacks import vvv

class Connection(object):
    ''' SNMP based connections '''

    def __init__(self, runner, host, port, *args, **kwargs):
        self.runner = runner
        self.host = host
        self.port = port
        self.has_pipelining = False
        self.snmp_fd = None
        self.snmp_pid = None
        pass

    def _snmp_server(self, fd):
        stream = os.popen(fd)
        line = stream.readline()
        stream.write(line)

    def connect(self, port=None):
        pipe = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(pipe[0])
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

            self._snmp_server(pipe[1])
            os._exit(0)
        elif pid == -1:
            raise errors.AnsibleError('Unable to fork')
        else:
            os.close(pipe[1])
            self.snmp_fd = pipe[0]
            self.snmp_pid = pid
        return self

    def exec_command(self, cmd, tmp_path, become_user=None, sudoable=False, executable='/bin/sh', in_data=None):
        if sudoable and self.runner.become:
            raise errors.AnsibleError('Internal Error: this modules does not support running commands via %s' % self.runner.become_method)

        if in_data:
            raise errors.AnsibleError('Internal Error: this modules does not support optimized module pipelining')
       
        if executable:
            local_cmd = executable.split() + ['-c', cmd]
        else:
            local_cmd = cmd
        executable = executable.split()[0] if executable else None

        env = os.environ
        env['SNMP_FD'] = str(self.snmp_fd)

        vvv('EXEC %s' % (local_cmd), host=self.host)
        p = subprocess.Popen(
                             local_cmd,
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
        os.close(self.snmp_fd)
        os.waitpid(self.snmp_pid, 0)
