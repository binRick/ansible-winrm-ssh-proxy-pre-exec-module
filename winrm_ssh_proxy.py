#!/usr/bin/env python3
from __future__ import (absolute_import, division, print_function)
import itertools, logging, os, pwd, warnings, sys, subprocess, tempfile, json, time, atexit
from ansible import __version__ as ansible_version
from jinja2 import Environment
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.module_utils._text import to_text
from hashlib import sha256
from threading import Thread
from multiprocessing import Queue
from ansible.parsing.dataloader import DataLoader

del os.environ['http_proxy']
del os.environ['https_proxy']

LOCAL_ADDRESS = '127.150.190.200'
PORT_RANGE_START = 15000
AUTO_DELETE_TUNNEL_SCRIPTS = False
TUNNEL_SCRIPT_SUFFIX = '__winrm-proxy.sh'
DEBUG_MODE = True
DEBUG_SETUP_FILE = '/tmp/debug_{}.json'.format(TUNNEL_SCRIPT_SUFFIX)
SSH_TUNNEL_OBJECT = {
           'remote': {'host':'10.187.7.204','port':5986},
           'local': {'host':LOCAL_ADDRESS,'port':PORT_RANGE_START},
           'bastion': {'host':'10.187.7.11','user':'root','port':22},
           'timeout': 600,
           'interval': 2,
}
OPEN_PORTS_CMD = """
command netstat -alnt|command grep LISTEN|command grep '^tcp '|command tr -s ' '|command cut -d' ' -f4| command grep ^{{local.host}}|command cut -d':' -f2|command sort|command uniq
"""

SSH_TUNNEL_SCRIPT = """
#!/bin/bash
set -xe
cd /

command sudo command iptables -t nat -A OUTPUT -d {{remote.host}} -p tcp --dport {{remote.port}} -j DNAT --to-destination {{local.host}}:{{local.port}}
command sudo command iptables -t nat -A POSTROUTING -d {{remote.host}} -p tcp --dport {{remote.port}} -j MASQUERADE

command sudo command sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null

exec command ssh -F/dev/null -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -oProxyCommand=none -oControlMaster=no -oServerAliveInterval={{interval}} -oPort={{bastion.port}} -L {{local.host}}:{{local.port}}:{{remote.host}}:{{remote.port}} {{bastion.user}}@{{bastion.host}} "sleep {{timeout}}"
"""

with warnings.catch_warnings():
    warnings.filterwarnings('ignore')
    from ansible.plugins.callback import CallbackBase

try:
    from ansible import context
    cli_options = {key: value for key, value in context.CLIARGS.items()}
except ImportError:
    try:
        from __main__ import cli
        cli_options = cli.options.__dict__
    except ImportError:
        cli_options = {}

def normalizeScriptContents(S):
    LINES = []
    for l in S.split("\n"):
        LINES.append(" ".join(l.split()))
    return "\n".join(LINES)

def renderSshTunnelScript(SSH_TUNNEL_OBJECT):
    return normalizeScriptContents(Environment().from_string(SSH_TUNNEL_SCRIPT).render(
        SSH_TUNNEL_OBJECT,
    ).strip())


class AsynchronousFileReader(Thread):
    def __init__(self, fd, queue, proc):
        assert type(queue) == type(Queue())
        assert callable(fd.readline)
        Thread.__init__(self)
        self._fd = fd
        self._queue = queue
        self._proc = proc
    def run(self):
      try:
        for line in iter(self._fd.readline, ''):
            self._queue.put(line.decode().strip())
            time.sleep(.005)
      except Exception as e:
            pass
    def eof(self):
        time.sleep(.005)
        if (self._proc.poll()!=None):
            if DEBUG_MODE:
                print("[EOF] pid {} exited with code {}".format(self._proc.pid, self._proc.poll()))
            time.sleep(.01)
            self._proc.terminate()
            return True
        return not self.is_alive() and self._queue.empty()


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'winrm_ssh_proxy'

    def __init__(self):
        super(CallbackModule, self).__init__()
        self.env = json.loads(json.dumps(os.environ.copy()))
        self.shell = False
        self.proc = None
        self.netstat = None
        self.VARIABLE_MANAGER = None

    def cleanupProcess(self):
        try:
            print("[cleanupProcess]")
            if self.proc and self.proc.pid > 0 :
                print("[cleanupProcess] Terminating {}".format(PID))
                self.proc.kill()
                os.kill(self.proc.pid)
                time.sleep(1.0)
                EXIT_CODE = self.proc.returncode
                print("[cleanupProcess]    PID = {}".format(self.proc.pid))
                print("[cleanupProcess]    EXIT_CODE = {}".format(EXIT_CODE))
        except Exception as e:
            pass

    def setupTunnelProcess(self):
        processStartTime = int(time.time())
        atexit.register(self.cleanupProcess)

        self.netstat = {'ports':[]}
        self.OPEN_PORTS_CMD = Environment().from_string(OPEN_PORTS_CMD).render(SSH_TUNNEL_OBJECT).strip()
        self.proc = subprocess.Popen(self.OPEN_PORTS_CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/', env=self.env, shell=True)
        self.netstat['stdout'], self.netstat['stderr'] = self.proc.communicate()
        self.netstat['exit_code'] = self.proc.wait()
        self.netstat['stdout'] = self.netstat['stdout'].decode()
        self.netstat['stderr'] = self.netstat['stderr'].decode()
        
        for p in self.netstat['stdout'].strip().split("\n"):
            self.netstat['ports'].append(p.strip())

        if self.netstat['exit_code'] != 0:
            raise Exception('Unable to check locally listening ports :: {}'.format(self.OPEN_PORTS_CMD))    

        while SSH_TUNNEL_OBJECT['local']['port'] in self.netstat['ports']:
            SSH_TUNNEL_OBJECT['local']['port'] += 1
            if SSH_TUNNEL_OBJECT['local']['port'] > 65000:
                raise Exception("Unable to allocate local port!")
        SCRIPT_CONTENTS = renderSshTunnelScript(SSH_TUNNEL_OBJECT)
        SCRIPT_PATH = tempfile.NamedTemporaryFile(suffix=TUNNEL_SCRIPT_SUFFIX,delete=AUTO_DELETE_TUNNEL_SCRIPTS).name
        with open(SCRIPT_PATH,'w') as f:
            f.write(SCRIPT_CONTENTS)
            os.chmod(SCRIPT_PATH, 0o755)

        self.cmd = SCRIPT_PATH
        SSH_TUNNEL_PROCESS_IS_RUNNING = True
        processStartTime = int(time.time())
        if DEBUG_MODE:
            print(SSH_TUNNEL_OBJECT)


        stdoutLines = []
        stderrLines = []
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/', shell=self.shell, env=os.environ.copy())

        stdout_queue = Queue()
        stdout_reader = AsynchronousFileReader(self.proc.stdout, stdout_queue, self.proc)
        stdout_reader.start()
        stderr_queue = Queue()
        stderr_reader = AsynchronousFileReader(self.proc.stderr, stderr_queue, self.proc)
        stderr_reader.start()

        while not stdout_reader.eof() or not stderr_reader.eof():
            while not stderr_queue.empty():
                stderr = stderr_queue.get()
                stderrLines.append(stderr)
            while not stdout_queue.empty():
                line = stdout_queue.get()
                stdoutLines.append(line)

        self.proc.stdout.close()
        self.proc.stderr.close()
        exit_code = self.proc.wait()
        processEndTime = int(time.time())
        processRunTime = processEndTime - processStartTime

        return {
            "netstat": self.netstat,
            "cmd": self.cmd,
            "pid": self.proc.pid,
            "exit_code": exit_code,
            "processStartTime": processStartTime,
            "processEndTime": processEndTime,
            "processRunTime": processRunTime,
            "stderrLines": stderrLines,
            "stdoutLines": stdoutLines,
            "SSH_TUNNEL_OBJECT": SSH_TUNNEL_OBJECT,
            'SCRIPT_CONTENTS': SCRIPT_CONTENTS,
            'SCRIPT_PATH': SCRIPT_PATH,
        }

    def v2_playbook_on_start(self, playbook):
        PLAYBOOK_PATH = os.path.abspath(playbook._file_name)
#        TUNNEL_RESULT = self.setupTunnelProcess()
        TUNNEL_THREAD = Thread(target=self.setupTunnelProcess, args=[])
        TUNNEL_THREAD.thread = True
        TUNNEL_THREAD.start()

        time.sleep(8.0)

        SETUP = {
          'PLAYBOOK_PATH': PLAYBOOK_PATH,
#          'TUNNEL_PROCESS': json.loads(json.dumps(TUNNEL_RESULT)),
        }
        if DEBUG_MODE:
            print("DEBUG_SETUP_FILE={}".format(DEBUG_SETUP_FILE))
            with open(DEBUG_SETUP_FILE,'w') as f1:
                f1.write(json.dumps(SETUP))
