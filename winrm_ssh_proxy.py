#!/usr/bin/env python3
from __future__ import (absolute_import, division, print_function)
import itertools, logging, os, pwd, warnings, sys, subprocess, tempfile, json, time, atexit, threading
from ansible import __version__ as ansible_version
from jinja2 import Environment
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.module_utils._text import to_text
from hashlib import sha256
from threading import Thread
from multiprocessing import Queue
from ansible.parsing.dataloader import DataLoader

for k in ['http_proxy','https_proxy']:
    if k in os.environ.keys():
       del os.environ[k]

TUNNEL_AVAILABLE = threading.Event()
TUNNEL = None
LOCAL_ADDRESS = '127.150.190.200'
PORT_RANGE_START = 18000
AUTO_DELETE_TUNNEL_SCRIPTS = False
TUNNEL_SCRIPT_SUFFIX = '__winrm-proxy.sh'
DEBUG_MODE = True
DEBUG_SETUP_FILE = '/tmp/debug_{}.json'.format(TUNNEL_SCRIPT_SUFFIX)
SSH_TUNNEL_OBJECT = {
           'remote': {'host':'10.187.22.222','port':5986},
           'local': {'host':LOCAL_ADDRESS,'port':PORT_RANGE_START},
           'bastion': {'host':'observium.xxxxxxxxx','user':'rblundell@xxxxxxxxxx','port':22,"ProxyCommand":"ssh -W %h:%p rblundell@xxxxxxxxxx@adminlinuxjumpserver.xxxxxxxxxxxxxx"},
           'timeout': 600,
           'interval': 2,
}
OPEN_PORTS_CMD = """
command netstat -alnt|command grep LISTEN|command grep '^tcp '|command tr -s ' '|command cut -d' ' -f4| command grep ^{{local.host}}|command cut -d':' -f2|command sort|command uniq
"""

SSH_TUNNEL_SCRIPT = """
#!/bin/bash
set -e
set +x
cd /

command sudo command iptables -t nat -A OUTPUT -d {{remote.host}} -p tcp --dport {{remote.port}} -j DNAT --to-destination {{local.host}}:{{local.port}}
command sudo command iptables -t nat -A POSTROUTING -d {{remote.host}} -p tcp --dport {{remote.port}} -j MASQUERADE

LocalCommand="echo OK > /tmp/lc"
LogLevel="ERROR"
command sudo command sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null
SSH_OPTIONS="-q -oGatewayPorts=no -oExitOnForwardFailure=yes -oClearAllForwardings=yes -oLogLevel=$LogLevel -oConnectTimeout=5 -oConnectionAttempts=5 -oForwardAgent=yes -oLocalCommand=\\\"${LocalCommand}\\\" -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -oControlMaster=no -oServerAliveInterval={{interval}} -oPort={{bastion.port}} -oUser=\\\"{{bastion.user}}\\\""
SSH_OPTIONS_PROXY="-oProxyCommand=\\\"{{bastion.ProxyCommand}}\\\""
SSH_OPTIONS_BATCH="-oBatchMode=yes -oPasswordAuthentication=no -oKbdInteractiveAuthentication=no -oChallengeResponseAuthentication=no"
PROXY_SSH_CMD="command ssh $SSH_OPTIONS $SSH_OPTIONS_BATCH $SSH_OPTIONS_PROXY -L {{local.host}}:{{local.port}}:{{remote.host}}:{{remote.port}} {{bastion.host}}"
PROXY_SSH_COPY_ID_CMD="command ssh-copy-id $SSH_OPTIONS {{bastion.host}}"

PROXY_SSH_CMD_TEST="${PROXY_SSH_CMD} pwd"
PROXY_SSH_CMD_SLEEP="${PROXY_SSH_CMD} sleep {{timeout}}"
echo "PROXY_SSH_CMD_TEST=$PROXY_SSH_CMD_TEST"
echo "PROXY_SSH_CMD_SLEEP=$PROXY_SSH_CMD_SLEEP"
set +e
eval "$PROXY_SSH_CMD_TEST"
exit_code=$?
if [[ "$exit_code" != "0" ]]; then
    echo Failed to test ssh cmd
    clear
#    echo "Ensuring Bastion host \"{{bastion.host}}\" has public key..."
#    eval "$PROXY_SSH_COPY_ID_CMD"
#    echo "OK"
#    exit_code=$?
#    if [[ "$exit_code" != "0" ]]; then
#        echo Failed to execute ssh-copy-id cmd
#        exit $exit_code
#    fi
fi
eval "$PROXY_SSH_CMD_SLEEP"
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
        self.hosts = None
        self.netstat = None
        self.play = None
        self.loader = None
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
            print(SCRIPT_PATH)
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
                print('stderr> {}'.format(stderr))
                print(stderr)
            while not stdout_queue.empty():
                stdout = stdout_queue.get()
                stdoutLines.append(stdout)
                print('stdout> {}'.format(stdout))

        self.proc.stdout.close()
        self.proc.stderr.close()
        exit_code = self.proc.wait()
        processEndTime = int(time.time())
        processRunTime = processEndTime - processStartTime

        time.sleep(15.0)
        TUNNEL_AVAILABLE.set()
        global TUNNEL
        TUNNEL = {
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




    def v2_playbook_on_play_start(self, *args, **kwargs):
        logging.debug("v2_playbook_on_play_start(self, *args, **kwargs)")
        self.play = args[0]  # Workaround for https://github.com/ansible/ansible/issues/13948
        self.loader = args[0]._loader
        self.hosts = args[0].get_variable_manager()._inventory.get_hosts()


    def v2_playbook_on_start(self, playbook):
        PLAYBOOK_PATH = os.path.abspath(playbook._file_name)
        TUNNEL_THREAD = Thread(target=self.setupTunnelProcess, args=[])
        TUNNEL_THREAD.daemon = True
        TUNNEL_THREAD.start()

        time.sleep(10.0)

        """
        while not TUNNEL_AVAILABLE.wait(timeout=30):
            print('\r{}% done...'.format(0), end='', flush=True)
            time.sleep(0.01)
        print('\r{}% done...'.format(100))
        """

        time.sleep(0.01)
        print('The tunnel state is {}'.format(TUNNEL))

        SETUP = {
          'PLAYBOOK_PATH': PLAYBOOK_PATH,
          'HOSTS': self.hosts,
          'PLAY': self.play,
          'LOADER': self.loader,
        }
        if DEBUG_MODE:
            print("DEBUG_SETUP_FILE={}".format(DEBUG_SETUP_FILE))
            with open(DEBUG_SETUP_FILE,'w') as f1:
                f1.write(json.dumps(SETUP))
