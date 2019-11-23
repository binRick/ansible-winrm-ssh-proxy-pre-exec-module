#!/usr/bin/env python3
from __future__ import (absolute_import, division, print_function)
import itertools, logging, os, pwd, warnings, sys, subprocess, tempfile, json, time, atexit, threading, psutil
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

DEBUG_MODE = True
MONITOR_TUNNEL_INTERVAL = 1.0
IPTABLES_POLL_LOCK_INTERVAL_SECONDS = 10
IPTABLES_POLL_CHECK_LOCK_INTERVAL_MICROSECONDS = 10000
CLEANUP_IPTABLES_RULES_ON_EXIT = True
TUNNEL_AVAILABLE_ACTIVATION_DELAY = 1.5
TUNNEL_AVAILABLE = threading.Event()
TUNNEL = None
LOCAL_ADDRESS = '127.150.190.200'
PORT_RANGE_START = 18000
AUTO_DELETE_TUNNEL_SCRIPTS = False
TUNNEL_SCRIPT_SUFFIX = '__winrm-proxy.sh'
DEBUG_SETUP_FILE = '/tmp/debug_{}.json'.format(TUNNEL_SCRIPT_SUFFIX)
IPTABLES_COMMON_ARGS = "-w {} -W {}".format(IPTABLES_POLL_LOCK_INTERVAL_SECONDS, IPTABLES_POLL_CHECK_LOCK_INTERVAL_MICROSECONDS)
SSH_TUNNEL_OBJECT = {
           'remotes': [
                {'host':os.environ['REMOTE_HOST'],'port':os.environ['REMOTE_PORT']},
            ],
           'local': {'host':LOCAL_ADDRESS,'port':PORT_RANGE_START},
           'bastion': {'host':os.environ['BASTION_HOST'],'user':os.environ['BASTION_USER'],'port':os.environ['BASTION_PORT'],"ProxyCommand":os.environ['BASTION_PROXY_COMMAND']},
           'timeout': 600,
           'interval': 2,
           'IPTABLES_COMMON_ARGS': IPTABLES_COMMON_ARGS,
}

TEMP_DROP_RULES_CMD = """
{% if ACTION == 'D' %}
{%set ba = '&&' %}
{%else%}
{%set ba = '||' %}
{%endif%}
{%for remote in remotes%}
command sudo command iptables {{IPTABLES_COMMON_ARGS}} -L -n | grep '{{remote.host}}'|tr -s ' '| grep '^DROP tcp' |grep '0.0.0.0/0 {{remote.host}} tcp dpt:{{remote.port}}$' {{ba}} \
    command sudo command iptables {{IPTABLES_COMMON_ARGS}} -{{ACTION}} OUTPUT -d {{remote.host}} -p tcp --dport {{remote.port}} -j DROP
{%endfor%}
"""

OPEN_PORTS_CMD = """
command netstat -alnt|command grep LISTEN|command grep '^tcp '|command tr -s ' '|command cut -d' ' -f4| command grep ^{{local.host}}|command cut -d':' -f2|command sort|command uniq
"""

GET_DNATS_CMD = """
command sudo command iptables {{IPTABLES_COMMON_ARGS}} -L -n -t nat| command grep 'to:{{local.host}}:' | command grep 'tcp dpt' | command grep ^DNAT| command tr -s ' '
"""

GET_MASQUERADES_CMD = """
{%for remote in remotes%}
command sudo command iptables {{IPTABLES_COMMON_ARGS}} -L -n -t nat|grep ^MASQ| grep dpt:{{remote.port}}$|tr -s ' '|grep '0.0.0.0/0 {{remote.host}} tcp dpt:'
{%endfor%}
"""

DELETE_DNATS_CMD = """
{%for remote in remotes%}
command sudo command iptables {{IPTABLES_COMMON_ARGS}} -t nat -D OUTPUT -d {{remote.host}} -p tcp --dport {{remote.port}} -j DNAT --to-destination {{local.host}}:{{local.port}}
command sudo command iptables {{IPTABLES_COMMON_ARGS}} -t nat -D POSTROUTING -d {{remote.host}} -p tcp --dport {{remote.port}} -j MASQUERADE
{%endfor%}
"""

SSH_TUNNEL_SCRIPT = """
#!/bin/bash
set -e
set +x
cd /

{%for remote in remotes%}
command sudo command iptables {{IPTABLES_COMMON_ARGS}} -t nat -A OUTPUT -d {{remote.host}} -p tcp --dport {{remote.port}} -j DNAT --to-destination {{local.host}}:{{local.port}}
command sudo command iptables {{IPTABLES_COMMON_ARGS}} -t nat -A POSTROUTING -d {{remote.host}} -p tcp --dport {{remote.port}} -j MASQUERADE
{%endfor%}

LocalCommand="echo OK > /tmp/lc"
LogLevel="ERROR"
command sudo command sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null
SSH_OPTIONS="-q -oGatewayPorts=no -oExitOnForwardFailure=yes -oClearAllForwardings=no -oLogLevel=$LogLevel -oConnectTimeout=5 -oConnectionAttempts=5 -oForwardAgent=yes -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -oControlMaster=no -oServerAliveInterval={{interval}} -oPort={{bastion.port}} -oUser=\\\"{{bastion.user}}\\\""
SSH_OPTIONS_PROXY=\\\"\\\"
SSH_OPTIONS_PROXY="-oProxyCommand=\\\"{{bastion.ProxyCommand}}\\\""
SSH_OPTIONS_BATCH="-oBatchMode=yes -oPasswordAuthentication=no -oKbdInteractiveAuthentication=no -oChallengeResponseAuthentication=no"
PROXY_SSH_CMD="command ssh $SSH_OPTIONS $SSH_OPTIONS_BATCH $SSH_OPTIONS_PROXY {%for remote in remotes%} -L{{local.host}}:{{local.port}}:{{remote.host}}:{{remote.port}}{%endfor%} {{bastion.host}}"
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
fi
eval "$PROXY_SSH_CMD_SLEEP"
"""

if 'DEBUG_MODE' in os.environ.keys() and os.environ['DEBUG_MODE'] == '1':
    DEBUG_MODE = True

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

def tunnelSocketOpen():
    for c in psutil.net_connections('inet4'):
        if c.laddr.ip == SSH_TUNNEL_OBJECT['local']['host'] and c.laddr.port == SSH_TUNNEL_OBJECT['local']['port']:
            return True
    return False

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

    def removeDropRulesCommand(self):
         t = SSH_TUNNEL_OBJECT.copy()
         t['ACTION'] = 'D'
         return normalizeScriptContents(Environment().from_string(TEMP_DROP_RULES_CMD).render(t).strip()).splitlines()

    def createDropRulesCommand(self):
         t = SSH_TUNNEL_OBJECT.copy()
         t['ACTION'] = 'I'
         return normalizeScriptContents(Environment().from_string(TEMP_DROP_RULES_CMD).render(t).strip()).splitlines()

    def cleanupIptables(self):
            while len(self.getDnats()) > 0 or len(self.getMasquerades()) > 0:
                DELETE_IPTABLES_CMDS = normalizeScriptContents(Environment().from_string(DELETE_DNATS_CMD).render(SSH_TUNNEL_OBJECT).strip()).splitlines()
                for l in DELETE_IPTABLES_CMDS:
                    if DEBUG_MODE:
                        print("DELETE_IPTABLES_CMD={}".format(l))
                    proc = subprocess.Popen(l.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=False)
                    out, err = proc.communicate()
                    code = proc.wait()
                    if code != 0:
                        print("cmd={},out={},err={},code={}".format(l,out,err,code))
                time.sleep(0.1)

    def cleanupProcess(self):
        self.undropTrafficToHosts()
        if CLEANUP_IPTABLES_RULES_ON_EXIT:
            self.cleanupIptables()
        try:
            if DEBUG_MODE:
                print("[cleanupProcess]")
            if self.proc and self.proc.pid > 0 :
                if DEBUG_MODE:
                    print("[cleanupProcess] Terminating {}".format(PID))

                try:
                    self.proc.kill()
                    os.kill(self.proc.pid)
                except Exception as e:
                    pass

                time.sleep(0.5)
                EXIT_CODE = self.proc.returncode
                if DEBUG_MODE:
                    print("[cleanupProcess]    PID = {}".format(self.proc.pid))
                    print("[cleanupProcess]    EXIT_CODE = {}".format(EXIT_CODE))
        except Exception as e:
            pass

    def monitorTunnelThread(self, HOSTS):
        TUNNEL_FIRST_AVAILABLE_TIMESTAMP = None
        TUNNEL_LAST_AVAILABLE_TIMESTAMP = None
        TUNNEL_LAST_UNAVAILABLE_TIMESTAMP = None
        TUNNEL_LAST_CHECKED_TIMESTAMP = None
        while True:
            NOW = int(time.time())
            DNATS = self.getDnats()
            MASQUERADES = self.getMasquerades()
            if DEBUG_MODE:
                print("Detected {} DNAT Rules and {} MASQUERADE Rules...".format(len(DNATS),len(MASQUERADES)))
            if tunnelSocketOpen() and len(DNATS)>0 and len(MASQUERADES)>0:
                if DEBUG_MODE:
                    print("[monitorTunnelThread] TUNNEL IS AVAILABLE")
                if not TUNNEL_FIRST_AVAILABLE_TIMESTAMP:
                    TUNNEL_FIRST_AVAILABLE_TIMESTAMP = NOW
                TUNNEL_LAST_AVAILABLE_TIMESTAMP = NOW
                if not TUNNEL_AVAILABLE.is_set() and NOW > (TUNNEL_FIRST_AVAILABLE_TIMESTAMP + TUNNEL_AVAILABLE_ACTIVATION_DELAY):
                    if DEBUG_MODE:
                        print("[monitorTunnelThread] Activating Available Tunnel..")
                    TUNNEL_AVAILABLE.set()
            else:
                TUNNEL_LAST_UNAVAILABLE_TIMESTAMP = NOW
                TUNNEL_AVAILABLE.clear()
                if DEBUG_MODE:
                    print("[monitorTunnelThread] TUNNEL NOT AVAILABLE")

            TUNNEL_LAST_CHECKED_TIMESTAMP = NOW
            time.sleep(MONITOR_TUNNEL_INTERVAL)

    def getMasquerades(self):
        CMD = Environment().from_string(GET_MASQUERADES_CMD).render(SSH_TUNNEL_OBJECT).strip()
        if DEBUG_MODE:
            print("[getMasquerades] CMD = {}".format(CMD))

        proc = subprocess.Popen(CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/', shell=True, universal_newlines=True)
        out, err = proc.communicate()
        out = out.splitlines()
        err = err.splitlines()
        code = proc.wait()
        if code != 0:
            return []
        MASQS = []
        for l in out:
            L = l.split(' ')
            if len(L) == 7:
                MASQS.append({
                    'proto': L[1],
                    'src': L[3],
                    'dest': L[4],
                    'dport': int(L[6].split(':')[1]),
                })
        return MASQS

    def getDnats(self):
        CMD = Environment().from_string(GET_DNATS_CMD).render(SSH_TUNNEL_OBJECT).strip()
        if DEBUG_MODE:
            print("[getDnats] CMD = {}".format(CMD))
        proc = subprocess.Popen(CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/', shell=True, universal_newlines=True)
        out, err = proc.communicate()
        out = out.splitlines()
        err = err.splitlines()
        code = proc.wait()
        if code != 0:
            return []
        DNATS = []
        for l in out:
            L = l.split(' ')
            if len(L) == 8:
                DNATS.append({
                    'proto': L[1],
                    'src': L[3],
                    'dest': L[4],
                    'dport': int(L[6].replace('dpt:','')),
                    'to': {
                        'host': L[7].replace('to:','').split(':')[0],
                        'port': int(L[7].replace('to:','').split(':')[1]),
                    },
                })
        return DNATS

    def setupTunnelProcess(self, HOSTS):
        processStartTime = int(time.time())
        atexit.register(self.cleanupProcess)
        if DEBUG_MODE:
            print('[setupTunnelProcess] HOSTS: {}'.format(HOSTS))

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
                if DEBUG_MODE:
                    print('stderr> {}'.format(stderr))
            while not stdout_queue.empty():
                stdout = stdout_queue.get()
                stdoutLines.append(stdout)
                if DEBUG_MODE:
                    print('stdout> {}'.format(stdout))

        self.proc.stdout.close()
        self.proc.stderr.close()
        exit_code = self.proc.wait()
        processEndTime = int(time.time())
        processRunTime = processEndTime - processStartTime

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

    def undropTrafficToHosts(self):
        for CMD in self.removeDropRulesCommand():
            SCRIPT_PATH = tempfile.NamedTemporaryFile(suffix=TUNNEL_SCRIPT_SUFFIX,delete=AUTO_DELETE_TUNNEL_SCRIPTS).name
            with open(SCRIPT_PATH,'w') as f:
                f.write(CMD)
                os.chmod(SCRIPT_PATH, 0o700)
                if DEBUG_MODE:
                    print('[undropTrafficToHosts] CMD={}, SCRIPT_PATH={}'.format(CMD,SCRIPT_PATH))
                proc = subprocess.Popen(CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)
                out, err = proc.communicate()
                code = proc.wait()
                if code != 0:
                    raise Exception("cmd={},out={},err={},code={}".format(CMD,out,err,code))
        return True

    def dropTrafficToHosts(self):
        for CMD in self.createDropRulesCommand():
            SCRIPT_PATH = tempfile.NamedTemporaryFile(suffix=TUNNEL_SCRIPT_SUFFIX,delete=AUTO_DELETE_TUNNEL_SCRIPTS).name
            with open(SCRIPT_PATH,'w') as f:
                f.write(CMD)
                os.chmod(SCRIPT_PATH, 0o700)
                if DEBUG_MODE:
                    print('[dropTrafficToHosts] CMD={}, SCRIPT_PATH={}'.format(CMD,SCRIPT_PATH))
                proc = subprocess.Popen(CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)
                out, err = proc.communicate()
                code = proc.wait()
                if code != 0:
                    raise Exception("cmd={},out={},err={},code={}".format(CMD,out,err,code))
        return True

    def v2_playbook_on_play_start(self, *args, **kwargs):
        if DEBUG_MODE:
            print('[v2_playbook_on_play_start]')
        logging.debug("v2_playbook_on_play_start(self, *args, **kwargs)")
        self.play = args[0]
        if DEBUG_MODE:
            print('self.play={}'.format(self.play))
        self.loader = args[0]._loader
        self.hosts = args[0].get_variable_manager()._inventory.get_hosts()
        if DEBUG_MODE:
            print('self.hosts={}'.format(self.hosts))

        self.dropTrafficToHosts()

        TUNNEL_THREAD = Thread(target=self.setupTunnelProcess, args=[self.hosts])
        TUNNEL_THREAD.daemon = True
        TUNNEL_THREAD.start()

        TUNNEL_MONITOR_THREAD = Thread(target=self.monitorTunnelThread, args=[self.hosts])
        TUNNEL_MONITOR_THREAD.daemon = True
        TUNNEL_MONITOR_THREAD.start()

        while not TUNNEL_AVAILABLE.wait(timeout=30):
            print('\r{}% done. Waiting for tunnel to become available..'.format(0), end='', flush=True)
            time.sleep(0.1)

        print('\n[winrm_ssh_proxy] The tunnel state is available\n')

        SETUP = {
          'HOSTS': "{}".format(self.hosts),
          'PLAY': "{}".format(self.play),
        }
        if DEBUG_MODE:
            print("DEBUG_SETUP_FILE={}".format(DEBUG_SETUP_FILE))
            with open(DEBUG_SETUP_FILE,'w') as f1:
                f1.write(json.dumps(SETUP))

    def v2_playbook_on_start(self, playbook):
        PLAYBOOK_PATH = os.path.abspath(playbook._file_name)
        if DEBUG_MODE:
            print('[v2_playbook_on_start]')
