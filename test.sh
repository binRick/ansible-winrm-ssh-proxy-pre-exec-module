#!/bin/bash
HOST='10.187.22.222'
HOST='10.187.7.34'
U='PRODUCT\rblundell'
U='Administrator'

ANSIBLE_CALLBACK_WHITELIST=vpntech,winrm_ssh_proxy \
ANSIBLE_CALLBACK_PLUGINS=~/ansible-winrm-ssh-proxy-pre-exec-module:~/.local/lib/python3.6/site-packages/ansible/plugins/callback \
ANSIBLE_DEBUG=0 \
    ansible-playbook \
        -c winrm \
        -u $U \
        -k \
        -i ${HOST}, test.yaml $@

