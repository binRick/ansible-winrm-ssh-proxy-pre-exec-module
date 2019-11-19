#!/bin/bash
HOST=10.110.10.31
U='Administrator'

ANSIBLE_CALLBACK_WHITELIST=vpntech,winrm_ssh_proxy \
    ANSIBLE_CALLBACK_PLUGINS=~/ansible-winrm-ssh-proxy-pre-exec-module:~/.local/lib/python3.6/site-packages/ansible/plugins/callback \
    ANSIBLE_DEBUG=1 \
    ansible-playbook \
        -c winrm \
        -u $U \
        -k \
        -i ${HOST}, test.yaml $@

