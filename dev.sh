#!/bin/bash
ANSIBLE_CALLBACK_WHITELIST=vpntech,winrm_ssh_proxy \
    ANSIBLE_CALLBACK_PLUGINS=~/ansible-winrm-ssh-proxy-pre-exec-module:~/.local/lib/python3.6/site-packages/ansible/plugins/callback \
    ANSIBLE_DEBUG=0 \
    ansible-playbook \
        -c winrm \
        -eansible_ssh_user=Administrator -k -i 10.187.7.204, test.yaml $@

