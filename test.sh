#!/bin/bash
if [[ "$REMOTE_USER" == "" ]]; then
    REMOTE_USER='Administrator'
fi
if [[ "$REMOTE_HOST" == "" ]]; then
    REMOTE_HOST='10.187.22.222'
    REMOTE_HOST='10.187.7.34'
fi

ANSIBLE_CALLBACK_WHITELIST=vpntech,winrm_ssh_proxy \
ANSIBLE_CALLBACK_PLUGINS=~/ansible-winrm-ssh-proxy-pre-exec-module:~/.local/lib/python3.6/site-packages/ansible/plugins/callback \
ANSIBLE_DEBUG=0 \
    ansible-playbook \
        -c winrm \
        -u "${REMOTE_USER}" \
        -k \
        -i ${REMOTE_HOST}, \
            test.yaml $@

