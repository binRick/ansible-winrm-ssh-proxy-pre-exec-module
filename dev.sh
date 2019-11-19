#!/bin/bash
ANSIBLE_CALLBACK_WHITELIST=vpntech,winrm_ssh_proxy \
    ANSIBLE_CALLBACK_PLUGINS=~/ansible-winrm-ssh-proxy-pre-exec-module:~/.local/lib/python3.6/site-packages/ansible/plugins/callback \
    ANSIBLE_DEBUG=0 \
    ansible-playbook -i gitlab.product.hicloud, test.yaml $@

