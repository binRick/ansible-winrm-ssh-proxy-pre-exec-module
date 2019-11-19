#!/bin/bash
ANSIBLE_CALLBACK_WHITELIST=vpntech,winrm_ssh_proxy ANSIBLE_CALLBACK_PLUGINS=~/xxxxxxxxxxxxx/callback_plugins:~/xxxxxxxxxxxxxxxxx/ansible-winrm-ssh-proxy-pre-exec-module ANSIBLE_DEBUG=0 ansible-playbook -i vpn299, lib/Ansible/testPlaybooks/devSyncPlays.yaml $@

cat /tmp/kkkkkkk
