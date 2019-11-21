#!/bin/bash
nodemon -w . -e js,py,yaml,json,sh -x bash -- -c "echo sudo systemctl restart firewalld ; bash insecureDevWrapper.sh"
