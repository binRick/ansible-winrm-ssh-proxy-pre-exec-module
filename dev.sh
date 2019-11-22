#!/bin/bash
nodemon -w . -e js,py,yaml,json,sh -x bash -- -c "bash insecureDevWrapper.sh"
