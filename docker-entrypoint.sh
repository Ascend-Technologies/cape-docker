#!/bin/sh

set -e

/usr/bin/python3 /update_conf.py
/usr/bin/supervisord