#!/usr/bin/env python

import os
import sys
import ConfigParser


#Setting reporting.conf
reporting_cfg = ConfigParser.ConfigParser()
reporting_cfg.read("/opt/CAPEv2/conf/reporting.conf")
with open("/opt/CAPEv2/conf/reporting.conf", 'w') as cfile:
    if os.environ.get('ES_HOST'):
        reporting_cfg.set('elasticsearch', 'enabled', "yes")
        if os.environ.get('ES_PORT'):
            reporting_cfg.set('elasticsearch', 'hosts', "%s:%s" % (os.environ['ES_HOST'],os.environ['ES_PORT']))
        else:
            reporting_cfg.set('elasticsearch', 'hosts', os.environ['ES_HOST'])

    if os.environ.get('MONGO_HOST'):
        reporting_cfg.set('mongodb', 'enabled', "yes")
        reporting_cfg.set('mongodb', 'host', os.environ['MONGO_HOST'])
    if os.environ.get('MONGO_PORT'):
        reporting_cfg.set('mongodb', 'port', os.environ['MONGO_TCP_PORT'])

    reporting_cfg.write(cfile)

#Setting cuckoo.conf
cuckoo_cfg = ConfigParser.ConfigParser()
cuckoo_cfg.read("/opt/CAPEv2/conf/cuckoo.conf")
with open("/opt/CAPEv2/conf/cuckoo.conf", 'w') as cfile:
    if os.environ.get('RESULTSERVER_HOST'):
        cuckoo_cfg.set('resultserver', 'ip', os.environ['RESULTSERVER_HOST'])
    if os.environ.get('RESULTSERVER_PORT'):
        cuckoo_cfg.set('resultserver', 'port', os.environ['RESULTSERVER_PORT'])

    if os.environ.get('MACHINERY'):
        cuckoo_cfg.set('cuckoo', 'machinery', os.environ['MACHINERY'])

    if os.environ.get('DATABASE_CONNECTION'):
        cuckoo_cfg.set('database', 'connection', os.environ['DATABASE_CONNECTION'])

    cuckoo_cfg.write(cfile)



sys.exit()
