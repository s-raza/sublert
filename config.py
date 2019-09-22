#!/usr/bin/python

import json
import os

def get_engine_string():

    retval = None
    
    if sldb['dialect'] is not None:
        
        retval = sldb['dialect']+"://"+sldb['uname']+":"+sldb['password']+"@"+sldb['host']
        
        if sldb['port'] is not None:
            retval = retval+":"+sldb['port']
            
        retval = retval + "/"+sldb['dbname']
    
    return retval 


def load_config():
    
    with open(os.path.abspath('../config.json')) as data:
        config = json.load(data)

    globals().update(config)
    sldb['conn_string'] = get_engine_string()

load_config()
