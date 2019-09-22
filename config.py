#!/usr/bin/python

import json
import os

def load_config():
    
    with open(os.path.abspath('../config.json')) as data:
        config = json.load(data)

    globals().update(config)

load_config()
