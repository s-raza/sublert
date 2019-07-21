#!/usr/bin/python

import json

# Path to json file with the configuration data
with open('/opt/progs/sublert/config_live.json') as data:
    conf = json.load(data)

# Slack webhooks for notifications
posting_webhook = conf['SLACK']['posting_webhook']
errorlogging_webhook = conf['SLACK']['errorlogging_webhook']
slack_sleep_enabled = conf['SLACK']['slack_sleep_enabled']  # bypass Slack rate limit when using free workplace, switch to False if you're using Pro/Ent version.
at_channel_enabled = conf['SLACK']['at_channel_enabled']   # Add @channel notifications to Slack messages, switch to False if you don't want to use @channel

# crtsh postgres credentials, please leave it unchanged.
DB_HOST = conf['CRTSH']['db_host']
DB_NAME = conf['CRTSH']['db_name']
DB_USER = conf['CRTSH']['db_user']
DB_PASSWORD = conf['CRTSH']['db_password']

# sublert postgresql database credentials
sldb_user = conf['SLDB']['uname']
sldb_pass = conf['SLDB']['pass']
sldb_host = conf['SLDB']['host']
sldb_dbname = conf['SLDB']['dbname']
sldb_port = conf['SLDB']['port']
