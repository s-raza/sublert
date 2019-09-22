                                       _____       __    __          __
                                      / ___/__  __/ /_  / /__  _____/ /_
                                      \__ \/ / / / __ \/ / _ \/ ___/ __/
                                     ___/ / /_/ / /_/ / /  __/ /  / /_
                                    /____/\__,_/_.___/_/\___/_/   \__/

                                Author: Yassine Aboukir (@yassineaboukir)
                                            Version: 1.4.7

## What's this about?
Sublert is a security and reconnaissance tool that was written in Python to leverage certificate transparency for the sole purpose of monitoring new subdomains deployed by specific organizations and issued TLS/SSL certificate. The tool is supposed to be scheduled to run periodically at fixed times, dates, or intervals (Ideally each day). New identified subdomains will be sent to Slack workspace with a notification push. Furthermore, the tool performs DNS resolution to determine working subdomains.

## Requirements
- Virtual Private Server (VPS) running on Unix. (I personally use digitalOcean)
- Python 2.x or 3.x.
- Free Slack workplace.

## Installation & Configuration
Please refer to below article for a detailed technical explanation:
- https://medium.com/@yassineaboukir/automated-monitoring-of-subdomains-for-fun-and-profit-release-of-sublert-634cfc5d7708

## Database Configuration (Postgresql)

Install Postgresql database (Debian based systems)

```
    $ sudo apt-get install postgresql
```

Create the database user for sublert

```
    $ sudo -u postgres createuser <username>
```

Create database for sublert

```
    $ sudo -u postgres createdb <dbname>
```

Setup a password for the database user

```
    $ sudo -u postgres psql
    psql=# alter user <username> with encrypted password '<password>';
```

Grant permissions to the database for the user

```
    $ sudo -u postgres psql
    psql=# grant all privileges on database <dbname> to <username> ;
```

Finally update the config.py file to reflect the credentials created above

## JSON Configuration

Place a JSON file 'config.json' one directory above the folder containing the sublert.py file, with the following .

If dialect is set to null a local file named "sublert.db" will be created in the same folder from where sublert is being run, and sqlite database will be used.

##### Postgresql Sample

```
{
    "slack" : {
            "posting_webhook":     "<posting_webhook from slack>",
            "errorlogging_webhook": "<errorlogging_webhook from slack>",
            "sleep_enabled": true,
            "at_channel_enabled": true
            },
        
    "crtsh" : {
            "host" : "crt.sh",
            "name" : "certwatch",
            "user" : "guest",
            "password": ""
            },
        
    "sldb" : {
            "dialect": "postgresql",
            "uname": "sublertusr",
            "password": "sublertpass",
            "host": "localhost",
            "dbname": "sublertdb",
            "port": null
           }
}
```

##### MySQL Sample

```
{
    "slack" : {
            "posting_webhook":     "<posting_webhook from slack>",
            "errorlogging_webhook": "<errorlogging_webhook from slack>",
            "sleep_enabled": true,
            "at_channel_enabled": true
            },
        
    "crtsh" : {
            "host" : "crt.sh",
            "name" : "certwatch",
            "user" : "guest",
            "password": ""
            },
        
    "sldb" : {
            "dialect": "mysql+mysqldb",
            "uname": "sublertusr",
            "password": "sublertpass",
            "host": "localhost",
            "dbname": "sublertdb",
            "port": null
           }
}
```

## Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-u            | --url       | Adds a domain to monitor. E.g: yahoo.com.
-d            | --delete      | Domain to remove from the monitored list. E.g: yahoo.com.
-a            | --list       | Listing all monitored domains.
-t            | --threads       | Number of concurrent threads to use (Default: 20).
-r            | --resolve      | Perform DNS resolution.
-l            | --logging     | Enable Slack-based error logging.
-m            | --reset        | Reset everything.

## Is there a roadmap?
YES! The tool is now open sourced to be used by the community but contributions are valuable and highly appreciated. I have a number of items that I will be working on to polish the tool, among of which are:
- ~~Use of a relational database instead of text files for storage.~~ (Done)
- Extracting as much information as possible including: title, status code, screenshot and checking for potential subdomain takeovers.
- Integrate Telegram too for notification pushes.

## Feedback and issues?
If you have any feedback, anything that you want to see implemented or running into issues using Sublert, please feel free to file an issue on https://github.com/yassineaboukir/sublert/issues
