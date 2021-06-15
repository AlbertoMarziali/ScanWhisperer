ScanWhisperer
===============

ScanWhisperer is a vulnerability management tool and report aggregator. ScanWhisperer will pull all the reports from the different Vulnerability scanners and send them via API to ElasticSearch to be indexed and explored in a visual and searchable format in Kibana.

This is a custom version of VulnWhisperer. You can find the original one <a href="https://github.com/HASecuritySolutions/VulnWhisperer">here</a>.

The main differences between the original version and this version are:
- Works with Python3
- Supports AWS Inspector API
- Supports NiktoWrapper (S3)
- Supports BitSight API
- Has been stripped down (OpenVAS, Qualys, Jira and MockAPI removed)
- Sends reports to Elastic Search via API, completely bypassing Logstash

Currently Supports
-----------------

### Vulnerability Frameworks

- [X] [Nessus (**v6**/**v7**/**v8**)](https://www.tenable.com/products/nessus/nessus-professional)
- [X] [Tenable.io](https://www.tenable.com/products/tenable-io)
- [X] [AWS Inspector](https://aws.amazon.com/it/inspector/)
- [X] [NiktoWrapper (S3)](https://github.com/AlbertoMarziali/NiktoWrapper)
- [X] [BitSight](https://www.bitsight.com)

### Reporting Frameworks

- [X] [ELK (**v6**/**v7**)](https://www.elastic.co/elk-stack)



Getting Started
===============

1) Follow the [install requirements](#installreq)
2) Fill out the section you want to process in <a href="https://github.com/AlbertoMarziali/ScanWhisperer/blob/main/configs/frameworks.ini">frameworks.ini file</a>
4) [Run Scanwhisperer](#run)

Requirements
-------------
####
*   Python 3+
*   Vulnerability Scanner (AWS Inspector, Nessus, Tenable.io, NiktoWrapper, BitSight)
*   Reporting System: ElasticStack 6+

<a id="installreq">Installation</a>
--------------------
**Install OS packages requirement dependencies** (Debian-based distros, CentOS don't need it)
```shell

sudo apt-get install  zlib1g-dev libxml2-dev libxslt1-dev 
```

**(Optional) Use a python virtualenv to not mess with host python libraries**
```shell
virtualenv venv (will create the python 3.6 virtualenv)
source venv/bin/activate (start the virtualenv, now pip will run there and should install libraries without sudo)

deactivate (for quitting the virtualenv once you are done)
```

**Install python libraries requirements**

```python
pip install -r /path/to/ScanWhisperer/requirements.txt
cd /path/to/ScanWhisperer
python setup.py install
```

**(Optional) If using a proxy, add proxy URL as environment variable to PATH**
```shell
export HTTP_PROXY=http://example.com:8080
export HTTPS_PROXY=http://example.com:8080
```

Now you're ready to pull down scans. (see <a href="#run">run section</a>)

Configuration
-----

There are a few configuration steps to setting up ScanWhisperer:
*   Configure Ini file

<a href="https://github.com/AlbertoMarziali/ScanWhisperer/blob/main/configs/frameworks.ini">frameworks.ini file</a>

<a id="run">Run</a>
-----
To run, fill out the configuration file with your vulnerability scanner settings. Then you can execute from the command line.
```python
(optional flag: -F -> provides "Fancy" log colouring, good for comprehension when manually executing ScanWhisperer)
scan_whisperer -c configs/frameworks.ini -s nessus 
or
scan_whisperer -c configs/frameworks.ini -s awsinspector

```
If no section is specified (e.g. -s nessus), scanwhisperer will check on the config file for the modules that have the property `enabled=true` and run them sequentially.



Credits
===============
All original authors and contributors:
   - [Austin Taylor (@HuntOperator)](https://github.com/austin-taylor)
   - [Justin Henderson (@smapper)](https://github.com/SMAPPER)
   - [Quim Montal (@qmontal)](https://github.com/qmontal)
   - [@pemontto](https://github.com/pemontto)
   - [@cybergoof](https://github.com/cybergoof)
