#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from six.moves import range
from functools import reduce

__author__ = 'Austin Taylor'

from ..base.config import swConfig
from .base import scanWhispererBase
from ..frameworks.nessus import NessusAPI

import pandas as pd
from lxml import objectify
import sys
import os
import io
import time
import sqlite3
import json
import logging
import socket
from datetime import datetime

import hashlib
from elasticsearch import Elasticsearch
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class scanWhispererNessus(scanWhispererBase):
    CONFIG_SECTION = None

    def __init__(
            self,
            profile='nessus',
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=False
    ):
        self.CONFIG_SECTION = profile

        super(scanWhispererNessus, self).__init__(config=config,purge=purge)

        self.develop = True
        self.purge = purge
        self.verbose = verbose

        # set up logger
        self.logger = logging.getLogger('scanWhispererNessus')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('Starting {} whisperer'.format(self.CONFIG_SECTION))

        # if the config is available
        if config is not None:
            try:
                # Try to read data from config file
                # Nessus/Tenable.io data
                self.nessus_hostname = self.config.get(self.CONFIG_SECTION, 'hostname')
                self.nessus_port = self.config.get(self.CONFIG_SECTION, 'port')
                self.nessus_trash = self.config.getbool(self.CONFIG_SECTION, 'trash')

                # Nessus/Tenable.io API Keys
                self.access_key = self.config.get(self.CONFIG_SECTION, 'access_key')
                self.secret_key = self.config.get(self.CONFIG_SECTION, 'secret_key')

                # Elastic Search
                self.elk_host = self.config.get(self.CONFIG_SECTION, 'elk_host')
                self.elk_username = self.config.get(self.CONFIG_SECTION, 'elk_username')
                self.elk_password = self.config.get(self.CONFIG_SECTION, 'elk_password')

                try:
                    # Try to connect to Nessus
                    self.logger.info('Attempting to connect to {}...'.format(self.CONFIG_SECTION))
                    self.nessus = \
                        NessusAPI( profile=self.CONFIG_SECTION,
                                   hostname=self.nessus_hostname,
                                   port=self.nessus_port,
                                   access_key=self.access_key,
                                   secret_key=self.secret_key
                                  )
                    self.nessus_connect = True
                    self.logger.info('Connected to {} on {host}:{port}'.format(self.CONFIG_SECTION, host=self.nessus_hostname,port=str(self.nessus_port)))

                    # try to connect to Elastic Search
                    try:
                        # disable Elastic Search logger
                        logging.getLogger('elasticsearch').setLevel(logging.CRITICAL)

                        # connect to Elastic Search
                        self.logger.info('Attempting to connect to Elastic Search ({})'.format(self.elk_host))
                        self.elastic_client= Elasticsearch('https://{}:{}@{}'.format(self.elk_username, self.elk_password, self.elk_host), ca_certs=False, verify_certs=False)
                        self.elk_connect = True
                        self.logger.info('Connected to Elastic Search ({})'.format(self.elk_host))

                    except Exception as e:
                        self.logger.error('Could not connect to Elastic Search ({})'.format(self.elk_host))

                except Exception as e:
                    self.logger.error('Could not connect to {}: {}'.format(self.CONFIG_SECTION, e))

            except Exception as e:
                self.logger.error('Could not properly load your config: {}'.format(e))

    # This function adds field to report
    def add_to_report(self, report, field, content):
        if content:
            if isinstance(content, str):
                content = content.strip()

            report.update({ field : content })

    # This function creates a single report
    def create_report(self, scan, finding):
        # assemble report: 
        # NESSUS: Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output
        # TENABLEIO: Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,Asset UUID,Vulnerability State,IP Address,FQDN,NetBios,OS,MAC Address,Plugin Family,CVSS Base Score,CVSS Temporal Score,CVSS Temporal Vector,CVSS Vector,CVSS3 Base Score,CVSS3 Temporal Score,CVSS3 Temporal Vector,CVSS3 Vector,System Type,Host Start,Host End
        report = {}

        # ---- Nessus/Tenable.io only part
        self.add_to_report(report, '{}.scan.name'.format(self.CONFIG_SECTION), scan.get('scan_name'))
        self.add_to_report(report, '{}.scan.id'.format(self.CONFIG_SECTION), scan.get('scan_id'))
        self.add_to_report(report, '{}.history.id'.format(self.CONFIG_SECTION), scan.get('history_id'))
        self.add_to_report(report, '{}.plugin.id'.format(self.CONFIG_SECTION), finding.get('Plugin ID'))
        self.add_to_report(report, '{}.plugin.name'.format(self.CONFIG_SECTION), finding.get('Name'))
        self.add_to_report(report, 'tenableio.plugin.family', finding.get('Plugin Family')) # Tenable.io only

        # ---- Asset part ----
        self.add_to_report(report, 'asset.host', finding.get('Host'))
        self.add_to_report(report, 'asset.ip', finding.get('IP Address')) 
        self.add_to_report(report, 'asset.port', finding.get('Port'))   
        self.add_to_report(report, 'asset.protocol', finding.get('Protocol'))
        self.add_to_report(report, 'asset.uuid', finding.get('Asset UUID')) # Tenable.io only
        self.add_to_report(report, 'asset.fqdn', finding.get('FQDN')) 
        self.add_to_report(report, 'asset.netbios', finding.get('NetBios')) 
        self.add_to_report(report, 'asset.os', finding.get('OS')) 
        self.add_to_report(report, 'asset.mac_address', finding.get('Mac Address')) 
        self.add_to_report(report, 'asset.system_type', finding.get('System Type')) # Tenable.io only

        # ---- CVE Part ----
        self.add_to_report(report, 'cve.id', finding.get('CVE')) 
        self.add_to_report(report, 'cve.cvss.score', finding.get('CVSS')) 
        self.add_to_report(report, 'cve.cvss.vector', finding.get('CVSS Vector'))  # Tenable.io only
        self.add_to_report(report, 'cve.cvss2.score', finding.get('CVSS')) 
        self.add_to_report(report, 'cve.cvss.base.score', finding.get('CVSS Base Score'))  # Tenable.io only
        self.add_to_report(report, 'cve.cvss.temporal.score', finding.get('CVSS Temporal Score'))  # Tenable.io only
        self.add_to_report(report, 'cve.cvss.temporal.vector', finding.get('CVSS Temporal Vector'))  # Tenable.io only
        self.add_to_report(report, 'cve.cvss3.score', finding.get('CVSS3 Base Score'))  # Tenable.io only
        self.add_to_report(report, 'cve.cvss3.vector', finding.get('CVSS3 Vector'))  # Tenable.io only
        self.add_to_report(report, 'cve.cvss3.base.score', finding.get('CVSS3 Base Score'))  # Tenable.io only
        self.add_to_report(report, 'cve.cvss3.temporal.score', finding.get('CVSS3 Temporal Score'))  # Tenable.io only
        self.add_to_report(report, 'cve.cvss3.temporal.vector', finding.get('CVSS3 Temporal Vector'))  # Tenable.io only
        if report.get('cve.id'):
            self.add_to_report(report, 'cve.package_name', finding.get('Name'))  

        # ---- Finding metadata part ----
        self.add_to_report(report, 'finding.first_observed', datetime.fromtimestamp(scan.get('norm_time', datetime.now().timestamp())).isoformat())
        self.add_to_report(report, 'finding.last_observed', datetime.fromtimestamp(scan.get('norm_time', datetime.now().timestamp())).isoformat())
        self.add_to_report(report, 'finding.risk', finding.get('Risk'))
        self.add_to_report(report, 'finding.title', finding.get('Synopsis'))
        self.add_to_report(report, 'finding.description', finding.get('Description'))
        self.add_to_report(report, 'finding.solution', finding.get('Solution'))
        self.add_to_report(report, 'finding.source', self.CONFIG_SECTION)
        self.add_to_report(report, 'finding.plugin_output', finding.get('Plugin Output'))
        self.add_to_report(report, 'finding.see_also', finding.get('See Also'))
        self.add_to_report(report, 'finding.state', finding.get('Vulnerability State')) # Tenable.io only
        # Guess finding type by existing fields
        if report.get('cve.cvss.score'):
            self.add_to_report(report, 'finding.type', 'cve')
        else:
            self.add_to_report(report, 'finding.type', 'other')

        return report

    
    def push_report(self, scan, finding):

        # Create report
        report = self.create_report(scan, finding)

        # Use scan_type field to generate id accordingly
        document_id = hashlib.sha1(('{}{}{}{}'.format(report.get('asset.ip'), report.get('asset.port'), report.get('cve.id', ''), report.get('finding.title'))).encode('utf-8')).hexdigest()

        # Create index on Elastic Search
        try:
            # create index if needed
            mapping = {
                "mappings": {
                    "properties": {
                        "cve.cvss.score": {
                            "type": "float" 
                        },
                        "cve.cvss2.score": {
                            "type": "float" 
                        },
                        "cve.cvss.base.score": {
                            "type": "float" 
                        },
                        "cve.cvss.temporal.score": {
                            "type": "float" 
                        },
                        "cve.cvss3.score": {
                            "type": "float" 
                        },
                        "cve.cvss3.base.score": {
                            "type": "float" 
                        },
                        "cve.cvss3.temporal.score": {
                            "type": "float" 
                        },

                    }
                }
            }
            self.elastic_client.indices.create(index='scanwhisperer-{}-{}'.format(report.get('finding.type'), self.CONFIG_SECTION),body=mapping, ignore=400)

        except Exception as e:
            self.logger.error('Failed create index scanwhisperer-{}-{} on Elastic Search: {}'.format(report.get('finding.type'), self.CONFIG_SECTION, e)) 
          
        # Query Elastic Search to fetch a document with the same ID
        # If found,overwrite new first_observed with older to avoid updating it
        try:
            # Fetch document
            elk_response = self.elastic_client.search(index='scanwhisperer-{}-{}'.format(report.get('finding.type'), self.CONFIG_SECTION), body={
                "query": {
                    "match": {
                        "_id": document_id
                    }
                }
            })

            # If document was found, apply older first observed
            if elk_response.get('hits').get('total').get('value') == 1:
                # Maintain old first observed
                report['finding.first_observed'] = elk_response.get('hits').get('hits')[0].get('_source').get('finding.first_observed')

        except Exception as e:
            self.logger.error('Failed to get document from Elastic Search: {}'.format(e)) 

        # Push report to Elastic
        try:
            # push report
            self.elastic_client.update(index='scanwhisperer-{}-{}'.format(report.get('finding.type'), self.CONFIG_SECTION), id=document_id, body={'doc': report,'doc_as_upsert':True})
        
        except Exception as e:
            self.logger.error('Failed push document to Elastic Search: {}'.format(e)) 


    # This function returns a list of scans to process (each scan is combined with history)
    def get_scans_to_process(self, scans):

        self.logger.info('Gathering all scan data... this may take a while...')
        scans_to_process = []
        for s in scans:
            if s:
                record = {}
                record['scan_id'] = s['id']
                record['scan_name'] = s.get('name', '')
                record['owner'] = s.get('owner', '')
                record['creation_date'] = s.get('creation_date', '')
                record['starttime'] = s.get('starttime', '')
                record['timezone'] = s.get('timezone', '')
                record['folder_id'] = s.get('folder_id', '')
                try:
                    for h in self.nessus.get_scan_history(s['id']):
                        record['uuid'] = h.get('uuid', '')
                        record['status'] = h.get('status', '')
                        record['history_id'] = h.get('history_id', '')
                        record['last_modification_date'] = h.get('last_modification_date', '')
                        record['norm_time'] = self.nessus.get_utc_from_local(int(record['last_modification_date']), local_tz=record['timezone'])
                    
                        scans_to_process.append(record.copy())
                except:
                    pass

        # Exclude uncomplete scans
        scans_to_process = [scan for scan in scans_to_process if scan['status'] in ['completed', 'imported']]

        # Exclude already processed scans
        if self.uuids:
            scans_to_process = [scan for scan in scans_to_process if scan['uuid'] not in self.uuids]

        self.logger.info('Identified {new} scans to be processed'.format(new=len(scans_to_process)))

        return scans_to_process


    def whisper_nessus(self):
        if self.nessus_connect and self.elk_connect:
            # get scan list from nessus/tenableio, avoiding already fetched scans (if failed, throw an exception)
            try:
                scan_list = self.get_scans_to_process(self.nessus.scans['scans'])

                # if no scans are available, just exit
                if not scan_list:
                    self.logger.warn('No new scans to process. Exiting...')
                    return self.exit_code

                # for each scan to process, download csv report and export to Elastic Search
                for scan in scan_list:
                    
                    # Try to request scan report
                    try:
                        report_req = self.nessus.download_scan(scan_id=scan['scan_id'], history=scan['history_id'], export_format='csv')

                        # Import requested scan report inside a DataFrame
                        report_csv = pd.read_csv(io.StringIO(report_req), na_filter=False)

                        # ONLY FOR NESSUS: Add Host info
                        if len(report_csv) > 0 and self.CONFIG_SECTION == 'nessus':
                            self.logger.info('Fetching host info')
                            host_list = self.nessus.get_scan_hosts(scan_id=scan['scan_id'], history_id=scan['history_id'])

                            # Edit the dataframe to add host info
                            report_csv['IP Address'] = report_csv.apply (lambda row: host_list.get(row['Host'], {}).get('host-ip', ''), axis=1) 
                            report_csv['FQDN'] = report_csv.apply (lambda row: host_list.get(row['Host'], {}).get('host-fqdn', ''), axis=1) 
                            report_csv['NetBios'] = report_csv.apply (lambda row: host_list.get(row['Host'], {}).get('netbios-name', ''), axis=1) 
                            report_csv['OS'] = report_csv.apply (lambda row: host_list.get(row['Host'], {}).get('operating-system', ''), axis=1) 
                            report_csv['Mac Address'] = report_csv.apply (lambda row: host_list.get(row['Host'], {}).get('mac-address', ''), axis=1) 

                            self.logger.info('Added host info for {} hosts'.format(len(host_list)))

                        self.logger.info('Pushing {} {} reports to Elastic Search'.format(report_csv.shape[0], self.CONFIG_SECTION))

                        # Iterate over report lines and push it to Elastic Search
                        try:
                            for index, finding in report_csv.iterrows():
                                self.push_report(scan, finding)
                        except Exception as e:
                            self.logger.error('{} finding push error: {}'.format(self.CONFIG_SECTION, e))   

                        # Save the scan in ScanWhisperer DB
                        record_meta = (
                                scan['scan_name'],
                                scan['scan_id'],
                                scan['norm_time'],
                                'file_name',
                                time.time(),
                                report_csv.shape[0],
                                self.CONFIG_SECTION,
                                scan['uuid'],
                                1,
                                0,
                            )
                        self.record_insert(record_meta)

                        self.logger.info('{} {} reports pushed to Elastic Search'.format(report_csv.shape[0], self.CONFIG_SECTION))

                    except Exception as e:
                        self.logger.error('Could not download {} scan {}: {}'.format(self.CONFIG_SECTION, scan['scan_id'], e))

            except Exception as e:
                self.logger.error('Could not process new {} scans: {}'.format(self.CONFIG_SECTION, e))
                            
            self.conn.close()
            self.logger.info('Scan aggregation completed!')
        else:
            self.logger.error('Failed to connect to {} API at {}:{}'.format(self.CONFIG_SECTION, self.nessus_hostname, self.nessus_port))
            self.exit_code += 1
        return self.exit_code

