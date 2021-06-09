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


    # This function creates a single report
    def create_report(self, scan, finding):
        # assemble report: 
        # NESSUS: Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output
        # TENABLEIO: Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,Asset UUID,Vulnerability State,IP Address,FQDN,NetBios,OS,MAC Address,Plugin Family,CVSS Base Score,CVSS Temporal Score,CVSS Temporal Vector,CVSS Vector,CVSS3 Base Score,CVSS3 Temporal Score,CVSS3 Temporal Vector,CVSS3 Vector,System Type,Host Start,Host End
        report = {}

        # ---- Scan data part ----
        report.update({ 'tags': self.CONFIG_SECTION })

        df_scan_name = scan.get('scan_name', '')
        report.update({ 'scan_name': df_scan_name })

        df_scan_id = scan.get('scan_id', '')
        report.update({ 'scan_id': str(df_scan_id) })

        df_history_id = scan.get('history_id', '')
        report.update({ 'history_id': str(df_history_id) })

        df_plugin_id = finding.get('Plugin ID', '')
        report.update({ 'plugin_id': str(df_plugin_id) })

        df_plugin_name = finding.get('Name', '')
        report.update({ 'plugin_name': df_plugin_name })

        # ---- Time part ----
        df_first_observed = datetime.fromtimestamp(scan.get('norm_time', datetime.now().timestamp())).isoformat()
        report.update({ 'first_observed': df_first_observed })

        df_last_observed =  datetime.fromtimestamp(scan.get('norm_time', datetime.now().timestamp())).isoformat()
        report.update({ 'last_observed': df_last_observed  })

        # ---- Common finding part ----
        df_risk = finding.get('Risk', '')
        if df_risk is not '':
            report.update({ 'risk': df_risk })

        df_asset = finding.get('Host', '')
        report.update({ 'asset': df_asset })

        df_protocol = finding.get('Protocol', '')
        if df_protocol is not '':
            report.update({ 'protocol': df_protocol })

        df_port = finding.get('Port', '')
        report.update({ 'port': df_port })

        df_title = finding.get('Synopsis', '')
        if df_title is not '':
            report.update({ 'title': df_title.strip() })

        df_description = finding.get('Description', '')
        if df_description is not '':
            report.update({ 'description': df_description.strip() })

        df_solution = finding.get('Solution', '')
        if df_solution is not '':
            report.update({ 'solution' : df_solution.strip() })

        df_see_also = finding.get('See Also', '')
        if df_see_also is not '':
            report.update({ 'see_also' : df_see_also.strip() })

        df_plugin_output = finding.get('Plugin Output', '')
        if df_plugin_output is not '':
            report.update({ 'plugin_output' : df_plugin_output.strip() })

        df_asset_uuid = finding.get('Asset UUID', '')  # Tenable.io only
        if df_asset_uuid is not '':
            report.update({ 'asset_uuid' : df_asset_uuid })

        df_vuln_state = finding.get('Vulnerability State', '') # Tenable.io only
        if df_vuln_state is not '':
            report.update({ 'vulnerability_state' : df_vuln_state })

        df_ip = finding.get('IP Address', finding.get('Host', '')) # Tenable.io only, fix for Nessus
        report.update({ 'ip' : df_ip })

        df_fqdn = finding.get('FQDN', '') # Tenable.io only
        if df_fqdn is not '':
            report.update({ 'fqdn' : df_fqdn })

        df_netbios = finding.get('NetBios', '') # Tenable.io only
        if df_netbios is not '':
            report.update({ 'netbios' : df_netbios })
            
        df_os = finding.get('OS', '') # Tenable.io only
        if df_os is not '':
            report.update({ 'os' : df_os })

        df_mac_address = finding.get('Mac Address', '') # Tenable.io only
        if df_mac_address is not '':
            report.update({ 'mac_address' : df_mac_address })

        df_plugin_family = finding.get('Plugin Family', '') # Tenable.io only
        if df_plugin_family is not '':
            report.update({ 'plugin_family' : df_plugin_family })

        df_system_type = finding.get('System Type', '') # Tenable.io only
        if df_system_type is not '':
            report.update({ 'system_type' : df_system_type })

        df_host_start = finding.get('Host Start', '') # Tenable.io only
        if df_host_start is not '':
            report.update({ 'host_start' : df_host_start })

        df_host_end = finding.get('Host End', '') # Tenable.io only
        if df_host_end is not '':
            report.update({ 'host_end' : df_host_end })

        # ---- CVE part ----
        # extract CVE related fields (if present)
        # CVE,CVSS,CVSS Base Score,CVSS Temporal Score,CVSS Temporal Vector,|CVSS Vector,CVSS3 Base Score,CVSS3 Temporal Score,CVSS3 Temporal Vector,CVSS3 Vector,
        df_cve = finding.get('CVE', '') 
        if df_cve is not '':
            report.update({ 'cve' : df_cve })

        df_cvss = finding.get('CVSS', '') 
        if df_cvss is not '':
            report.update({ 'cvss' : df_cvss })
            report.update({ 'cvss2_score' : df_cvss })

        df_cvss_base_score = finding.get('CVSS Base Score', '') # Tenable.io only
        if df_cvss_base_score is not '':
            report.update({ 'cvss_base_score' : df_cvss_base_score })

        df_cvss_temporal_score = finding.get('CVSS Temporal Score', '') # Tenable.io only
        if df_cvss_temporal_score is not '':
            report.update({ 'cvss_temporal_score' : df_cvss_temporal_score })

        df_cvss_temporal_vector = finding.get('CVSS Temporal Vector', '') # Tenable.io only
        if df_cvss_temporal_vector is not '':
            report.update({ 'cvss_temporal_vector' : df_cvss_temporal_vector })

        df_cvss_vector = finding.get('CVSS Vector', '') # Tenable.io only
        if df_cvss_vector is not '':
            report.update({ 'cvss_vector' : df_cvss_vector })

        df_cvss3_base_score = finding.get('CVSS3 Base Score', '') # Tenable.io only
        if df_cvss3_base_score is not '':
            report.update({ 'cvss3_base_score' : df_cvss3_base_score })
            report.update({ 'cvss3_score' : df_cvss3_base_score })

        df_cvss3_temporal_score = finding.get('CVSS3 Temporal Score', '') # Tenable.io only
        if df_cvss3_temporal_score is not '':
            report.update({ 'cvss3_temporal_score' : df_cvss3_temporal_score })

        df_cvss3_temporal_vector = finding.get('CVSS3 Temporal Vector', '') # Tenable.io only
        if df_cvss3_temporal_vector is not '':
            report.update({ 'cvss3_temporal_vector' : df_cvss3_temporal_vector })

        df_cvss3_vector = finding.get('CVSS3 Vector', '') # Tenable.io only
        if df_cvss3_vector is not '':
            report.update({ 'cvss3_vector' : df_cvss3_vector })
        
        # ---- SCAN TYPE DETECTION ----
        # Detect scan type by existing fields
        df_scan_type = ''
        if report.get('cve'):
            df_scan_type = 'cve'
        else:
            df_scan_type = 'other'
        
        report.update({ 'scan_type': df_scan_type })

        # ---- SCAN TYPE SPECIFIC ACTIONS ----
        if report.get('scan_type') == 'cve':
            # add package_name field, for better integration with other tools
            report.update({ 'package_name': finding.get('Name', '') })

        return report

    
    def push_report(self, scan, finding):

        # Create report
        report = self.create_report(scan, finding)

        # Use scan_type field to generate id accordingly
        document_id = ''
        if report.get('scan_type') == 'cve':
            document_id = hashlib.sha1(('{}{}{}'.format(report.get('ip'), report.get('port'), report.get('cve'))).encode('utf-8')).hexdigest()
        else:
            document_id = hashlib.sha1(('{}{}{}'.format(report.get('ip'), report.get('port'), report.get('title'))).encode('utf-8')).hexdigest()

        # Create index on Elastic Search
        try:
            # create index if needed
            mapping = {
                "mappings": {
                    "properties": {
                        "cvss": {
                            "type": "float" 
                        },
                        "cvss2_score": {
                            "type": "float" 
                        },
                        "cvss_base_score": {
                            "type": "float" 
                        },
                        "cvss_temporal_score": {
                            "type": "float" 
                        },
                        "cvss3_score": {
                            "type": "float" 
                        },
                        "cvss3_base_score": {
                            "type": "float" 
                        },
                        "cvss3_temporal_score": {
                            "type": "float" 
                        },

                    }
                }
            }
            self.elastic_client.indices.create(index='scanwhisperer-{}-{}'.format(report.get('scan_type'), self.CONFIG_SECTION),body=mapping, ignore=400)

        except Exception as e:
            self.logger.error('Failed create index scanwhisperer-{}-{} on Elastic Search: {}'.format(report.get('scan_type'), self.CONFIG_SECTION, e)) 
          
        # Query Elastic Search to fetch a document with the same ID
        # If found,overwrite new first_observed with older to avoid updating it
        try:
            # Fetch document
            elk_response = self.elastic_client.search(index='scanwhisperer-{}-{}'.format(report.get('scan_type'), self.CONFIG_SECTION), body={
                "query": {
                    "match": {
                        "_id": document_id
                    }
                }
            })

            # If document was found, apply older first observed
            if elk_response.get('hits').get('total').get('value') == 1:
                # Maintain old first observed
                report['first_observed'] = elk_response.get('hits').get('hits')[0].get('_source').get('first_observed')

        except Exception as e:
            self.logger.error('Failed to get document from Elastic Search: {}'.format(e)) 

        # Push report to Elastic
        try:
            # push report
            self.elastic_client.update(index='scanwhisperer-{}-{}'.format(report.get('scan_type'), self.CONFIG_SECTION), id=document_id, body={'doc': report,'doc_as_upsert':True})
        
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
                        record['norm_time'] = self.nessus.get_utc_from_local(int(record['last_modification_date']), local_tz=self.nessus.tz_conv(record['timezone']))
                    
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

                        self.logger.info('{} {} records whispered to Elastic Search'.format(report_csv.shape[0], self.CONFIG_SECTION))

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

