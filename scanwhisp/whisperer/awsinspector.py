#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from six.moves import range
from functools import reduce

__author__ = 'Alberto Marziali'

from ..base.config import swConfig
from .base import scanWhispererBase
from ..frameworks.awsinspector import AWSInspectorAPI

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
import re

import hashlib
from elasticsearch import Elasticsearch
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class scanWhispererAWSInspector(scanWhispererBase):
    CONFIG_SECTION = None

    def __init__(
            self,
            profile='awsinspector',
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=False
    ):
        self.CONFIG_SECTION = profile

        super(scanWhispererAWSInspector, self).__init__(config=config,purge=purge)

        self.purge = purge
        self.verbose = verbose

        # setup logger
        self.logger = logging.getLogger('scanWhispererAWSInspector')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('Starting {} whisperer'.format(self.CONFIG_SECTION))

        # if the config is available
        if config is not None:
            try:
                # fetch data from config file
                # AWS Inspector
                self.access_key = self.config.get(self.CONFIG_SECTION, 'access_key')
                self.secret_key = self.config.get(self.CONFIG_SECTION, 'secret_key')
                self.region_name = self.config.get(self.CONFIG_SECTION, 'region_name')

                # Elastic Search
                self.elk_host = self.config.get(self.CONFIG_SECTION, 'elk_host')
                self.elk_username = self.config.get(self.CONFIG_SECTION, 'elk_username')
                self.elk_password = self.config.get(self.CONFIG_SECTION, 'elk_password')

                # try to connect to AWS Inspector
                try:
                    self.logger.info('Attempting to connect to {}...'.format(self.CONFIG_SECTION))
                    self.awsinspector = \
                        AWSInspectorAPI(region_name=self.region_name,
                                  access_key=self.access_key,
                                  secret_key=self.secret_key
                                  )
                    self.awsinspector_connect = True
                    self.logger.info('Connected to {}'.format(self.CONFIG_SECTION))

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


    # This function return the list of scan to process (scan listed by api - scan already imported)
    def get_scans_to_process(self, latest_scans):
        self.logger.info('Gathering all scan data... this may take a while...')
        scans_to_process = []

        if self.uuids:
            for scan in latest_scans:
                if scan['arn'] not in self.uuids:
                    scans_to_process.append(scan)
        else:
            scans_to_process = latest_scans

        self.logger.info('Identified {new} scans to be processed'.format(new=len(scans_to_process)))

        return scans_to_process


    # This function adds a field to report
    def add_to_report(self, report, field, content):
        if content:
            if isinstance(content, str):
                content = content.strip()

            report.update({ field : content })


    # This function creates a single report
    def create_report(self, scan, finding):
        # assemble report
        report = {}

        # ---- AWS Inspector specific part ----
        # This fields are exclusive to AWS Inspector
        self.add_to_report(report, 'awsinspector.scan.arn', scan['arn'])
        self.add_to_report(report, 'awsinspector.scan.name', scan.get('name')) 
        self.add_to_report(report, 'awsinspector.rules_package.arn', finding.get('serviceAttributes', {}).get('rulesPackageArn'))
        self.add_to_report(report, 'awsinspector.rules_package.name', self.awsinspector.get_rule_name(finding.get('serviceAttributes').get('rulesPackageArn')))
        self.add_to_report(report, 'awsinspector.finding.arn', finding['arn'])
        self.add_to_report(report, 'awsinspector.aws_account_id', next((item for item in re.findall(r'^arn:aws:inspector:.*:([0-9]*):.*$', finding['arn'])), None))
        self.add_to_report(report, 'awsinspector.tag', next((item.get('value') for item in finding['assetAttributes']['tags'] if item.get('key') == 'Name'), ''))

        # ---- Asset part ----
        # Scan target (asset) properties
        self.add_to_report(report, 'asset.host', finding['assetAttributes']['agentId'])
        self.add_to_report(report, 'asset.ip', next((item.get('publicIp') for item in finding['assetAttributes']['networkInterfaces'] if item.get('publicIp') != ''), None))

        # ---- CVE part ----
        # extract CVE related fields (if present)
        self.add_to_report(report, 'cve.id', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'CVE_ID'), None))
        self.add_to_report(report, 'cve.cvss3.score', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'CVSS3_SCORE'), None))
        self.add_to_report(report, 'cve.cvss2.score', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'CVSS2_SCORE'), None))
        self.add_to_report(report, 'cve.package_name', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'package_name'), None))

        # ---- CIS Part ----
        # extract CIS related fields (if present)
        self.add_to_report(report, 'cis.control', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'BENCHMARK_RULE_ID'), None))
        self.add_to_report(report, 'cis.benchmark', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'BENCHMARK_ID'), None))
        self.add_to_report(report, 'cis.level', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'CIS_BENCHMARK_PROFILE'), None))
        
        # ---- Finding metadata part ----
        # extract Finding metadata 
        self.add_to_report(report, 'finding.title', finding.get('title'))
        self.add_to_report(report, 'finding.description', finding.get('description'))
        self.add_to_report(report, 'finding.solution', finding.get('recommendation'))
        self.add_to_report(report, 'finding.source', 'awsinspector')
        self.add_to_report(report, 'finding.first_observed', finding.get('updatedAt', datetime.now()).isoformat())
        self.add_to_report(report, 'finding.last_observed', finding.get('updatedAt', datetime.now()).isoformat())
        # guess finding type by existing fields
        if report.get('cve.id'):
            self.add_to_report(report, 'finding.type', 'cve')
        elif report.get('cis.benchmark'):
            self.add_to_report(report, 'finding.type', 'cis')
        else:
            self.add_to_report(report, 'finding.type', 'other')
        # calculate finding risk
        if report.get('cve.cvss2.score'):
            # Calculate risk based off cvss2 score
            try:
                if(float(report.get('cve.cvss2.score')) == 0):
                    self.add_to_report(report, 'finding.risk', 'Info')
                elif (float(report.get('cve.cvss2.score')) <= 3.9):
                    self.add_to_report(report, 'finding.risk', 'Low')
                elif (float(report.get('cve.cvss2.score')) <= 6.9):
                    self.add_to_report(report, 'finding.risk', 'Medium')
                elif (float(report.get('cve.cvss2.score')) <= 9.9):
                    self.add_to_report(report, 'finding.risk', 'High')
                elif (float(report.get('cve.cvss2.score')) == 10):
                    self.add_to_report(report, 'finding.risk', 'Critical')        
            except ValueError:  
                print ("Not a float")
        else:
            # Use AWS Inspector severity as Risk
            self.add_to_report(report, 'finding.risk', finding.get('severity'))

        
        return report

    
    def push_report(self, scan, finding):

        # Create report
        report = self.create_report(scan, finding)

        # Use scan_type field to generate id accordingly
        document_id = ''
        if report.get('finding.type') == 'cve':
            document_id = hashlib.sha1(('{}{}'.format(report.get('asset.host'), report.get('cve.id'))).encode('utf-8')).hexdigest()
        else:
            document_id = hashlib.sha1(('{}{}'.format(report.get('asset.host'), report.get('finding.title'))).encode('utf-8')).hexdigest()

        # Create index on Elastic Search
        try:
            # create index if needed
            mapping = {
                "mappings": {
                    "properties": {
                        "cve.cvss2.score": {
                            "type": "float" 
                        },
                        "cve.cvss3.score": {
                            "type": "float" 
                        }
                    }
                }
            }
            self.elastic_client.indices.create(index='scanwhisperer-{}-awsinspector'.format(report.get('finding.type')),body=mapping, ignore=400)

        except Exception as e:
            self.logger.error('Failed create index scanwhisperer-{}-awsinspector on Elastic Search: {}'.format(report.get('finding.type'), e)) 
          
        # Query Elastic Search to fetch a document with the same ID
        # If found,overwrite new first_observed with older to avoid updating it
        try:
            # Fetch document
            elk_response = self.elastic_client.search(index='scanwhisperer-{}-awsinspector'.format(report.get('finding.type')), body={
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
            self.elastic_client.update(index='scanwhisperer-{}-awsinspector'.format(report.get('finding.type')), id=document_id, body={'doc': report,'doc_as_upsert':True})
        
        except Exception as e:
            self.logger.error('Failed push document to Elastic Search: {}'.format(e)) 


    def whisper_awsinspector(self):
        if self.awsinspector_connect and self.elk_connect:
            # get scan list from inspector, avoiding already fetched scans (if failed, throw an exception)
            try:
                scans = self.get_scans_to_process(self.awsinspector.scans)

                # if no scans are available, just exit
                if not scans:
                    self.logger.warn('No new scans to process. Exiting...')
                    return self.exit_code

                # cycle through every scan available
                for scan in scans:

                    # Try to request findings list
                    try:
                        findings = self.awsinspector.get_scan_findings(scan['arn'])

                        # cycle through every finding
                        whispered_count = 0
                        for finding in findings:
                            # parse the finding and add the row to output_csv
                            try:
                                self.push_report(scan, finding)
                                whispered_count += 1
                            except Exception as e:
                                self.logger.error('AWS Inspector finding push error: {}'.format(e))   

                        # save the scan (assessmentRun) in the scanwhisperer db
                        record_meta = (
                                        scan['name'],
                                        scan['arn'],
                                        int(time.time()),
                                        'file_name',
                                        int(time.time()),
                                        whispered_count,
                                        self.CONFIG_SECTION,
                                        scan['arn'],
                                        1,
                                        0,
                                    )
                        self.record_insert(record_meta)
                        self.logger.info('{} records whispered to Elastic Search'.format(whispered_count))
                    
                    except Exception as e:
                        self.logger.error('Could not download {} scan {} findings: {}'.format(self.CONFIG_SECTION, scan['arn'], str(e)))

            except Exception as e:
                self.logger.error('Could not process new {} scans: {}'.format(self.CONFIG_SECTION, e))

            self.conn.close()
            self.logger.info('Scan aggregation completed!')
        else:
            self.logger.error('Failed to connect to {} API'.format(self.CONFIG_SECTION))
            self.exit_code += 1
        return self.exit_code

