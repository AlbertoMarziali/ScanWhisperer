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


    # This function creates a single report
    def create_report(self, scan, finding):
        # assemble report
        report = {}

        # ---- Scan data part ----
        report.update({ 'tags': 'awsinspector' })

        df_scanArn = scan['arn']
        report.update({ 'scan_arn' : df_scanArn.strip() })

        df_scanName = scan.get('name', '')
        report.update({ 'scan_name' : df_scanName.strip() })

        df_ruleArn = finding.get('serviceAttributes').get('rulesPackageArn')
        report.update({ 'rules_package_arn' : df_ruleArn.strip() })

        df_ruleName = self.awsinspector.get_rule_name(finding.get('serviceAttributes').get('rulesPackageArn'))
        report.update({ 'rules_package_name': df_ruleName.strip() })

        # ---- Time part ----
        df_first_observed = finding.get('updatedAt', datetime.now()).isoformat()
        report.update({ 'first_observed': df_first_observed })

        df_last_observed = finding.get('updatedAt', datetime.now()).isoformat()
        report.update({ 'last_observed': df_last_observed  })

        # ---- Finding Common part ----
        df_finding_arn = finding['arn']
        report.update({'finding_arn': df_finding_arn})

        df_aws_account_id = next((item for item in re.findall(r'^arn:aws:inspector:.*:([0-9]*):.*$', finding['arn'])), '')
        report.update({'aws_account_id': df_aws_account_id})

        df_agentId = finding['assetAttributes']['agentId']
        report.update({ 'asset': df_agentId.strip() })

        df_publicIp = next((item.get('publicIp', '') for item in finding['assetAttributes']['networkInterfaces'] if item.get('publicIp') != ''), '')
        if df_publicIp is not '':
            report.update({ 'ip': df_publicIp.strip() })

        df_tagName = next((item.get('value', '') for item in finding['assetAttributes']['tags'] if item.get('key') == 'Name'), '')
        if df_tagName is not '':
            report.update({ 'tag': df_tagName.strip() })

        df_title = finding.get('title', '')
        if df_title is not '':
            report.update({ 'title': df_title.strip() })

        df_description = finding.get('description', '')
        if df_description is not '':
            report.update({ 'description': df_description.strip() })

        df_recommendation = finding.get('recommendation', '')
        if df_recommendation is not '':
            report.update({ 'solution' : df_recommendation.strip() })

        # ---- CVE part ----
        # extract CVE related fields (if present)
        df_cvss3_score = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'CVSS3_SCORE'), '')
        if df_cvss3_score is not '':
             report.update({ 'cvss3_score': df_cvss3_score })

        df_cvss2_score = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'CVSS2_SCORE'), '')
        if df_cvss2_score is not '':
            report.update({ 'cvss2_score': df_cvss2_score })
  
        df_cve_id = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'CVE_ID'), '')
        if df_cve_id is not '':
            report.update({ 'cve':  df_cve_id.strip() })

        df_pkg_name = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'package_name'), '')
        if df_pkg_name is not '':
            report.update({ 'package_name': df_pkg_name.strip() })
        
        df_cvss2 = ''
        if df_cvss2_score is not '':
            try:
                if(float(df_cvss2_score) == 0):
                    df_cvss2 = 'Info'
                elif (float(df_cvss2_score) <= 3.9):
                    df_cvss2 = 'Low'
                elif (float(df_cvss2_score) <= 6.9):
                    df_cvss2 = 'Medium'
                elif (float(df_cvss2_score) <= 9.9):
                    df_cvss2 = 'High'
                elif (float(df_cvss2_score) == 10):
                    df_cvss2 = 'Critical'

                report.update({ 'risk': df_cvss2 })
                
            except ValueError:  
                print ("Not a float")

        # ---- CIS Part ----
        # extract CIS related fields (if present)
        df_cis_control = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'BENCHMARK_RULE_ID'), '')
        if df_cis_control is not '':
            report.update({ 'cis_control': df_cis_control.strip() })

        df_cis_benchmark = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'BENCHMARK_ID'), '')
        if df_cis_benchmark is not '':
            report.update({ 'cis_benchmark': df_cis_benchmark.strip() })

        df_cis_level = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'CIS_BENCHMARK_PROFILE'), '')
        if df_cis_level is not '':
            report.update({ 'cis_level': df_cis_level.strip() })
        
        df_cis_severity = ''
        if df_cis_control is not '':
            df_cis_severity = finding.get('severity', '')
            if df_cis_severity is not '':
                report.update({ 'cis_severity': df_cis_severity.strip() })

        # ---- SCAN TYPE DETECTION ----
        # Detect scan type by existing fields
        df_scan_type = ''
        if report.get('cve'):
            df_scan_type = 'cve'
        elif report.get('cis_benchmark'):
            df_scan_type = 'cis'
        else:
            df_scan_type = 'other'
        
        report.update({ 'scan_type': df_scan_type })

        return report

    
    def push_report(self, scan, finding):

        # Create report
        report = self.create_report(scan, finding)

        # Use scan_type field to generate id accordingly
        document_id = ''
        if report.get('scan_type') == 'cve':
            document_id = hashlib.sha1(('{}{}'.format(report.get('asset'), report.get('cve'))).encode('utf-8')).hexdigest()
        else:
            document_id = hashlib.sha1(('{}{}'.format(report.get('asset'), report.get('title'))).encode('utf-8')).hexdigest()

        # Create index on Elastic Search
        try:
            # create index if needed
            mapping = {
                "mappings": {
                    "properties": {
                        "cvss2_score": {
                            "type": "float" 
                        },
                        "cvss3_score": {
                            "type": "float" 
                        }
                    }
                }
            }
            self.elastic_client.indices.create(index='scanwhisperer-{}-awsinspector'.format(report.get('scan_type')),body=mapping, ignore=400)

        except Exception as e:
            self.logger.error('Failed create index scanwhisperer-{}-awsinspector on Elastic Search: {}'.format(report.get('scan_type'), e)) 
          
        # Query Elastic Search to fetch a document with the same ID
        # If found,overwrite new first_observed with older to avoid updating it
        try:
            # Fetch document
            elk_response = self.elastic_client.search(index='scanwhisperer-{}-awsinspector'.format(report.get('scan_type')), body={
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
            self.elastic_client.update(index='scanwhisperer-{}-awsinspector'.format(report.get('scan_type')), id=document_id, body={'doc': report,'doc_as_upsert':True})
        
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

