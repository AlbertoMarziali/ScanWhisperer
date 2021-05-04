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
                # fetch API keys from config file
                self.access_key = self.config.get(self.CONFIG_SECTION, 'access_key')
                self.secret_key = self.config.get(self.CONFIG_SECTION, 'secret_key')
                self.region_name = self.config.get(self.CONFIG_SECTION, 'region_name')

                try:
                    # try to connect to AWS Inspector
                    self.logger.info('Attempting to connect to {}...'.format(self.CONFIG_SECTION))
                    self.awsinspector = \
                        AWSInspectorAPI(region_name=self.region_name,
                                  access_key=self.access_key,
                                  secret_key=self.secret_key
                                  )
                    self.awsinspector_connect = True
                    self.logger.info('Connected to {}'.format(self.CONFIG_SECTION))

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

    # This function creates a single CSV output file row
    def create_report(self, scan, finding):
        # extract the correct fields. Everyone is optional except for agentId and scanId. If not found, it'll trow an exception
        df_agentId = finding['assetAttributes']['agentId']
        df_publicIp = next((item.get('publicIp', '') for item in finding['assetAttributes']['networkInterfaces'] if item.get('publicIp') != ''), '')
        df_tagName = next((item.get('value', '') for item in finding['assetAttributes']['tags'] if item.get('key') == 'Name'), '')
        df_cvss3_score = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'CVSS3_SCORE'), '')
        df_cvss2_score = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'CVSS2_SCORE'), '')
        df_cve_id = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'CVE_ID'), '')
        df_pkg_name = next((item.get('value', '') for item in finding['attributes'] if item.get('key') == 'package_name'), '')
        df_title = finding.get('title', '')
        df_description = finding.get('description', '')
        df_recommendation = finding.get('recommendation', '')
        df_scanArn = scan['arn']
        df_scanName = scan.get('name', '')
        df_last_seen = finding.get('updatedAt', datetime.now()).timestamp()

        # calculate the correct cvss2 string score
        df_cvss2 = ''
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
        except ValueError:  
            print ("Not a float")

        # return the dataframe
        return {    'Agent ID' : df_agentId,
                    'Public IP': df_publicIp,
                    'Tag': self.cleanser(df_tagName),
                    'CVSS3 Score': df_cvss3_score,
                    'CVSS2 Score': df_cvss2_score,
                    'CVSS2 Severity': self.cleanser(df_cvss2),
                    'CVE': self.cleanser(df_cve_id),
                    'Package Name': self.cleanser(df_pkg_name),
                    'Title': self.cleanser(df_title),
                    'Description': self.cleanser(df_description),
                    'Recommendation' : self.cleanser(df_recommendation),
                    'Scan ARN' : df_scanArn,
                    'Scan Name' : self.cleanser(df_scanName),
                    'Last Seen' : df_last_seen
                }

    def whisper_awsinspector(self):
        if self.awsinspector_connect:
            # get scan list from inspector, avoiding already fetched scans (if failed, throw an exception)
            try:
                scans = self.get_scans_to_process(self.awsinspector.scans)

                # if no scans are available, just exit
                if not scans:
                    self.logger.warn('No new scans to process. Exiting...')
                    return self.exit_code

                # cycle through every scan available
                for scan in scans:
                    findings = self.awsinspector.get_scan_findings(scan['arn'])

                    # create the destination DataFrame
                    output_csv = pd.DataFrame()

                    # cycle through every finding
                    for finding in findings:
                        # parse the finding and add the row to output_csv
                        try:
                            output_csv = output_csv.append(self.create_report(scan, finding), ignore_index=True)
                        except:
                            self.logger.warn('AWS Inspector finding fetch error (missing agentId?)')   

                    # save the output csv of the scan
                    file_name = 'AWS_Inspector_%s.csv' % (time.time())
                    repls = (('\\', '_'), ('/', '_'), (' ', '_'))
                    file_name = reduce(lambda a, kv: a.replace(*kv), repls, file_name)
                    relative_path_name = self.path_check(file_name)

                    output_csv.to_csv(relative_path_name, index=False)

                    # save the scan (assessmentRun) in the scanwhisperer db
                    record_meta = (
                                    scan['name'],
                                    scan['arn'],
                                    int(time.time()),
                                    file_name,
                                    int(time.time()),
                                    output_csv.shape[0],
                                    self.CONFIG_SECTION,
                                    scan['arn'],
                                    1,
                                    0,
                                )
                    self.record_insert(record_meta)
                    self.logger.info('{filename} records written to {path}'.format(filename=output_csv.shape[0], path=file_name))

            except Exception as e:
                self.logger.error('Could not download {} scan: {}'.format(self.CONFIG_SECTION, str(e)))

            self.logger.info('Scan aggregation complete!')
        else:
            self.logger.error('Failed to connect to AWS API')
            self.exit_code += 1
        return self.exit_code

