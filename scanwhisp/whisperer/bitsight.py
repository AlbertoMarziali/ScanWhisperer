#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

from pandas.io import api

__author__ = 'Alberto Marziali'

from ..base.config import swConfig
from .base import scanWhispererBase
from ..frameworks.bitsight import BitSightAPI
import logging
import io
import pandas as pd
import hashlib
from elasticsearch import Elasticsearch
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime
from geoip import geolite2
import socket
import json
import re
import copy


class scanWhispererBitSight(scanWhispererBase):
    CONFIG_SECTION = None

    def __init__(
            self,
            profile='bitsight',
            config=None,
            verbose=None
    ):
        self.CONFIG_SECTION = profile

        super(scanWhispererBitSight, self).__init__(config=config)

        self.verbose = verbose

        # set up logger
        self.logger = logging.getLogger('scanWhispererBitSight')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('Starting {} whisperer'.format(self.CONFIG_SECTION))

        # if the config is available
        if config is not None:
            try:
                # Try to fetch data from config file
                # BitSight
                self.api_key = self.config.get(self.CONFIG_SECTION, 'api_key')

                # Elastic Search
                self.elk_host = self.config.get(self.CONFIG_SECTION, 'elk_host')
                self.elk_username = self.config.get(self.CONFIG_SECTION, 'elk_username')
                self.elk_password = self.config.get(self.CONFIG_SECTION, 'elk_password')

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

                try:
                    # Try to connect to S3
                    self.logger.info('Attempting to connect to BitSight')

                    self.bitsight = BitSightAPI(api_key=self.api_key)

                    self.bitsight_connect = True
                    self.logger.info('Connected to BitSight')

                except Exception as e:
                    self.logger.error('Could not connect to BitSight: {}'.format(str(e)))

            except Exception as e:
                self.logger.error('Could not properly load your config!\nReason: {e}'.format(e=e))
                

    def index_cleanup(self):
        # Delete old index on Elastic Search
        self.elastic_client.indices.delete(index='scanwhisperer-bitsight',ignore=[400,404])

        # Create index on Elastic Search
        mapping = {
            "mappings": {
                "properties": {
                    "asset.port": {
                        "type": "integer" 
                    },
                    "asset.geo.location": {
                        "type": "geo_point" 
                    }
                }
            }
        }
        self.elastic_client.indices.create(index='scanwhisperer-bitsight',body=mapping, ignore=400)

        self.logger.info('Index "scanwhisperer-bitsight" on Elastic Search ready.')
    
    
    # This function adds a field to report
    def add_to_report(self, report, field, content):
        if content:
            if isinstance(content, str):
                content = content.strip()

            report.update({ field : content })


    # This function creates a reports from a finding (one finding may contain multiple reports)
    def create_reports(self, company, finding):
        # assemble report: 
        report = {}
        reports = []

         # ---- BitSight specific part ----
        # This fields are exclusive to BitSight
        self.add_to_report(report, 'bitsight.company', company.get('name'))
        self.add_to_report(report, 'bitsight.evidence_key',  finding.get('evidence_key'))
        # Attributed companies. Pick first not containing "Group", else pick absolute First.
        self.add_to_report(report, 'bitsight.attributed_company', next((item.get('name') for item in finding['attributed_companies'] if item.get('name') and "Group" not in item.get('name', '')), next((item.get('name') for item in finding['attributed_companies']), None)))
        self.add_to_report(report, 'bitsight.rolledup_observation_id',  finding.get('rolledup_observation_id'))
        self.add_to_report(report, 'bitsight.temporary_id',  finding.get('temporary_id'))
        
        # ---- Asset part ----
        # Scan target (asset) properties
        self.add_to_report(report, 'asset.observed_ips', finding.get('details', {}).get('observed_ips'))
        self.add_to_report(report, 'asset.port', finding.get('details', {}).get('dest_port'))
        # Geo location coordinates (extract IP from Observed IPS)
        if report.get('asset.observed_ips'):
            try:
                # IP Location lookup
                observed_ip = next((item for item in report['asset.observed_ips']), '')
                extracted_ip = next((item for item in re.findall(r'(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)', observed_ip)), '')
                df_geoip_location = geolite2.lookup(extracted_ip)
                if df_geoip_location:
                    self.add_to_report(report, 'asset.geo.location', {
                                                "lat": df_geoip_location.location[0],
                                                "lon": df_geoip_location.location[1]
                                            })
            except: 
                pass # Ignore it
        # Geo name (IT, CZ)
        self.add_to_report(report, 'asset.geo.name', finding.get('details', {}).get('geo_ip_location'))

        # ---- Finding part ----
        # extract Finding metadata 
        self.add_to_report(report, 'finding.comments', finding.get('comments'))
        self.add_to_report(report, 'finding.grade', finding.get('details', {}).get('grade'))
        self.add_to_report(report, 'finding.rollup_end_date', finding.get('details').get('rollup_end_date'))
        self.add_to_report(report, 'finding.rollup_start_date', finding.get('details').get('rollup_start_date'))
        self.add_to_report(report, 'finding.first_observed', finding.get('first_seen'))
        self.add_to_report(report, 'finding.last_observed', finding.get('last_seen'))
        self.add_to_report(report, 'finding.source', self.CONFIG_SECTION)
        self.add_to_report(report, 'finding.remaining_decay', finding.get('remaining_decay'))
        self.add_to_report(report, 'finding.risk.category', finding.get('risk_category'))
        self.add_to_report(report, 'finding.risk.vector.raw', finding.get('risk_vector'))
        self.add_to_report(report, 'finding.risk.vector.label', finding.get('risk_vector_label'))
        self.add_to_report(report, 'finding.severity.score', finding.get('severity'))
        self.add_to_report(report, 'finding.severity.category', finding.get('severity_category'))

        # findings details
        df_diligence_annotations = finding.get('details', {}).get('diligence_annotations', '')
        if df_diligence_annotations is not '':
            self.add_to_report(report, 'finding.diligence_annotations', json.dumps(df_diligence_annotations, indent=4, sort_keys=True))

        # Report is almost ready
        reports.append(report)

        # REPORT DUPLICATION
        # Multiple assets and remediation leads to multiple reports

        # ASSET: Multiple assets generate multiple reports
        # Tecnique: copy the report list and duplicate each field in a new one
        df_assets = finding.get('assets', [])
        if df_assets:
            new_reports = []

            # copy each report from reports and multiply it
            for single_report in reports:

                # create a new report for each asset
                for asset in df_assets:
                    new_report = copy.deepcopy(single_report) # copy the report

                    # Asset name
                    self.add_to_report(new_report, 'asset.name', asset.get('asset'))
                    # Asset importance
                    self.add_to_report(new_report, 'asset.importance', asset.get('importance'))
                    # Asset category
                    self.add_to_report(new_report, 'asset.category', asset.get('category'))

                    # Add report to new reports
                    new_reports.append(new_report)

            # Replace report list
            reports = copy.deepcopy(new_reports)

        # REMEDIATIONS: Multiple remediations generate multiple reports.
        # Loop over remediations and create a new report for each one
        # Tecnique: copy the report list and duplicate each field in a new one
        df_remediations = finding.get('details', {}).get('remediations', [])
        if df_remediations:
            new_reports = []

            # copy each report from reports and multiply it
            for single_report in reports:

                # create a new report for each remediation
                for remediation in df_remediations:
                    new_report = copy.deepcopy(single_report) # copy the report

                    # Add Message Field
                    self.add_to_report(new_report, 'finding.title', remediation.get('message'))
                    # Add Remediation Field
                    self.add_to_report(new_report, 'finding.solution', remediation.get('remediation_tip'))

                    # Add report to new reports
                    new_reports.append(new_report)

            # Replace report list
            reports = copy.deepcopy(new_reports)

        # Return the generated reports
        return reports

    
    def push_report(self, company, finding):
        # Get reports to push
        reports = self.create_reports(company, finding)

        # For each report, push it
        for report in reports:
            # Push report to Elastic
            try:
                self.elastic_client.index(index='scanwhisperer-bitsight', body=report)
            except Exception as e:
                self.logger.error('Failed push document to Elastic Search: {}'.format(e)) 


    def whisperer_bitsight(self):
        # If BitSIght connection has been successful
        if self.bitsight_connect:
            # Update all reports
            try:
                # Cleanup index
                self.index_cleanup()

                try:
                    # Get companies via API
                    for company in self.bitsight.get_companies():
                        self.logger.info('Processing company: {}'.format(company.get('name')))

                        # For each company, get findings and push reports
                        self.bitsight.get_findings(company, self.push_report)

                        # Company one
                        self.logger.info('Done')

                    # Done
                    self.logger.info('All jobs done!')

                except Exception as e:
                    self.logger.error('Failed to process BitSight reports: {}'.format(e)) 

            except Exception as e:
                self.logger.error('Failed to cleanup index "scanwhisperer-bitsight" from Elastic Search: {}'.format(e))

        else:
            self.logger.error('Connection to BitSight unavailable.')
            self.exit_code += 1

        self.logger.info('Done. ({})'.format(self.exit_code))
        return self.exit_code

