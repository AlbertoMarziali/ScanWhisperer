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
                    "port": {
                        "type": "integer" 
                    },
                    "geoip_location": {
                        "type": "geo_point" 
                    }
                }
            }
        }
        self.elastic_client.indices.create(index='scanwhisperer-bitsight',body=mapping, ignore=400)

        self.logger.info('Index "scanwhisperer-bitsight" on Elastic Search ready.')
    

    # This function creates a reports from a finding (one finding may contain multiple reports)
    def create_reports(self, company, finding):
        # assemble report: 
        report = {}

        # Tool name
        report.update({ 'tags': self.CONFIG_SECTION })

        # Company name, from company object
        df_company = company.get('name', '')
        if df_company is not '':
            report.update({ 'company': df_company })

        # Asset. Pick first
        df_asset = next((item.get('asset', '') for item in finding['assets']), '')
        if df_asset is not '':
            report.update({ 'asset': df_asset })

        # Asset importance. Pick first
        df_asset_importance = next((item.get('importance', '') for item in finding['assets']), '')
        if df_asset_importance is not '':
            report.update({ 'asset_importance': df_asset_importance })

        # Asset category. Pick first
        df_asset_category = next((item.get('category', '') for item in finding['assets']), '')
        if df_asset_category is not '':
            report.update({ 'asset_category': df_asset_category })

        # Attributed companies. Pick first not containing "Group", else pick absolute First.
        df_attributed_company = next((item.get('name', '') for item in finding['attributed_companies'] if item.get('name') and "Group" not in item.get('name', '')), '')
        if df_attributed_company is '':
            df_attributed_company = next((item.get('name', '') for item in finding['attributed_companies']), '')
        report.update({ 'attributed_company': df_attributed_company })

        # User comments
        df_comments = finding.get('comments', '')
        if df_comments is not '':
            report.update({ 'comments': df_comments })

        # Port
        df_port = finding.get('details').get('dest_port', '')
        if df_port is not '':
            report.update({ 'port': df_port })

        # Grade
        df_grade = finding.get('details').get('grade', '')
        if df_grade is not '':
            report.update({ 'grade': df_grade })

        # Diligence annotation (extra data)
        df_diligence_annotations = finding.get('details').get('diligence_annotations', '')
        if df_diligence_annotations is not '':
            report.update({ 'diligence_annotations': json.dumps(df_diligence_annotations, indent=4, sort_keys=True) })

        # Observed IPS
        df_observed_ips = finding.get('details').get('observed_ips', '')
        if df_observed_ips is not '':
            report.update({ 'observed_ips': df_observed_ips })

        # Rollup end date
        df_rollup_end_date = finding.get('details').get('rollup_end_date', '')
        if df_rollup_end_date is not '':
            report.update({ 'rollup_end_date': df_rollup_end_date })

        # Rollup start date
        df_rollup_start_date = finding.get('details').get('rollup_start_date', '')
        if df_rollup_start_date is not '':
            report.update({ 'rollup_start_date': df_rollup_start_date })

        # Evidence key
        df_evidence_key = finding.get('evidence_key', '')
        if df_evidence_key is not '':
            report.update({ 'evidence_key': df_evidence_key })

        # Geoip coordinates (extract IP from Observed IPS)
        if df_observed_ips is not '':
            try:
                # IP Location lookup
                observed_ip = next((item for item in df_observed_ips), '')
                extracted_ip = next((item for item in re.findall(r'(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)', observed_ip)), '')
                df_geoip_location = geolite2.lookup(extracted_ip)
                if df_geoip_location:
                    report.update({ 'geoip_location': {
                                                "lat": df_geoip_location.location[0],
                                                "lon": df_geoip_location.location[1]
                                            } })
            except: 
                pass # Ignore it

        # Geoip location (IT, CZ)
        df_geo_ip_location_name = finding.get('details').get('geo_ip_location', '')
        if df_geo_ip_location_name is not '':
            report.update({ 'geo_ip_location_name': df_geo_ip_location_name })

        # First seen
        df_first_seen = finding.get('first_seen', '')
        if df_first_seen is not '':
            report.update({ 'first_seen': df_first_seen })

        # Last seen
        df_last_seen = finding.get('last_seen', '')
        if df_last_seen is not '':
            report.update({ 'last_seen': df_last_seen })

        # Remaining decay
        df_remaining_decay = finding.get('remaining_decay', '')
        if df_remaining_decay is not '':
            report.update({ 'remaining_decay': df_remaining_decay })

        # Risk category
        df_risk_category = finding.get('risk_category', '')
        if df_risk_category is not '':
            report.update({ 'risk_category': df_risk_category })

        # Risk vector
        df_risk_vector = finding.get('risk_vector', '')
        if df_risk_vector is not '':
            report.update({ 'risk_vector': df_risk_vector })

        # Risk vector label
        df_risk_vector_label = finding.get('risk_vector_label', '')
        if df_risk_vector_label is not '':
            report.update({ 'risk_vector_label': df_risk_vector_label })

        # Rolledup observation id
        df_rolledup_observation_id = finding.get('rolledup_observation_id', '')
        if df_rolledup_observation_id is not '':
            report.update({ 'rolledup_observation_id': df_rolledup_observation_id })

        # Severity
        df_severity = finding.get('severity', '')
        if df_severity is not '':
            report.update({ 'severity': df_severity })

        # Severity category
        df_severity_category = finding.get('severity_category', '')
        if df_severity_category is not '':
            report.update({ 'severity_category': df_severity_category })

        # Temporary ID
        df_temporary_id = finding.get('temporary_id', '')
        if df_temporary_id is not '':
            report.update({ 'temporary_id': df_temporary_id })

        # Multiple remediations generate multiple reports.
        # Loop over remediations and create a new report for each one
        reports = []

        df_remediations = finding.get('details').get('remediations')
        if df_remediations:
            for remediation in df_remediations:
                # Add Message Field
                df_message = remediation.get('message', '')
                if df_message is not '':
                    report.update({ 'message': df_message })

                # Add Remediation Field
                df_remediation_tip = remediation.get('remediation_tip', '')
                if df_remediation_tip is not '':
                    report.update({ 'remediation': df_remediation_tip })

                # Append to list
                reports.append(report)
        else:
            # Just append current report
            reports.append(report)

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

