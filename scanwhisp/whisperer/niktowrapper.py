#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

__author__ = 'Alberto Marziali'

from ..base.config import swConfig
from .base import scanWhispererBase
from ..frameworks.niktowrapper import NiktoWrapperS3
import logging
import io
import pandas as pd
import hashlib
from elasticsearch import Elasticsearch
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime
from geoip import geolite2


class scanWhispererNiktoWrapper(scanWhispererBase):
    CONFIG_SECTION = None

    def __init__(
            self,
            profile='niktowrapper',
            config=None,
            verbose=None
    ):
        self.CONFIG_SECTION = profile

        super(scanWhispererNiktoWrapper, self).__init__(config=config)

        self.verbose = verbose

        # set up logger
        self.logger = logging.getLogger('scanWhispererNiktoWrapper')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('Starting {} whisperer'.format(self.CONFIG_SECTION))

        # if the config is available
        if config is not None:
            try:
                # Try to fetch data from config file
                # NiktoWrapper (S3)
                self.access_key = self.config.get(self.CONFIG_SECTION, 'access_key')
                self.secret_key = self.config.get(self.CONFIG_SECTION, 'secret_key')
                self.region_name = self.config.get(self.CONFIG_SECTION, 'region_name')
                self.bucket_name = self.config.get(self.CONFIG_SECTION, 'bucket_name')

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
                    self.logger.info('Attempting to connect to S3')

                    self.niktowrapper = NiktoWrapperS3(access_key=self.access_key,
                                                        secret_key=self.secret_key,
                                                        region_name=self.region_name,
                                                        bucket_name=self.bucket_name)

                    self.s3_connect = True
                    self.logger.info('Connected to S3')

                except Exception as e:
                    self.logger.error('Could not connect to S3: {}'.format(str(e)))

            except Exception as e:
                self.logger.error('Could not properly load your config!\nReason: {e}'.format(e=e))
                
    

    # This function creates a single report
    def create_report(self, finding):
        # assemble report: 
        # hostname,ip,port,osvdb,httpmethod,uri,result,branch
        report = {}

        # ---- Scan data part ----
        report.update({ 'tags': self.CONFIG_SECTION })

        df_hostname = finding.get('hostname', '')
        if df_hostname is not '':
            report.update({ 'hostname': df_hostname })

        df_ip = finding.get('ip', '')
        report.update({ 'ip': df_ip })

        df_port = finding.get('port', '')
        report.update({ 'port': df_port })

        df_osvdb = finding.get('osvdb', '')
        if df_osvdb is not '':
            report.update({ 'osvdb': df_osvdb })

        df_httpmethod = finding.get('httpmethod', '')
        if df_httpmethod is not '':
            report.update({ 'httpmethod': df_httpmethod })

        df_uri = finding.get('uri', '')
        if df_uri is not '':
            report.update({ 'uri': df_uri })

        df_result = finding.get('result', '')
        report.update({ 'result': df_result })

        df_branch = finding.get('branch', '')
        if df_branch is not '':
            report.update({ 'branch': df_branch })

        # ---- Time part ----
        df_first_observed = datetime.now().isoformat()
        report.update({ 'first_observed': df_first_observed })

        df_last_observed =  datetime.now().isoformat()
        report.update({ 'last_observed': df_last_observed })

        # ---- GEOIP part ----
        df_geoip = geolite2.lookup(report['ip'])
        if df_geoip:
            report.update({ 'location': {
                                            "lat": df_geoip.location[0],
                                            "lon": df_geoip.location[1]
                                        } })

        return report

    
    def push_report(self, finding):

        # Create report
        report = self.create_report(finding)

        # Generate id 
        document_id = hashlib.sha1(('{}{}{}'.format(report.get('ip'), report.get('port'), report.get('result'))).encode('utf-8')).hexdigest()
        
        # Create index on Elastic Search
        try:
            # create index if needed
            mapping = {
                "mappings": {
                    "properties": {
                        "port": {
                            "type": "integer" 
                        },
                        "location": {
                            "type": "geo_point" 
                        }
                    }
                }
            }
            self.elastic_client.indices.create(index='scanwhisperer-niktowrapper',body=mapping, ignore=400)

        except Exception as e:
            self.logger.error('Failed to create index scanwhisperer-niktowrapper on Elastic Search: {}'.format(e)) 
          
        # Query Elastic Search to fetch a document with the same ID
        # If found,overwrite new first_observed with older to avoid updating it
        try:
            # Fetch document
            elk_response = self.elastic_client.search(index='scanwhisperer-niktowrapper', body={
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
            self.elastic_client.update(index='scanwhisperer-niktowrapper', id=document_id, body={'doc': report,'doc_as_upsert':True})
        
        except Exception as e:
            self.logger.error('Failed push document to Elastic Search: {}'.format(e)) 



    def whisper_niktowrapper(self):
        # If S3 connection has been successful
        if self.s3_connect:
            # get new file list
            try:
                files_to_process = self.niktowrapper.get_new_files()

                # if no scans are available, just exit
                if not files_to_process or len(files_to_process) == 0:
                    self.logger.warn('No new scans to process.')
                else:
                    # cycle through every scan available
                    for remote_file_name in files_to_process:
                        
                        # Download the file from S3
                        self.logger.info('Processing {}'.format(remote_file_name))
                        report_csv = pd.read_csv(io.StringIO(self.niktowrapper.download_file(remote_file_name)), na_filter=False)
                        
                        # Iterate over report lines and push it to Elastic Search
                        try:
                            for index, finding in report_csv.iterrows():
                                self.push_report(finding)
                        except Exception as e:
                            self.logger.error('{} finding push error: {}'.format(self.CONFIG_SECTION, e))   

                        self.logger.info('{} {} records whispered to Elastic Search'.format(report_csv.shape[0], self.CONFIG_SECTION))

                        # Delete the file from S3
                        self.niktowrapper.delete_file(remote_file_name)
                        self.logger.info('File removed from S3: {}'.format(remote_file_name))

                # done
                self.logger.info('All jobs done.')

            except Exception as e:
                self.logger.error('Download from S3 failed: {}'.format(e))

        else:
            self.logger.error('Connection to S3 unavailable.')
            self.exit_code += 1

        self.logger.info('Done. ({})'.format(self.exit_code))
        return self.exit_code

