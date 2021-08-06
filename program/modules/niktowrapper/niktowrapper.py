#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

__author__ = 'Alberto Marziali'

from base.base import scanWhispererBase
from modules.niktowrapper.niktowrappers3 import NiktoWrapperS3
from modules.niktowrapper.niktowrapperelk import NiktoWrapperELK

import logging
import io
import pandas as pd


class scanWhispererNiktoWrapper(scanWhispererBase):
    CONFIG_SECTION = None

    def __init__(
            self,
            profile='niktowrapper',
            config=None,
            verbose=False,
            daemon=False
    ):
        self.CONFIG_SECTION = profile

        super(scanWhispererNiktoWrapper, self).__init__(config=config)

        self.verbose = verbose
        self.daemon = daemon
        self.ready = False

        # set up logger
        self.logger = logging.getLogger('scanWhispererNiktoWrapper')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('Starting Module')

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

                try:
                    # Try to connect to S3
                    self.logger.info('Attempting to connect to S3')

                    self.niktowrappers3 = NiktoWrapperS3( access_key=self.access_key,
                                                            secret_key=self.secret_key,
                                                            region_name=self.region_name,
                                                            bucket_name=self.bucket_name,
                                                            verbose=verbose)

                    self.logger.info('Connected to S3')

                    try:
                        # Try to connect to Elastic Search
                        self.logger.info('Attempting to connect to Elastic Search ({})'.format(self.elk_host))
                        self.niktowrapperelk = NiktoWrapperELK( host=self.elk_host,
                                                                username=self.elk_username,
                                                                password=self.elk_password,
                                                                verbose=verbose)

                        self.logger.info('Connected to Elastic Search ({})'.format(self.elk_host))

                        self.ready = True                            
                        self.logger.info('Module Ready')

                    except Exception as e:
                        self.logger.error('Could not connect to Elastic Search ({}): {}'.format(self.elk_host, e))

                except Exception as e:
                    self.logger.error('Could not connect to S3: {}'.format(str(e)))

            except Exception as e:
                self.logger.error('Could not properly load your config!\nReason: {e}'.format(e=e))
                

    def whisper_niktowrapper(self):
        # If module is ready
        if self.ready:
            # get new file list
            try:
                files_to_process = self.niktowrappers3.get_new_files()

                # if no scans are available, just exit
                if not files_to_process or len(files_to_process) == 0:
                    if not self.daemon:
                        self.logger.warn('No new scans to process.')
                else:
                    self.logger.info('Processing {} new reports'.format(len(files_to_process)))
                            
                    # cycle through every scan available
                    for remote_file_name in files_to_process:
                        
                        self.logger.info('Processing report {}'.format(remote_file_name))

                        # Download the file from S3     
                        self.logger.debug('Downloading report...')
                        try:
                            report_csv = pd.read_csv(io.StringIO(self.niktowrappers3.download_file(remote_file_name)), na_filter=False)
                        except Exception as e:
                            self.logger.error('NiktoWrapper findings download failed: {}'.format(e))  
                            return

                        # Check if the report contains some findings
                        if len(report_csv) > 0:

                            # Clear the document queue (avoid memory leak)
                            self.niktowrapperelk.clear_queue()
                        
                            # Iterate over report lines and push it to Elastic Search
                            self.logger.debug('Creating documents from {} NiktoWrapper findings...'.format(report_csv.shape[0]))
                            try:
                                # Iterate over report rows
                                for index, finding in report_csv.iterrows():
                                    self.niktowrapperelk.add_to_queue(finding)
                            except Exception as e:
                                self.logger.error('NiktoWrapper document creation failed: {}'.format(e))   
                                return
                            
                            # When document queue is ready, push it
                            self.logger.debug('Pushing documents...')
                            try:
                                self.niktowrapperelk.push_queue()  
                            except Exception as e:
                                self.logger.error('NiktoWrapper document queue push failed: {}'.format(e))   
                                return

                            # Delete the file from S3
                            self.logger.debug('Deleting report from S3...')
                            try:
                                self.niktowrappers3.delete_file(remote_file_name)
                                self.logger.debug('File removed from S3: {}'.format(remote_file_name))
                            except Exception as e:
                                self.logger.error('NiktoWrapper report deletion failed: {}'.format(e))  
                                return

                            self.logger.info('Report processed successfully')  

                        else:
                            self.logger.warn('Report doesn\'t contain any finding')

            except Exception as e:
                self.logger.error('Download from S3 failed: {}'.format(e))

        # Close DB connection only if not in daemon mode
        if not self.daemon:
            self.logger.info('Module\'s job completed!')

