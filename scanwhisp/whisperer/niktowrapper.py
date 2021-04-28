#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

__author__ = 'Alberto Marziali'

from ..base.config import swConfig
from .base import scanWhispererBase
from ..frameworks.niktowrapper import NiktoWrapperS3
import logging


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
                self.access_key = self.config.get(self.CONFIG_SECTION, 'access_key')
                self.secret_key = self.config.get(self.CONFIG_SECTION, 'secret_key')
                self.region_name = self.config.get(self.CONFIG_SECTION, 'region_name')
                self.bucket_name = self.config.get(self.CONFIG_SECTION, 'bucket_name')

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

                        local_file_path = self.path_check(remote_file_name)
                        self.niktowrapper.download_file(remote_file_name, local_file_path)

                        self.logger.info('File written: {}'.format(local_file_path))

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

