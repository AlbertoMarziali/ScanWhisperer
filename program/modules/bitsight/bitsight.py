#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

__author__ = 'Alberto Marziali'

from common.base import scanWhispererBase
from modules.bitsight.bitsightapi import BitSightAPI
from modules.bitsight.bitsightelk import BitSightELK

import logging


class scanWhispererBitSight(scanWhispererBase):
    CONFIG_SECTION = None

    def __init__(
            self,
            profile='bitsight',
            config=None,
            verbose=False,
            daemon=False
    ):
        self.CONFIG_SECTION = profile

        super(scanWhispererBitSight, self).__init__(config=config)

        self.verbose = verbose
        self.daemon = daemon
        self.ready = False

        # set up logger
        self.logger = logging.getLogger('scanWhispererBitSight')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('Starting Module')

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

                try:
                    # Try to connect to S3
                    self.logger.info('Attempting to connect to BitSight')
                    self.bitsightapi = BitSightAPI( api_key=self.api_key,
                                                    verbose=verbose)

                    self.logger.info('Connected to BitSight')

                    try:
                        # Try to connect to Elastic Search
                        self.logger.info('Attempting to connect to Elastic Search ({})'.format(self.elk_host))
                        self.bitsightelk = \
                            BitSightELK( host=self.elk_host,
                                         username=self.elk_username,
                                         password=self.elk_password,
                                         verbose=verbose
                                        )
                        
                        self.logger.info('Connected to Elastic Search ({})'.format(self.elk_host))

                        self.ready = True
                        self.logger.info('Module Ready')

                    except Exception as e:
                        self.logger.error('Could not connect to Elastic Search ({}): {}'.format(self.elk_host, e))

                except Exception as e:
                    self.logger.error('Could not connect to BitSight: {}'.format(str(e)))

            except Exception as e:
                self.logger.error('Could not properly load your config: {e}'.format(e=e))
                

    def whisperer_bitsight(self):
        # If module is ready
        if self.ready:
            # Update all reports
            try:
                # Clear Elastic Search index
                self.bitsightelk.clear_index()

                # Get companies via API
                for company in self.bitsightapi.get_companies():

                    self.logger.info('Processing company: {}'.format(company.get('name')))

                    # Clear the document queue (avoid memory leak)
                    self.bitsightelk.clear_queue()

                    # For each company, get findings and create documents
                    self.logger.debug('Fetching findings and creating documents...')
                    try:
                        self.bitsightapi.get_findings(company, self.bitsightelk.add_to_queue)
                    except Exception as e:
                        self.logger.error('Document creation failed: {}'.format(e))
                        return

                    # Push documents to Elastic Search
                    self.logger.debug('Pushing documents...')
                    try:
                        self.bitsightelk.push_queue()
                    except Exception as e:
                        self.logger.error('Document queue push failed: {}'.format(e))   
                        return

                    # Company done
                    self.logger.info('Report processed successfully')

            except Exception as e:
                self.logger.error('Failed to process reports: {}'.format(e)) 

        # Close DB connection only if not in daemon mode
        if not self.daemon:
            self.logger.info('Module\'s job completed!') 

