#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

__author__ = 'Alberto Marziali'

from ...base.config import swConfig
from ...whisperer.base import scanWhispererBase
from ...modules.bitsight.bitsightapi import BitSightAPI
from ...modules.bitsight.bitsightelk import BitSightELK

import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

                try:
                    # Try to connect to S3
                    self.logger.info('Attempting to connect to BitSight')
                    self.bitsightapi = BitSightAPI(api_key=self.api_key)

                    self.bitsightapi_connect = True
                    self.logger.info('Connected to BitSight')

                    try:
                        # Try to connect to Elastic Search
                        self.logger.info('Attempting to connect to Elastic Search ({})'.format(self.elk_host))
                        self.bitsightelk = \
                            BitSightELK( host=self.elk_host,
                                         username=self.elk_username,
                                         password=self.elk_password,
                                        )

                        self.bitsightelk_connect = True
                        self.logger.info('Connected to Elastic Search ({})'.format(self.elk_host))

                    except Exception as e:
                        self.logger.error('Could not connect to Elastic Search ({}): {}'.format(self.elk_host, e))

                except Exception as e:
                    self.logger.error('Could not connect to BitSight: {}'.format(str(e)))

            except Exception as e:
                self.logger.error('Could not properly load your config!\nReason: {e}'.format(e=e))
                

    def whisperer_bitsight(self):
        # If BitSIght connection has been successful
        if self.bitsightapi_connect and self.bitsightelk_connect:
            # Update all reports
            try:
                try:
                    # Get companies via API
                    for company in self.bitsightapi.get_companies():
                        self.logger.info('Processing company: {}'.format(company.get('name')))

                        # For each company, get findings and create documents
                        self.bitsightapi.get_findings(company, self.bitsightelk.add_to_queue)

                        # Push documents to Elastic Search
                        self.bitsightelk.push_queue()

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

