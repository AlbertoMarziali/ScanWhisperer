#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

__author__ = 'Alberto Marziali'

from base.base import scanWhispererBase
from modules.awsinspector.awsinspectorapi import AWSInspectorAPI
from modules.awsinspector.awsinspectorelk import AWSInspectorELK

import time
import logging


class scanWhispererAWSInspector(scanWhispererBase):
    CONFIG_SECTION = None

    def __init__(
            self,
            profile='awsinspector',
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=False,
            daemon=False
    ):
        self.CONFIG_SECTION = profile

        super(scanWhispererAWSInspector, self).__init__(config=config,purge=purge)

        self.purge = purge
        self.verbose = verbose
        self.daemon = daemon
        self.ready = False

        # setup logger
        self.logger = logging.getLogger('scanWhispererAWSInspector')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('Starting Module')

        # if the config is available
        if config is not None:
            try:
                # fetch data from config file
                # AWS Inspector
                self.inspector_access_key = self.config.get(self.CONFIG_SECTION, 'inspector_access_key')
                self.inspector_secret_key = self.config.get(self.CONFIG_SECTION, 'inspector_secret_key')
                self.organization_access_key = self.config.get(self.CONFIG_SECTION, 'organization_access_key')
                self.organization_secret_key = self.config.get(self.CONFIG_SECTION, 'organization_secret_key')
                self.region_name = self.config.get(self.CONFIG_SECTION, 'region_name')

                # Elastic Search
                self.elk_host = self.config.get(self.CONFIG_SECTION, 'elk_host')
                self.elk_username = self.config.get(self.CONFIG_SECTION, 'elk_username')
                self.elk_password = self.config.get(self.CONFIG_SECTION, 'elk_password')

                # try to connect to AWS Inspector
                try:
                    self.logger.info('Attempting to connect to AWS Inspector')
                    self.awsinspectorapi = \
                        AWSInspectorAPI(region_name=self.region_name,
                                  inspector_access_key=self.inspector_access_key,
                                  inspector_secret_key=self.inspector_secret_key,
                                  organization_access_key=self.organization_access_key,
                                  organization_secret_key=self.organization_secret_key,
                                  )

                    self.logger.info('Connected to AWS Inspector')

                    try:
                        # Try to connect to Elastic Search
                        self.logger.info('Attempting to connect to Elastic Search ({})'.format(self.elk_host))
                        self.awsinspectorelk = AWSInspectorELK( host=self.elk_host,
                                                                username=self.elk_username,
                                                                password=self.elk_password,
                                                                verbose=verbose,
                                                                awsinspectorapi=self.awsinspectorapi)

                        self.logger.info('Connected to Elastic Search ({})'.format(self.elk_host))

                        self.ready = True
                        self.logger.info('Module Ready')

                    except Exception as e:
                        self.logger.error('Could not connect to Elastic Search ({}): {}'.format(self.elk_host, e))

                except Exception as e:
                    self.logger.error('Could not connect to AWS Inspector: {}'.format(e))
               

            except Exception as e:
                self.logger.error('Could not properly load your config: {}'.format(e))


    # This function return the list of scan to process (scan listed by api - scan already imported)
    def get_scans_to_process(self, latest_scans):
        scans_to_process = []
        uuids = self.retrieve_uuids()

        if uuids:
            for scan in latest_scans:
                if scan['arn'] not in uuids:
                    scans_to_process.append(scan)
        else:
            scans_to_process = latest_scans

        return scans_to_process


    def whisper_awsinspector(self):
        # If module is ready
        if self.ready:
            # get scan list from inspector, avoiding already fetched scans (if failed, throw an exception)
            try:
                scans = self.get_scans_to_process(self.awsinspectorapi.get_scans())

                # if no scans are available, just exit
                if not scans:
                    if not self.daemon:
                        self.logger.warn('No new scans to process. Exiting...')
                else:
                    self.logger.info('Identified {new} scans to be processed'.format(new=len(scans)))

                    # cycle through every scan available
                    for scan in scans:

                        # Start
                        self.logger.info('Processing scan {}'.format(scan['arn']))

                        # Download findings inside the scan
                        self.logger.debug('Downloading findings...')
                        try:
                            findings = self.awsinspectorapi.get_scan_findings(scan['arn'])
                        except Exception as e:
                            self.logger.error('Findings download failed: {}'.format(e))   
                            return

                        # Check if the scan contains some findings
                        if len(findings) > 0:

                            # Cycle through every finding and create documents
                            self.logger.debug('Creating documents from {} findings'.format(len(findings)))
                            try:
                                for finding in findings:
                                    self.awsinspectorelk.add_to_queue(scan, finding)
                            except Exception as e:
                                self.logger.error('Document creation failed: {}'.format(e))   
                                return

                            # When document queue is ready, push it
                            self.logger.debug('Pushing documents...')
                            try:
                                self.awsinspectorelk.push_queue()
                                
                            except Exception as e:
                                self.logger.error('Document queue push failed: {}'.format(e))  
                                return 

                        else:
                            self.logger.warn('Scan doesn\'t contain any finding')

                        # save the scan (assessmentRun) in the scanwhisperer db
                        record_meta = (
                                        scan['name'],
                                        scan['arn'],
                                        int(time.time()),
                                        'file_name',
                                        int(time.time()),
                                        len(findings),
                                        self.CONFIG_SECTION,
                                        scan['arn'],
                                        1,
                                        0,
                                    )
                        self.record_insert(record_meta)

                        self.logger.info('Scan processed successfully')   
                    
            except Exception as e:
                self.logger.error('Could not process new scans: {}'.format(e))
            
        # Close DB connection only if not in daemon mode
        if not self.daemon:
            self.conn.close()
            self.logger.info('Module\'s job completed!')

