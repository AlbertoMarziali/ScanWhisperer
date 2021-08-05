#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

__author__ = 'Alberto Marziali'

from ...base.base import scanWhispererBase
from ...modules.awsinspector.awsinspectorapi import AWSInspectorAPI
from ...modules.awsinspector.awsinspectorelk import AWSInspectorELK

import time
import logging

from yaspin import yaspin


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

        self.logger.info('\nStarting AWS Inspector whisperer')

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
                    self.logger.info('Attempting to connect to AWS Inspector'.format(self.CONFIG_SECTION))
                    self.awsinspectorapi = \
                        AWSInspectorAPI(region_name=self.region_name,
                                  inspector_access_key=self.inspector_access_key,
                                  inspector_secret_key=self.inspector_secret_key,
                                  organization_access_key=self.organization_access_key,
                                  organization_secret_key=self.organization_secret_key,
                                  )

                    self.awsinspectorapi_connect = True
                    self.logger.info('Connected to {}'.format(self.CONFIG_SECTION))

                    try:
                        # Try to connect to Elastic Search
                        self.logger.info('Attempting to connect to Elastic Search ({})'.format(self.elk_host))
                        self.awsinspectorelk = AWSInspectorELK( host=self.elk_host,
                                                                username=self.elk_username,
                                                                password=self.elk_password,
                                                                verbose=verbose,
                                                                awsinspectorapi=self.awsinspectorapi)

                        self.awsinspectorelk_connect = True
                        self.logger.info('Connected to Elastic Search ({})'.format(self.elk_host))

                    except Exception as e:
                        self.logger.error('Could not connect to Elastic Search ({}): {}'.format(self.elk_host, e))

                except Exception as e:
                    self.logger.error('Could not connect to {}: {}'.format(self.CONFIG_SECTION, e))
               

            except Exception as e:
                self.logger.error('Could not properly load your config: {}'.format(e))


    # This function return the list of scan to process (scan listed by api - scan already imported)
    def get_scans_to_process(self, latest_scans):
        scans_to_process = []

        if self.uuids:
            for scan in latest_scans:
                if scan['arn'] not in self.uuids:
                    scans_to_process.append(scan)
        else:
            scans_to_process = latest_scans

        self.logger.info('Identified {} scans to be processed'.format(len(scans_to_process)))

        return scans_to_process


    def whisper_awsinspector(self):
        if self.awsinspectorapi_connect and self.awsinspectorelk_connect:
            # get scan list from inspector, avoiding already fetched scans (if failed, throw an exception)
            try:
                scans = self.get_scans_to_process(self.awsinspectorapi.scans)

                # if no scans are available, just exit
                if not scans:
                    self.logger.warn('No new scans to process. Exiting...')
                    return self.exit_code

                # cycle through every scan available
                for scan in scans:

                     # Start
                    self.logger.info('Processing AWS Inspector scan {}'.format(scan['arn']))

                    # Download findings inside the scan
                    with yaspin(text="Downloading findings", color="cyan") as spinner:
                        try:
                            findings = self.awsinspectorapi.get_scan_findings(scan['arn'])
                        except Exception as e:
                            self.logger.error('AWS Inspector findings download failed: {}'.format(e))   
                            return
                        
                        spinner.ok("✅")

                    # Check if the scan contains some findings
                    if len(findings) > 0:

                        # Cycle through every finding and create documents
                        with yaspin(text="Creating documents from {} findings".format(len(findings)), color="cyan") as spinner:
                            try:
                                for finding in findings:
                                    self.awsinspectorelk.add_to_queue(scan, finding)
                            except Exception as e:
                                self.logger.error('AWS Inspector document creation failed: {}'.format(e))   
                                return

                            spinner.ok("✅")

                        # When document queue is ready, push it
                        with yaspin(text="Pushing documents", color="cyan") as spinner:
                            try:
                                self.awsinspectorelk.push_queue()
                                
                            except Exception as e:
                                self.logger.error('AWS Inspectors document queue push failed: {}'.format(e))  
                                return 

                            spinner.ok("✅")

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

                    self.logger.info('Scan processed successfully.')   
                    
   
            except Exception as e:
                self.logger.error('Could not process new {} scans: {}'.format(self.CONFIG_SECTION, e))

            self.conn.close()
            self.logger.info('Scan aggregation completed!')
        else:
            self.logger.error('Failed to connect to {} API'.format(self.CONFIG_SECTION))
            self.exit_code += 1
        return self.exit_code

