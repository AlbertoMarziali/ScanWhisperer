#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

__author__ = 'Alberto Marziali'

from base.base import scanWhispererBase
from modules.tenableio.tenableioapi import TenableioAPI
from modules.tenableio.tenableioelk import TenableioELK

import pandas as pd
import io
import time
import logging


class scanWhispererTenableio(scanWhispererBase):
    CONFIG_SECTION = None

    def __init__(
            self,
            profile='tenableio',
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=False,
            daemon=False
    ):
        self.CONFIG_SECTION = profile

        super(scanWhispererTenableio, self).__init__(config=config,purge=purge)

        self.purge = purge
        self.verbose = verbose
        self.daemon = daemon
        self.ready = False

        # set up logger
        self.logger = logging.getLogger('scanWhispererTenableio')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('Starting Module')

        # if the config is available
        if config is not None:
            try:
                # Try to read data from config file
                # Tenable.io data
                self.tenableio_trash = self.config.getbool(self.CONFIG_SECTION, 'trash')

                # Tenable.io API Keys
                self.access_key = self.config.get(self.CONFIG_SECTION, 'access_key')
                self.secret_key = self.config.get(self.CONFIG_SECTION, 'secret_key')

                # Elastic Search
                self.elk_host = self.config.get(self.CONFIG_SECTION, 'elk_host')
                self.elk_username = self.config.get(self.CONFIG_SECTION, 'elk_username')
                self.elk_password = self.config.get(self.CONFIG_SECTION, 'elk_password')

                try:
                    # Try to connect to Tenableio
                    self.logger.info('Attempting to connect to Tenable.io')
                    self.tenableioapi = \
                        TenableioAPI(   access_key=self.access_key,
                                        secret_key=self.secret_key,
                                        verbose=verbose
                                  )
                    self.logger.info('Connected to Tenable.io')

                    try:
                        # Try to connect to Elastic Search
                        self.logger.info('Attempting to connect to Elastic Search ({})'.format(self.elk_host))
                        self.tenableioelk = \
                            TenableioELK(   host=self.elk_host,
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
                    self.logger.error('Could not connect to Tenable.io: {}'.format(e))

            except Exception as e:
                self.logger.error('Could not properly load your config: {}'.format(e))

    
    # This function returns a list of scans to process (each scan is combined with history)
    def get_scans_to_process(self, scans):

        scans_to_process = []
        for s in scans:
            if s:
                record = {}
                record['scan_id'] = s['id']
                record['scan_name'] = s.get('name', '')
                record['owner'] = s.get('owner', '')
                record['creation_date'] = s.get('creation_date', '')
                record['starttime'] = s.get('starttime', '')
                record['timezone'] = s.get('timezone', '')
                record['folder_id'] = s.get('folder_id', '')
                try:
                    for h in self.tenableioapi.get_scan_history(s['id']):
                        record['uuid'] = h.get('uuid', '')
                        record['status'] = h.get('status', '')
                        record['history_id'] = h.get('history_id', '')
                        record['last_modification_date'] = h.get('last_modification_date', '')
                        record['norm_time'] = self.tenableioapi.get_utc_from_local(int(record['last_modification_date']), local_tz=record['timezone'])
                    
                        scans_to_process.append(record.copy())
                except:
                    pass

        # Exclude uncomplete scans
        scans_to_process = [scan for scan in scans_to_process if scan['status'] in ['completed', 'imported']]

        # Exclude already processed scans
        uuids = self.retrieve_uuids()
        if uuids:
            scans_to_process = [scan for scan in scans_to_process if scan['uuid'] not in uuids]


        return scans_to_process


    def whisper_tenableio(self):
        # If module is ready
        if self.ready:
            # get scan list from tenableio/tenableio, avoiding already fetched scans (if failed, throw an exception)
            try:
                scan_list = self.get_scans_to_process(self.tenableioapi.get_scans().get('scans', []))

                # if no scans are available, just exit
                if not scan_list:
                    if not self.daemon:
                        self.logger.warn('No new scans to process. Exiting...')
                else:
                    self.logger.info('Identified {new} scans to be processed'.format(new=len(scan_list)))

                    # for each scan to process, download csv report and export to Elastic Search
                    for scan in scan_list:
                        
                        # Start
                        self.logger.info('Processing scan {}, (history {})'.format(scan['scan_id'], scan['history_id']))

                        # Download the scan report and import inside a DataFrame
                        self.logger.debug('Downloading findings...')
                        try:
                            report_req = self.tenableioapi.download_scan(scan_id=scan['scan_id'], history=scan['history_id'], export_format='csv')
                            report_csv = pd.read_csv(io.StringIO(report_req), na_filter=False)
                        except Exception as e:
                            self.logger.error('Findings download failed: {}'.format(e))  
                            return

                        # Check if the scan contains some findings
                        if len(report_csv) > 0:

                            # Clear the document queue (avoid memory leak)
                            self.tenableioelk.clear_queue()

                            # Iterate over report lines and creates documents
                            self.logger.debug('Creating documents from {} findings...'.format(report_csv.shape[0]))
                            try:
                                for index, finding in report_csv.iterrows():
                                    # Add document from finding
                                    self.tenableioelk.add_to_queue(scan, finding)

                            except Exception as e:
                                self.logger.error('Document creation failed: {}'.format(e))   
                                return

                            # When document queue is ready, push it
                            self.logger.debug('Pushing documents...')
                            try:
                                self.tenableioelk.push_queue()
                                
                            except Exception as e:
                                self.logger.error('Document queue push failed: {}'.format(e))  
                                return 

                        else:
                            self.logger.warn('Scan doesn\'t contain any finding')

                        # Save the scan in ScanWhisperer DB
                        record_meta = (
                                scan['scan_name'],
                                scan['scan_id'],
                                scan['norm_time'],
                                'file_name',
                                time.time(),
                                report_csv.shape[0],
                                self.CONFIG_SECTION,
                                scan['uuid'],
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

