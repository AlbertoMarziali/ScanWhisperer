#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

__author__ = 'Alberto Marziali'

from ...base.base import scanWhispererBase
from ...modules.tenableio.tenableioapi import TenableioAPI
from ...modules.tenableio.tenableioelk import TenableioELK

import pandas as pd
import io
import time
import logging

from yaspin import yaspin


class scanWhispererTenableio(scanWhispererBase):
    CONFIG_SECTION = None

    def __init__(
            self,
            profile='tenableio',
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=False
    ):
        self.CONFIG_SECTION = profile

        super(scanWhispererTenableio, self).__init__(config=config,purge=purge)

        self.develop = True
        self.purge = purge
        self.verbose = verbose

        # set up logger
        self.logger = logging.getLogger('scanWhispererTenableio')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('Starting Tenable.io whisperer')

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
                    self.logger.info('Attempting to connect to Tenable.io...')
                    self.tenableioapi = \
                        TenableioAPI(   access_key=self.access_key,
                                        secret_key=self.secret_key,
                                        verbose=verbose
                                  )
                    self.tenableioapi_connect = True
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
                        self.tenableioelk_connect = True
                        self.logger.info('Connected to Elastic Search ({})'.format(self.elk_host))

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
        if self.uuids:
            scans_to_process = [scan for scan in scans_to_process if scan['uuid'] not in self.uuids]

        self.logger.info('Identified {new} scans to be processed'.format(new=len(scans_to_process)))

        return scans_to_process


    def whisper_tenableio(self):
        if self.tenableioapi_connect and self.tenableioelk_connect:
            # get scan list from tenableio/tenableio, avoiding already fetched scans (if failed, throw an exception)
            try:
                scan_list = self.get_scans_to_process(self.tenableioapi.scans['scans'])

                # if no scans are available, just exit
                if not scan_list:
                    self.logger.warn('No new scans to process. Exiting...')
                    return self.exit_code

                # for each scan to process, download csv report and export to Elastic Search
                for scan in scan_list:
                    
                    # Start
                    self.logger.info('Processing Tenable.io scan {}, (history {})'.format(scan['scan_id'], scan['history_id']))

                    # Download the scan report and import inside a DataFrame
                    with yaspin(text="Downloading findings", color="cyan") as spinner:
                        try:
                            report_req = self.tenableioapi.download_scan(scan_id=scan['scan_id'], history=scan['history_id'], export_format='csv')
                            report_csv = pd.read_csv(io.StringIO(report_req), na_filter=False)
                        except Exception as e:
                            self.logger.error('Tenable.io findings download failed: {}'.format(e))  
                            return
                        
                        spinner.ok("✅")

                    # Iterate over report lines and creates documents
                    with yaspin(text='Creating documents for {} Tenable.io findings.'.format(report_csv.shape[0]), color="cyan") as spinner:
                        try:
                            for index, finding in report_csv.iterrows():
                                # Add document from finding
                                self.tenableioelk.add_to_queue(scan, finding)

                        except Exception as e:
                            self.logger.error('Tenable.io document creation failed: {}'.format(e))   
                            return

                        spinner.ok("✅")

                    # When document queue is ready, push it
                    with yaspin(text="Pushing documents", color="cyan") as spinner:
                        try:
                            self.tenableioelk.push_queue()
                            
                        except Exception as e:
                            self.logger.error('Tenable.io document queue push failed: {}'.format(e))  
                            return 

                        spinner.ok("✅")

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

                    self.logger.info('Scan processed successfully.')   

            except Exception as e:
                self.logger.error('Could not process new Tenable.io scans: {}'.format(e))
                            
            self.conn.close()
            self.logger.info('Scan aggregation completed!')
        else:
            self.logger.error('Failed to connect to Tenable.io API')
            self.exit_code += 1
        return self.exit_code

