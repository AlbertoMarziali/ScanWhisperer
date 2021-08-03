#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from six.moves import range
from functools import reduce

__author__ = 'Alberto Marziali'

from ...base.config import swConfig
from ...whisperer.base import scanWhispererBase
from ...modules.nessus.nessusapi import NessusAPI
from ...modules.nessus.nessuselk import NessusELK

import pandas as pd
from lxml import objectify
import io
import time
import logging

from yaspin import yaspin


class scanWhispererNessus(scanWhispererBase):
    CONFIG_SECTION = None

    def __init__(
            self,
            profile='nessus',
            config=None,
            db_name='report_tracker.db',
            purge=False,
            verbose=False
    ):
        self.CONFIG_SECTION = profile

        super(scanWhispererNessus, self).__init__(config=config,purge=purge)

        self.develop = True
        self.purge = purge
        self.verbose = verbose

        # set up logger
        self.logger = logging.getLogger('scanWhispererNessus')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info('Starting {} whisperer'.format(self.CONFIG_SECTION))

        # if the config is available
        if config is not None:
            try:
                # Try to read data from config file
                # Nessus/Tenable.io data
                self.nessus_hostname = self.config.get(self.CONFIG_SECTION, 'hostname')
                self.nessus_port = self.config.get(self.CONFIG_SECTION, 'port')
                self.nessus_trash = self.config.getbool(self.CONFIG_SECTION, 'trash')

                # Nessus/Tenable.io API Keys
                self.access_key = self.config.get(self.CONFIG_SECTION, 'access_key')
                self.secret_key = self.config.get(self.CONFIG_SECTION, 'secret_key')

                # Elastic Search
                self.elk_host = self.config.get(self.CONFIG_SECTION, 'elk_host')
                self.elk_username = self.config.get(self.CONFIG_SECTION, 'elk_username')
                self.elk_password = self.config.get(self.CONFIG_SECTION, 'elk_password')

                try:
                    # Try to connect to Nessus
                    self.logger.info('Attempting to connect to {}...'.format(self.CONFIG_SECTION))
                    self.nessusapi = \
                        NessusAPI( profile=self.CONFIG_SECTION,
                                   hostname=self.nessus_hostname,
                                   port=self.nessus_port,
                                   access_key=self.access_key,
                                   secret_key=self.secret_key
                                  )
                    self.nessusapi_connect = True
                    self.logger.info('Connected to {} on {host}:{port}'.format(self.CONFIG_SECTION, host=self.nessus_hostname,port=str(self.nessus_port)))

                    try:
                        # Try to connect to Elastic Search
                        self.logger.info('Attempting to connect to Elastic Search ({})'.format(self.elk_host))
                        self.nessuselk = \
                            NessusELK( profile=self.CONFIG_SECTION,
                                    host=self.elk_host,
                                    username=self.elk_username,
                                    password=self.elk_password,
                                    verbose=verbose
                                    )
                        self.nessuselk_connect = True
                        self.logger.info('Connected to Elastic Search ({})'.format(self.elk_host))

                    except Exception as e:
                        self.logger.error('Could not connect to Elastic Search ({}): {}'.format(self.elk_host, e))

                except Exception as e:
                    self.logger.error('Could not connect to {}: {}'.format(self.CONFIG_SECTION, e))

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
                    for h in self.nessusapi.get_scan_history(s['id']):
                        record['uuid'] = h.get('uuid', '')
                        record['status'] = h.get('status', '')
                        record['history_id'] = h.get('history_id', '')
                        record['last_modification_date'] = h.get('last_modification_date', '')
                        record['norm_time'] = self.nessusapi.get_utc_from_local(int(record['last_modification_date']), local_tz=record['timezone'])
                    
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


    def whisper_nessus(self):
        if self.nessusapi_connect and self.nessuselk_connect:
            # get scan list from nessus/tenableio, avoiding already fetched scans (if failed, throw an exception)
            try:
                scan_list = self.get_scans_to_process(self.nessusapi.scans['scans'])

                # if no scans are available, just exit
                if not scan_list:
                    self.logger.warn('No new scans to process. Exiting...')
                    return self.exit_code

                # for each scan to process, download csv report and export to Elastic Search
                for scan in scan_list:
                    
                    # Try to request scan report
                    try:
                        # Start
                        self.logger.info('Processing {} scan {}, (history {})'.format(self.CONFIG_SECTION, scan['scan_id'], scan['history_id']))

                        # Download the scan report and import inside a DataFrame
                        with yaspin(text="Downloading findings", color="cyan") as spinner:
                            report_req = self.nessusapi.download_scan(scan_id=scan['scan_id'], history=scan['history_id'], export_format='csv')
                            report_csv = pd.read_csv(io.StringIO(report_req), na_filter=False)
                            spinner.ok("✅")

                        # ONLY FOR NESSUS: Add Host info
                        if len(report_csv) > 0 and self.CONFIG_SECTION == 'nessus':
                            
                            with yaspin(text="Fetching host info", color="cyan") as spinner:
                                host_list = self.nessusapi.get_scan_hosts(scan_id=scan['scan_id'], history_id=scan['history_id'])

                                # Edit the dataframe to add host info
                                report_csv['IP Address'] = report_csv.apply (lambda row: host_list.get(row['Host'], {}).get('host-ip', ''), axis=1) 
                                report_csv['FQDN'] = report_csv.apply (lambda row: host_list.get(row['Host'], {}).get('host-fqdn', ''), axis=1) 
                                report_csv['NetBios'] = report_csv.apply (lambda row: host_list.get(row['Host'], {}).get('netbios-name', ''), axis=1) 
                                report_csv['OS'] = report_csv.apply (lambda row: host_list.get(row['Host'], {}).get('operating-system', ''), axis=1) 
                                report_csv['Mac Address'] = report_csv.apply (lambda row: host_list.get(row['Host'], {}).get('mac-address', ''), axis=1) 

                                self.logger.debug('Added host info for {} hosts'.format(len(host_list)))
                                spinner.ok("✅")

                        # Iterate over report lines and creates documents
                        with yaspin(text='Creating documents for {} {} findings.'.format(report_csv.shape[0], self.CONFIG_SECTION), color="cyan") as spinner:

                            try:
                                for index, finding in report_csv.iterrows():
                                    # Add document from finding
                                    self.nessuselk.add_to_queue(scan, finding)

                            except Exception as e:
                                self.logger.error('{} document creation error: {}'.format(self.CONFIG_SECTION, e))   

                            spinner.ok("✅")

                        # When document queue is ready, push it
                        with yaspin(text="Pushing documents", color="cyan") as spinner:
                            try:
                                self.nessuselk.push_queue()
                                
                            except Exception as e:
                                self.logger.error('{} document queue push error: {}'.format(self.CONFIG_SECTION, e))   

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
                        self.logger.error('Could not download {} scan {}: {}'.format(self.CONFIG_SECTION, scan['scan_id'], e))

            except Exception as e:
                self.logger.error('Could not process new {} scans: {}'.format(self.CONFIG_SECTION, e))
                            
            self.conn.close()
            self.logger.info('Scan aggregation completed!')
        else:
            self.logger.error('Failed to connect to {} API at {}:{}'.format(self.CONFIG_SECTION, self.nessus_hostname, self.nessus_port))
            self.exit_code += 1
        return self.exit_code

