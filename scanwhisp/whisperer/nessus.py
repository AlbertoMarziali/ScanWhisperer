#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from six.moves import range
from functools import reduce

__author__ = 'Austin Taylor'

from ..base.config import swConfig
from .base import scanWhispererBase
from ..frameworks.nessus import NessusAPI

import pandas as pd
from lxml import objectify
import sys
import os
import io
import time
import sqlite3
import json
import logging
import socket
from datetime import datetime

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
                # Try to fetch data from config file
                self.nessus_hostname = self.config.get(self.CONFIG_SECTION, 'hostname')
                self.nessus_port = self.config.get(self.CONFIG_SECTION, 'port')
                self.nessus_trash = self.config.getbool(self.CONFIG_SECTION, 'trash')

                # Try to fetch the API keys from config file
                self.access_key = self.config.get(self.CONFIG_SECTION, 'access_key')
                self.secret_key = self.config.get(self.CONFIG_SECTION, 'secret_key')

                try:
                    # Try to connect to Nessus
                    self.logger.info('Attempting to connect to {}...'.format(self.CONFIG_SECTION))
                    self.nessus = \
                        NessusAPI( profile=self.CONFIG_SECTION,
                                   hostname=self.nessus_hostname,
                                   port=self.nessus_port,
                                   access_key=self.access_key,
                                   secret_key=self.secret_key
                                  )
                    self.nessus_connect = True
                    self.logger.info('Connected to {} on {host}:{port}'.format(self.CONFIG_SECTION, host=self.nessus_hostname,
                                                                               port=str(self.nessus_port)))
                except Exception as e:
                    self.logger.error('Could not connect to {}: {}'.format(self.CONFIG_SECTION, e))

            except Exception as e:
                self.logger.error('Could not properly load your config: {}'.format(e))


    def scan_count(self, scans, completed=False):
        """

        :param scans: Pulls in available scans
        :param completed: Only return completed scans
        :return:
        """

        self.logger.info('Gathering all scan data... this may take a while...')
        scan_records = []
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
                    for h in self.nessus.get_scan_history(s['id']):
                        record['uuid'] = h.get('uuid', '')
                        record['status'] = h.get('status', '')
                        record['history_id'] = h.get('history_id', '')
                        record['last_modification_date'] = \
                            h.get('last_modification_date', '')
                        record['norm_time'] = \
                            self.nessus.get_utc_from_local(int(record['last_modification_date'
                                                               ]),
                                                           local_tz=self.nessus.tz_conv(record['timezone'
                                                                                        ]))
                        scan_records.append(record.copy())
                except:
                    # Generates error each time nonetype is encountered.
                    pass

        if completed:
            scan_records = [s for s in scan_records if s['status'] == 'completed']
        return scan_records

    def whisper_nessus(self):
        if self.nessus_connect:
            scan_data = self.nessus.scans
            folders = scan_data['folders']
            scans = scan_data['scans'] if scan_data['scans'] else []
            all_scans = self.scan_count(scans)
            if self.uuids:
                scan_list = [scan for scan in all_scans if scan['uuid']
                             not in self.uuids and scan['status'] in ['completed', 'imported']]
            else:
                scan_list = all_scans
            self.logger.info('Identified {new} scans to be processed'.format(new=len(scan_list)))

            if not scan_list:
                self.logger.warn('No new scans to process. Exiting...')
                return self.exit_code

            # Create scan subfolders

            for f in folders:
                if not os.path.exists(self.path_check(f['name'])):
                    if f['name'] == 'Trash' and self.nessus_trash:
                        os.makedirs(self.path_check(f['name']))
                    elif f['name'] != 'Trash':
                        os.makedirs(self.path_check(f['name']))
                else:
                    os.path.exists(self.path_check(f['name']))
                    self.logger.info('Directory already exist for {scan} - Skipping creation'.format(
                        scan=self.path_check(f['name'])))

            # try download and save scans into each folder the belong to

            scan_count = 0

            # TODO Rewrite this part to go through the scans that have aleady been processed

            for s in scan_list:
                scan_count += 1
                (
                    scan_name,
                    scan_id,
                    history_id,
                    norm_time,
                    status,
                    uuid,
                ) = (
                    s['scan_name'],
                    s['scan_id'],
                    s['history_id'],
                    s['norm_time'],
                    s['status'],
                    s['uuid'],
                )

                # TODO Create directory sync function which scans the directory for files that exist already and
                #  populates the database

                folder_id = s['folder_id']
                if self.CONFIG_SECTION == 'tenableio':
                    folder_name = ''
                else:
                    folder_name = next(f['name'] for f in folders if f['id'] == folder_id)
                if status in ['completed', 'imported']:
                    file_name = '%s_%s_%s_%s.%s' % (scan_name, scan_id,
                                                    history_id, norm_time, 'csv')
                    repls = (('\\', '_'), ('/', '_'), (' ', '_'))
                    file_name = reduce(lambda a, kv: a.replace(*kv), repls, file_name)
                    relative_path_name = self.path_check(folder_name + '/' + file_name)

                    if os.path.isfile(relative_path_name):
                        if self.develop:
                            csv_in = pd.read_csv(relative_path_name)
                            record_meta = (
                                scan_name,
                                scan_id,
                                norm_time,
                                file_name,
                                time.time(),
                                csv_in.shape[0],
                                self.CONFIG_SECTION,
                                uuid,
                                1,
                                0,
                            )
                            self.record_insert(record_meta)
                            self.logger.info(
                                'File {filename} already exist! Updating database'.format(filename=relative_path_name))
                    else:
                        try:
                            file_req = \
                                self.nessus.download_scan(scan_id=scan_id, history=history_id,
                                                          export_format='csv')
                        except Exception as e:
                            self.logger.error(
                                'Could not download {} scan {}: {}'.format(self.CONFIG_SECTION, scan_id, str(e)))
                            self.exit_code += 1
                            continue

                        clean_csv = \
                            pd.read_csv(io.StringIO(file_req))
                        if len(clean_csv) > 2:
                            self.logger.info('Processing {}/{} for scan: {}'.format(scan_count, len(scan_list),
                                                                                    scan_name))
                            columns_to_cleanse = ['CVSS', 'CVE', 'Description', 'Synopsis', 'Solution', 'See Also',
                                                  'Plugin Output', 'MAC Address']

                            for col in columns_to_cleanse:
                                if col in clean_csv:
                                    clean_csv[col] = clean_csv[col].astype(str).apply(self.cleanser)

                            clean_csv.to_csv(relative_path_name, index=False)
                            record_meta = (
                                scan_name,
                                scan_id,
                                norm_time,
                                file_name,
                                time.time(),
                                clean_csv.shape[0],
                                self.CONFIG_SECTION,
                                uuid,
                                1,
                                0,
                            )
                            self.record_insert(record_meta)
                            self.logger.info('{filename} records written to {path} '.format(filename=clean_csv.shape[0],
                                                                                            path=file_name))
                        else:
                            record_meta = (
                                scan_name,
                                scan_id,
                                norm_time,
                                file_name,
                                time.time(),
                                clean_csv.shape[0],
                                self.CONFIG_SECTION,
                                uuid,
                                1,
                                0,
                            )
                            self.record_insert(record_meta)
                            self.logger.warn(
                                '{} has no host available... Updating database and skipping!'.format(file_name))
            self.conn.close()
            self.logger.info('Scan aggregation complete! Connection to database closed.')
        else:
            self.logger.error(
                'Failed to use scanner at {host}:{port}'.format(host=self.nessus_hostname, port=self.nessus_port))
            self.exit_code += 1
        return self.exit_code

