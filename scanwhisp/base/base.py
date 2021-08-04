#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from functools import reduce

__author__ = 'Austin Taylor'

from ..base.config import swConfig
import sys
import os
import sqlite3
import logging


class scanWhispererBase(object):
    CONFIG_SECTION = None

    def __init__(
            self,
            config=None,
            db_name='report_tracker.db',           
            section=None,
            purge=False,
            verbose=False
    ):

        if self.CONFIG_SECTION is None:
            raise Exception('Implementing class must define CONFIG_SECTION')

        self.exit_code = 0
        self.db_name = db_name
        self.purge = purge

        # set up logger
        self.logger = logging.getLogger('scanWhispererBase')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        # if the config is available
        if config is not None:
            self.config = swConfig(config_in=config)
            try:
                self.enabled = self.config.get(self.CONFIG_SECTION, 'enabled')
            except:
                self.enabled = False

            self.db_path = self.config.get(self.CONFIG_SECTION, 'db_path')

        if self.db_name is not None:
            if self.db_path:
                self.database = os.path.join(self.db_path,
                                             db_name)
            else:
                self.database = \
                    os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 'database', db_name))
            if not os.path.exists(self.db_path):
                os.makedirs(self.db_path)
                self.logger.info('Creating directory {dir}'.format(dir=self.db_path))

            if not os.path.exists(self.database):
                with open(self.database, 'w'):
                    self.logger.info('Creating file {dir}'.format(dir=self.database))

            try:
                self.conn = sqlite3.connect(self.database)
                self.cur = self.conn.cursor()
                self.logger.info('Connected to database at {loc}'.format(loc=self.database))
            except Exception as e:
                self.logger.error(
                    'Could not connect to database at {loc}\nReason: {e} - Please ensure the path exist'.format(
                        e=e,
                        loc=self.database))
        else:

            self.logger.error('Please specify a database to connect to!')
            exit(1)

        self.table_columns = [
            'scan_name',
            'scan_id',
            'last_modified',
            'filename',
            'download_time',
            'record_count',
            'source',
            'uuid',
            'processed',
            'reported',
        ]

        self.init()
        self.uuids = self.retrieve_uuids()
        self.processed = 0
        self.skipped = 0
        self.scan_list = []

    def create_table(self):
        self.cur.execute(
            'CREATE TABLE IF NOT EXISTS scan_history (id INTEGER PRIMARY KEY,'
            ' scan_name TEXT, scan_id INTEGER, last_modified DATE, filename TEXT,'
            ' download_time DATE, record_count INTEGER, source TEXT,'
            ' uuid TEXT, processed INTEGER, reported INTEGER)'
        )
        self.conn.commit()

    def delete_table(self):
        self.cur.execute('DELETE FROM scan_history WHERE source=\'{}\''.format(self.CONFIG_SECTION))
        self.conn.commit()

    def init(self):
        if self.purge:
            self.logger.info('Requested purge of {} data.'.format(self.CONFIG_SECTION))
            self.delete_table()
        self.create_table()

    def cleanser(self, _data):
        repls = (('\n', r'\n'), ('\r', r'\r'))
        data = reduce(lambda a, kv: a.replace(*kv), repls, _data)
        return data

    def record_insert(self, record):
        # for backwards compatibility with older versions without "reported" field

        try:
            # -1 to get the latest column, 1 to get the column name (old version would be "processed", new "reported")
            # TODO delete backward compatibility check after some versions
            last_column_table = self.cur.execute('PRAGMA table_info(scan_history)').fetchall()[-1][1]
            if last_column_table == self.table_columns[-1]:
                self.cur.execute('insert into scan_history({table_columns}) values (?,?,?,?,?,?,?,?,?,?)'.format(
                    table_columns=', '.join(self.table_columns)), record)

            else:
                self.cur.execute('insert into scan_history({table_columns}) values (?,?,?,?,?,?,?,?,?)'.format(
                    table_columns=', '.join(self.table_columns[:-1])), record[:-1])
            self.conn.commit()
        except Exception as e:
            self.logger.error("Failed to insert record in database. Error: {}".format(e))
            sys.exit(1)

    def retrieve_uuids(self):
        """
        Retrieves UUIDs from database and checks list to determine which files need to be processed.
        :return:
        """
        try:
            self.conn.text_factory = str
            self.cur.execute('SELECT uuid FROM scan_history where source = "{config_section}"'.format(
                config_section=self.CONFIG_SECTION))
            results = frozenset([r[0] for r in self.cur.fetchall()])
        except:
            results = []
        return results
