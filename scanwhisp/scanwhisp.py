#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from six.moves import range
from functools import reduce

__author__ = 'Austin Taylor'

from .base.config import swConfig
from .modules.nessus.nessus import scanWhispererNessus
from .whisperer.awsinspector import scanWhispererAWSInspector
from .modules.niktowrapper.niktowrapper import scanWhispererNiktoWrapper
from .modules.bitsight.bitsight import scanWhispererBitSight

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


class scanWhisperer(object):

    def __init__(self,
                 profile=None,
                 config=None,
                 verbose=None,
                 purge=False):

        self.profile = profile
        self.config = config
        self.verbose = verbose
        self.purge = purge
        self.exit_code = 0

        # set up logger
        self.logger = logging.getLogger('scanWhisperer')
        if verbose:
            self.logger.setLevel(logging.DEBUG)


    def whisper_vulnerabilities(self):

        if self.profile == 'nessus':
            sw = scanWhispererNessus(config=self.config,
                                     profile=self.profile,
                                     verbose=self.verbose,
                                     purge=self.purge)
            if sw:
                self.exit_code += sw.whisper_nessus()

        elif self.profile == 'tenableio':
            sw = scanWhispererNessus(config=self.config,
                                     profile=self.profile,
                                     verbose=self.verbose,
                                     purge=self.purge)
            if sw:
                self.exit_code += sw.whisper_nessus()

        elif self.profile == 'awsinspector':
            sw = scanWhispererAWSInspector(config=self.config,
                                           verbose=self.verbose,
                                           purge=self.purge)
            if sw:
                self.exit_code += sw.whisper_awsinspector()

        elif self.profile == 'niktowrapper':
            sw = scanWhispererNiktoWrapper(config=self.config,
                                           verbose=self.verbose)
            if sw:
                self.exit_code += sw.whisper_niktowrapper()

        elif self.profile == 'bitsight':
            sw = scanWhispererBitSight(config=self.config,
                                        verbose=self.verbose)
            if sw:
                self.exit_code += sw.whisperer_bitsight()

        return self.exit_code
