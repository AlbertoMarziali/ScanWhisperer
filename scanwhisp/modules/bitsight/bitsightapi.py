from __future__ import absolute_import
import json
import logging
import sys
import time
from datetime import datetime

import requests
import json


class BitSightAPI(object):

    def __init__(self, verbose=False, api_key=None):
        self.logger = logging.getLogger('NiktoWrapperS3')
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        if not all((api_key)):
            raise Exception('ERROR: API key')

        self.verbose = verbose
        self.api_key = api_key

        # Token check
        res = requests.get('https://api.bitsighttech.com/ratings/v1/', params=None, auth=(self.api_key, ''))
        if res.status_code != requests.codes.ok:
            raise Exception('ERROR: Invalid token.')

        
    def get_companies(self):
        res = requests.get('https://api.bitsighttech.com/ratings/v1/companies', params=None, auth=(self.api_key, ''))
        if res.status_code != requests.codes.ok:
            raise Exception('ERROR: Request error.')
        else:
            return res.json()['companies']
            

    def get_findings(self, company, callback):
        # url for first page
        url = 'https://api.bitsighttech.com/ratings/v1/companies/{}/findings?expand=attributed_companies&grade=WARN%2CBAD&limit=200&offset=0'.format(company.get('guid'))

        # loop until url is None    
        while url:
            res = requests.get(url, params=None, auth=(self.api_key, ''))

            if res.status_code != requests.codes.ok:
                raise Exception('ERROR: Request error.')
            else:
                # loop over findings
                for finding in res.json().get('results'):
                    callback(company, finding)

                # setup new url
                url = res.json()['links']['next']
