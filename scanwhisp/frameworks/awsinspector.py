from __future__ import absolute_import
import json
import logging
import sys
import time
from datetime import datetime

import boto3 #AWS Python SDK


class AWSInspectorAPI(object):

    def __init__(self, verbose=False, region_name=None, access_key=None, secret_key=None):
        self.logger = logging.getLogger('AWSInspectorAPI')
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        if not all((region_name, access_key, secret_key)):
            raise Exception('ERROR: Region or API keys.')

        self.verbose = verbose

        self.inspector = boto3.client(
            'inspector',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name = region_name
        )

        self.scans = self.get_scans()
        self.scan_ids = self.get_scan_arns()


    def get_scans(self):
        scans = []
        paginator = self.inspector.get_paginator('list_assessment_runs')

        for assArns in paginator.paginate(
            filter={
                'states': [
                    'COMPLETED',
                ],
            },
        ):
            if assArns['assessmentRunArns']:
                response = self.inspector.describe_assessment_runs(
                    assessmentRunArns = assArns['assessmentRunArns']
                )
                scans.extend(response['assessmentRuns'])

        return scans


    def get_scan_arns(self):
        scans = self.scans
        scan_arns = [scan_arn['arn'] for scan_arn in scans] if scans else []
        return scan_arns


    def get_scan_findings(self, scan_arn=None):
        
        paginator = self.inspector.get_paginator('list_findings')
        results = []

        for findings in paginator.paginate(
                assessmentRunArns=[
                    scan_arn,
                ],
                filter = {

                }
            ):

            if findings['findingArns']:
                response_d = self.inspector.describe_findings(
                    findingArns=findings['findingArns'],
                )
                results.extend(response_d['findings'])

        return results
