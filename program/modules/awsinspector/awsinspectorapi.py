from __future__ import absolute_import

__author__ = 'Alberto Marziali'

import logging

import boto3 #AWS Python SDK


class AWSInspectorAPI(object):

    def __init__(self, 
                verbose=False, 
                region_name=None, 
                inspector_access_key=None, 
                inspector_secret_key=None, 
                organization_access_key=None, 
                organization_secret_key=None):
        self.logger = logging.getLogger('AWSInspectorAPI')
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        if not all((region_name, inspector_access_key, inspector_secret_key, organization_access_key, organization_secret_key)):
            raise Exception('ERROR: Region or API keys.')

        self.verbose = verbose
                
        # setup cache dict for rule packages names
        self.rulepackagecache = {}

        # setup inspector client
        self.inspector = boto3.client(
            'inspector',
            aws_access_key_id=inspector_access_key,
            aws_secret_access_key=inspector_secret_key,
            region_name = region_name
        )

        # setup organizations client
        self.organization = boto3.client('organizations',
            aws_access_key_id=organization_access_key,
            aws_secret_access_key=organization_secret_key,
            region_name = region_name
        )

        # check inspector connectivity by running a dry get scan
        self.get_scans()

        # prepare account list
        self.aws_accounts = self.get_accounts() 


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


    def get_scan_findings(self, scan_arn):
        
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


    def get_rule_name(self, rule_arn):
        ret = ''
        # try to find the rule_arn inside local cache
        if self.rulepackagecache.get(rule_arn):
            ret = self.rulepackagecache.get(rule_arn)
        else:
            # if never cached, fetch rule name via API
            try:
                response = self.inspector.describe_rules_packages(
                    rulesPackageArns=[
                        rule_arn,
                    ]
                )

                ret = response['rulesPackages'][0]['name']
            except Exception as e:
                ret = 'Unknown'
                print(e)

            # save in cache, even if failed
            self.rulepackagecache[rule_arn] = ret
        
        return ret

    
    def get_accounts(self):
        accounts = {}

        # get account list via API
        paginator = self.organization.get_paginator('list_accounts')

        # loop through responses
        for response in paginator.paginate():
            if response.get('Accounts'):
                # take account list from result
                for account in response.get('Accounts'):
                    accounts[account.get('Id')] = account.get('Name')
        
        return accounts
