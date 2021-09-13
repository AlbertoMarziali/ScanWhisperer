from __future__ import absolute_import

__author__ = 'Alberto Marziali'

import logging
from datetime import datetime

import hashlib
from elasticsearch import Elasticsearch

import re

import warnings
warnings.filterwarnings("ignore")


class AWSInspectorELK(object):

    def __init__(self, verbose = False, username = None, password = None, host = None, awsinspectorapi = None):
        self.logger = logging.getLogger('AWSInspectorELK')
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.username = username
        self.password = password
        self.host = host
        self.awsinspectorapi = awsinspectorapi

        # Connect to Elastic Search
        logging.getLogger('elasticsearch').setLevel(logging.CRITICAL)
        self.elastic_client = Elasticsearch('https://{}:{}@{}'.format(self.username, self.password, self.host), ca_certs=False, verify_certs=False)
        
        # Check connection
        self.elastic_client.info()

        # Document queue
        self.document_queue = {}


    # This function adds field to document
    def add_field_to_document(self, document, field, content):
        if content:
            if isinstance(content, str):
                content = content.strip()

            document.update({ field : content })


    # This function creates a single document
    def create_document(self, scan, finding):
        # assemble document
        document = {}

        # ---- AWS Inspector specific part ----
        # This fields are exclusive to AWS Inspector
        self.add_field_to_document(document, 'awsinspector.scan.arn', scan['arn'])
        self.add_field_to_document(document, 'awsinspector.scan.name', scan.get('name')) 
        self.add_field_to_document(document, 'awsinspector.rules_package.arn', finding.get('serviceAttributes', {}).get('rulesPackageArn'))
        self.add_field_to_document(document, 'awsinspector.rules_package.name', self.awsinspectorapi.get_rule_name(finding.get('serviceAttributes').get('rulesPackageArn')))
        self.add_field_to_document(document, 'awsinspector.finding.arn', finding['arn'])
        self.add_field_to_document(document, 'awsinspector.aws_account.id', next((item for item in re.findall(r'^arn:aws:inspector:.*:([0-9]*):.*$', finding['arn'])), None))
        self.add_field_to_document(document, 'awsinspector.aws_account.name', self.awsinspectorapi.aws_accounts.get(document.get('awsinspector.aws_account.id', '')))
        self.add_field_to_document(document, 'awsinspector.tag', next((item.get('value') for item in finding['assetAttributes']['tags'] if item.get('key') == 'Name'), ''))

        # ---- Asset part ----
        # Scan target (asset) properties
        self.add_field_to_document(document, 'asset.host', finding['assetAttributes']['agentId'])
        self.add_field_to_document(document, 'asset.ip', next((item.get('publicIp') for item in finding['assetAttributes']['networkInterfaces'] if item.get('publicIp') != ''), None))

        # ---- CVE part ----
        # extract CVE related fields (if present)
        self.add_field_to_document(document, 'cve.id', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'CVE_ID'), None))
        self.add_field_to_document(document, 'cve.cvss3.score', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'CVSS3_SCORE'), None))
        self.add_field_to_document(document, 'cve.cvss2.score', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'CVSS2_SCORE'), None))
        self.add_field_to_document(document, 'cve.package_name', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'package_name'), None))

        # ---- CIS Part ----
        # extract CIS related fields (if present)
        self.add_field_to_document(document, 'cis.control', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'BENCHMARK_RULE_ID'), None))
        self.add_field_to_document(document, 'cis.benchmark', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'BENCHMARK_ID'), None))
        self.add_field_to_document(document, 'cis.level', next((item.get('value') for item in finding['attributes'] if item.get('key') == 'CIS_BENCHMARK_PROFILE'), None))
        
        # ---- Finding metadata part ----
        # extract Finding metadata 
        self.add_field_to_document(document, 'finding.title', finding.get('title'))
        self.add_field_to_document(document, 'finding.description', finding.get('description'))
        self.add_field_to_document(document, 'finding.solution', finding.get('recommendation'))
        self.add_field_to_document(document, 'finding.source', 'awsinspector')
        self.add_field_to_document(document, 'finding.first_observed', finding.get('updatedAt', datetime.utcnow()).isoformat())
        self.add_field_to_document(document, 'finding.last_observed', finding.get('updatedAt', datetime.utcnow()).isoformat())
        # guess finding type by existing fields
        if document.get('cve.cvss.score'):
            self.add_field_to_document(document, 'finding.type', 'cve')
        elif document.get('cis.benchmark'):
            self.add_field_to_document(document, 'finding.type', 'cis')
        else:
            self.add_field_to_document(document, 'finding.type', 'other')
        # calculate finding risk
        if document.get('cve.cvss2.score'):
            # Calculate risk based off cvss2 score
            try:
                if(float(document.get('cve.cvss2.score')) == 0):
                    self.add_field_to_document(document, 'finding.risk', 'Info')
                elif (float(document.get('cve.cvss2.score')) <= 3.9):
                    self.add_field_to_document(document, 'finding.risk', 'Low')
                elif (float(document.get('cve.cvss2.score')) <= 6.9):
                    self.add_field_to_document(document, 'finding.risk', 'Medium')
                elif (float(document.get('cve.cvss2.score')) <= 9.9):
                    self.add_field_to_document(document, 'finding.risk', 'High')
                elif (float(document.get('cve.cvss2.score')) == 10):
                    self.add_field_to_document(document, 'finding.risk', 'Critical')        
            except ValueError:  
                print ("Not a float")
        else:
            # Use AWS Inspector severity as Risk
            self.add_field_to_document(document, 'finding.risk', finding.get('severity'))

        
        return document


    # This function adds the document to the queue. If already there, it applies some changes to CVE field
    def add_to_queue(self, scan, finding):

        # Create Document
        document = self.create_document(scan, finding)

        # Generate id 
        document_id = hashlib.sha1(('{}{}'.format(document.get('asset.host'), document.get('finding.title'))).encode('utf-8')).hexdigest()

        # Add (or replace) document to the queue
        self.document_queue.update({ document_id : document })


    # Push documents to Elastic Search
    def push_queue(self):

        self.logger.debug('Pushing {} awsinspector documents'.format(len(self.document_queue)))

        # Iterate over document queue
        for document_id, document in self.document_queue.items():
            
            # Create index on Elastic Search
            try:
                # create index if needed
                mapping = {
                    "mappings": {
                        "properties": {
                            "cve.cvss2.score": {
                                "type": "float" 
                            },
                            "cve.cvss3.score": {
                                "type": "float" 
                            },
                            "asset.ip": {
                                "type": "ip" 
                            }
                        }
                    }
                }
                self.elastic_client.indices.create(index='scanwhisperer-{}-awsinspector'.format(document.get('finding.type')),body=mapping, ignore=400)

            except Exception as e:
                self.logger.error('Failed create index scanwhisperer-{}-awsinspector on Elastic Search: {}'.format(document.get('finding.type'), e)) 
            
            # Query Elastic Search to fetch a document with the same ID
            # If found,overwrite new first_observed with older to avoid updating it
            try:
                # Fetch document
                elk_response = self.elastic_client.search(index='scanwhisperer-{}-awsinspector'.format(document.get('finding.type')), body={
                    "query": {
                        "match": {
                            "_id": document_id
                        }
                    }
                })

                # If document was found, apply older first observed
                if elk_response.get('hits').get('total').get('value') == 1:
                    # Maintain old first observed
                    document['finding.first_observed'] = elk_response.get('hits').get('hits')[0].get('_source').get('finding.first_observed')

            except Exception as e:
                self.logger.error('Failed to get document from Elastic Search: {}'.format(e)) 

            # Push report to Elastic
            try:
                # push report
                self.elastic_client.update(index='scanwhisperer-{}-awsinspector'.format(document.get('finding.type')), id=document_id, body={'doc': document,'doc_as_upsert':True})
            
            except Exception as e:
                self.logger.error('Failed push document to Elastic Search: {}'.format(e)) 

        self.logger.debug('Pushed {} awsinspector documents to Elastic Search'.format(len(self.document_queue)))

        # Clear queue after push
        self.clear_queue()


    # Clear the document queue 
    def clear_queue(self):
        self.document_queue = {}
