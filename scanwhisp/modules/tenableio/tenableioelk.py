from __future__ import absolute_import
import logging
from datetime import datetime

import hashlib
from elasticsearch import Elasticsearch

import warnings
warnings.filterwarnings("ignore")


class TenableioELK(object):

    def __init__(self, verbose = False, username=None, password=None, host=None):
        self.logger = logging.getLogger('TenableioELK')
        if verbose:
            self.logger.setLevel(logging.DEBUG)
   
        self.username = username
        self.password = password
        self.host = host

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
        # assemble document: 
        document = {}

        # ---- Tenable.io part
        self.add_field_to_document(document, 'tenableio.scan.name', scan.get('scan_name'))
        self.add_field_to_document(document, 'tenableio.scan.id', scan.get('scan_id'))
        self.add_field_to_document(document, 'tenableio.history.id', scan.get('history_id'))
        self.add_field_to_document(document, 'tenableio.plugin.id', finding.get('Plugin ID'))
        self.add_field_to_document(document, 'tenableio.plugin.name', finding.get('Name'))
        self.add_field_to_document(document, 'tenableio.plugin.family', finding.get('Plugin Family')) 

        # ---- Asset part ----
        self.add_field_to_document(document, 'asset.host', finding.get('Host'))
        self.add_field_to_document(document, 'asset.ip', finding.get('IP Address')) 
        self.add_field_to_document(document, 'asset.port', finding.get('Port'))   
        self.add_field_to_document(document, 'asset.protocol', finding.get('Protocol'))
        self.add_field_to_document(document, 'asset.uuid', finding.get('Asset UUID')) 
        self.add_field_to_document(document, 'asset.fqdn', finding.get('FQDN')) 
        self.add_field_to_document(document, 'asset.netbios', finding.get('NetBios')) 
        self.add_field_to_document(document, 'asset.os', finding.get('OS')) 
        self.add_field_to_document(document, 'asset.mac_address', finding.get('Mac Address')) 
        self.add_field_to_document(document, 'asset.system_type', finding.get('System Type')) 

        # ---- CVE Part ----
        self.add_field_to_document(document, 'cve.id', finding.get('CVE')) 
        self.add_field_to_document(document, 'cve.cvss.score', finding.get('CVSS')) 
        self.add_field_to_document(document, 'cve.cvss.vector', finding.get('CVSS Vector'))  
        self.add_field_to_document(document, 'cve.cvss2.score', finding.get('CVSS')) 
        self.add_field_to_document(document, 'cve.cvss.base.score', finding.get('CVSS Base Score'))  
        self.add_field_to_document(document, 'cve.cvss.temporal.score', finding.get('CVSS Temporal Score'))  
        self.add_field_to_document(document, 'cve.cvss.temporal.vector', finding.get('CVSS Temporal Vector'))  
        self.add_field_to_document(document, 'cve.cvss3.score', finding.get('CVSS3 Base Score')) 
        self.add_field_to_document(document, 'cve.cvss3.vector', finding.get('CVSS3 Vector'))  
        self.add_field_to_document(document, 'cve.cvss3.base.score', finding.get('CVSS3 Base Score')) 
        self.add_field_to_document(document, 'cve.cvss3.temporal.score', finding.get('CVSS3 Temporal Score')) 
        self.add_field_to_document(document, 'cve.cvss3.temporal.vector', finding.get('CVSS3 Temporal Vector'))  
        if document.get('cve.cvss.score'):
            self.add_field_to_document(document, 'cve.package_name', finding.get('Name'))  

        # ---- Finding metadata part ----
        self.add_field_to_document(document, 'finding.first_observed', datetime.fromtimestamp(scan.get('norm_time', datetime.utcnow().timestamp())).isoformat())
        self.add_field_to_document(document, 'finding.last_observed', datetime.fromtimestamp(scan.get('norm_time', datetime.utcnow().timestamp())).isoformat())
        self.add_field_to_document(document, 'finding.risk', finding.get('Risk'))
        self.add_field_to_document(document, 'finding.title', finding.get('Synopsis'))
        self.add_field_to_document(document, 'finding.description', finding.get('Description'))
        self.add_field_to_document(document, 'finding.solution', finding.get('Solution'))
        self.add_field_to_document(document, 'finding.source', 'tenableio')
        self.add_field_to_document(document, 'finding.plugin_output', finding.get('Plugin Output'))
        self.add_field_to_document(document, 'finding.see_also', finding.get('See Also'))
        self.add_field_to_document(document, 'finding.state', finding.get('Vulnerability State')) 
        # Guess finding type by existing fields
        if document.get('cve.cvss.score'):
            self.add_field_to_document(document, 'finding.type', 'cve')
        else:
            self.add_field_to_document(document, 'finding.type', 'other')

        return document


    # This function adds the document to the queue. If already there, it applies some changes to CVE field
    def add_to_queue(self, scan, finding):

        # Create Document
        document = self.create_document(scan, finding)

        # Create Document ID
        document_id = hashlib.sha1(('{}{}{}'.format(document.get('asset.ip'), document.get('asset.port'), document.get('tenableio.plugin.id'))).encode('utf-8')).hexdigest()

        # Check if the document is already in the queue
        if self.document_queue.get(document_id):
            # If cve.id in old document, copy over to new document
            if self.document_queue.get(document_id).get('cve.id'):
                                            
                # If cve.id in new document and not in older document, add older cve.id to new cve.id, else just copy over
                if document.get('cve.id') and document.get('cve.id') not in self.document_queue.get(document_id).get('cve.id'):
                    # Add older cve.id to new cve.id
                    document['cve.id'] = '{},{}'.format(self.document_queue.get(document_id).get('cve.id'), document.get('cve.id'))
                else:
                    # Copy older cve.id in new document
                    document['cve.id'] = self.document_queue.get(document_id).get('cve.id')

        # Add (or replace) document to the queue
        self.document_queue.update({ document_id : document })


    # Push documents to Elastic Search
    def push_queue(self):

        self.logger.debug('Pushing {} Tenable.io documents.'.format(len(self.document_queue)))

        # Iterate over document queue
        for document_id, document in self.document_queue.items():
            
            # Create index on Elastic Search
            try:
                # create index if needed
                mapping = {
                    "mappings": {
                        "properties": {
                            "cve.cvss.score": {
                                "type": "float" 
                            },
                            "cve.cvss2.score": {
                                "type": "float" 
                            },
                            "cve.cvss.base.score": {
                                "type": "float" 
                            },
                            "cve.cvss.temporal.score": {
                                "type": "float" 
                            },
                            "cve.cvss3.score": {
                                "type": "float" 
                            },
                            "cve.cvss3.base.score": {
                                "type": "float" 
                            },
                            "cve.cvss3.temporal.score": {
                                "type": "float" 
                            },

                        }
                    }
                }
                self.elastic_client.indices.create(index='scanwhisperer-{}-tenableio'.format(document.get('finding.type')),body=mapping, ignore=400)

            except Exception as e:
                self.logger.error('Failed create index scanwhisperer-{}-tenableio on Elastic Search: {}'.format(document.get('finding.type'), e)) 
            
            # Query Elastic Search to fetch a document with the same ID
            # If found,overwrite new first_observed with older to avoid updating it
            try:
                # Fetch document
                elk_response = self.elastic_client.search(index='scanwhisperer-{}-tenableio'.format(document.get('finding.type')), body={
                    "query": {
                        "match": {
                            "_id": document_id
                        }
                    }
                })

                # If document was found
                if elk_response.get('hits').get('total').get('value') == 1:
                    # Maintain old first observed
                    document['finding.first_observed'] = elk_response.get('hits').get('hits')[0].get('_source').get('finding.first_observed')

            except Exception as e:
                self.logger.error('Failed to get document from Elastic Search: {}'.format(e)) 

            # Push document to Elastic
            try:
                # push document
                self.elastic_client.update(index='scanwhisperer-{}-tenableio'.format(document.get('finding.type')), id=document_id, body={'doc': document,'doc_as_upsert':True})
            
            except Exception as e:
                self.logger.error('Failed push document to Elastic Search: {}'.format(e)) 

        self.logger.debug('Pushed {} Tenable.io documents to Elastic Search'.format(len(self.document_queue)))

        # Clear queue after push
        self.document_queue = {}
