from __future__ import absolute_import

__author__ = 'Alberto Marziali'

import logging
from datetime import datetime

from geoip import geolite2
import hashlib
from elasticsearch import Elasticsearch

import warnings
warnings.filterwarnings("ignore")


class NiktoWrapperELK(object):

    def __init__(self, verbose = False, username = None, password = None, host = None):
        self.logger = logging.getLogger('NiktoWrapperELK')
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
    def create_document(self, finding):
        # assemble document: 
        # hostname,ip,port,osvdb,httpmethod,uri,result,branch
        document = {}

        # ---- Asset part ----
        self.add_field_to_document(document, 'asset.name', finding.get('hostname'))
        self.add_field_to_document(document, 'asset.ip', finding.get('ip'))
        self.add_field_to_document(document, 'asset.port', finding.get('port'))  
        self.add_field_to_document(document, 'asset.branch', finding.get('branch')) 
        # geoip
        df_geoip = geolite2.lookup(document.get('asset.ip'))
        if df_geoip:
            self.add_field_to_document(document, 'asset.geo.location', {
                                                "lat": df_geoip.location[0],
                                                "lon": df_geoip.location[1]
                                            })

        # ---- Finding part ----
        self.add_field_to_document(document, 'finding.source', 'niktowrapper')
        self.add_field_to_document(document, 'finding.osvdb', finding.get('osvdb'))
        self.add_field_to_document(document, 'finding.httpmethod', finding.get('httpmethod'))
        self.add_field_to_document(document, 'finding.uri', finding.get('uri'))
        self.add_field_to_document(document, 'finding.title', finding.get('result'))
        self.add_field_to_document(document, 'finding.first_observed', datetime.utcnow().isoformat())
        self.add_field_to_document(document, 'finding.last_observed', datetime.utcnow().isoformat())

        return document


    # This function adds the document to the queue. If already there, it applies some changes to CVE field
    def add_to_queue(self, finding):

        # Create Document
        document = self.create_document(finding)

        # Generate id 
        document_id = hashlib.sha1(('{}{}{}{}'.format(document.get('asset.name'), document.get('asset.ip'), document.get('asset.port'), document.get('finding.title'))).encode('utf-8')).hexdigest()

        # Add (or replace) document to the queue
        self.document_queue.update({ document_id : document })


    # Push documents to Elastic Search
    def push_queue(self):

        self.logger.debug('Pushing {} niktowrapper documents'.format(len(self.document_queue)))

        # Iterate over document queue
        for document_id, document in self.document_queue.items():
            
             # Create index on Elastic Search
            try:
                # create index if needed
                mapping = {
                    "mappings": {
                        "properties": {
                            "asset.port": {
                                "type": "integer" 
                            },
                            "asset.geo.location": {
                                "type": "geo_point" 
                            }
                        }
                    }
                }
                self.elastic_client.indices.create(index='scanwhisperer-niktowrapper',body=mapping, ignore=400)

            except Exception as e:
                self.logger.error('Failed to create index scanwhisperer-niktowrapper on Elastic Search: {}'.format(e)) 
            
            # Query Elastic Search to fetch a document with the same ID
            # If found,overwrite new first_observed with older to avoid updating it
            try:
                # Fetch document
                elk_response = self.elastic_client.search(index='scanwhisperer-niktowrapper', body={
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

            # Push document to Elastic
            try:
                # push document
                self.elastic_client.update(index='scanwhisperer-niktowrapper', id=document_id, body={'doc': document,'doc_as_upsert':True})
            
            except Exception as e:
                self.logger.error('Failed push document to Elastic Search: {}'.format(e)) 

        self.logger.debug('Pushed {} niktowrapper documents to Elastic Search'.format(len(self.document_queue)))

        # Clear queue after push
        self.document_queue = {}
