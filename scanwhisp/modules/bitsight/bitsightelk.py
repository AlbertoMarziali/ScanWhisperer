from __future__ import absolute_import
import logging

import json
import re
import copy
from geoip import geolite2

from elasticsearch import Elasticsearch

import warnings
warnings.filterwarnings("ignore")

class BitSightELK(object):

    def __init__(self, verbose = False, username = None, password = None, host = None):
        self.logger = logging.getLogger('BitSightELK')        
        if verbose:
            self.logger.setLevel(logging.DEBUG)

        self.username = username
        self.password = password
        self.host = host

        # Connect to Elastic Search
        logging.getLogger('elasticsearch').setLevel(logging.CRITICAL)
        self.elastic_client = Elasticsearch('https://{}:{}@{}'.format(self.username, self.password, self.host), ca_certs=False, verify_certs=False)
        
        # Document queue
        self.document_queue = []

        # Delete old index on Elastic Search
        self.elastic_client.indices.delete(index='scanwhisperer-bitsight',ignore=[400,404])

        # Create index on Elastic Search
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
        self.elastic_client.indices.create(index='scanwhisperer-bitsight',body=mapping, ignore=400)

        self.logger.info('Index "scanwhisperer-bitsight" on Elastic Search ready.')


    # This function adds field to document
    def add_field_to_document(self, document, field, content):
        if content:
            if isinstance(content, str):
                content = content.strip()

            document.update({ field : content })


    # This function creates a documents from a finding (one finding may contain multiple documents)
    def create_document(self, company, finding):
        # assemble document: 
        document = {}
        documents = []

         # ---- BitSight specific part ----
        # This fields are exclusive to BitSight
        self.add_field_to_document(document, 'bitsight.company', company.get('name'))
        self.add_field_to_document(document, 'bitsight.evidence_key',  finding.get('evidence_key'))
        # Attributed companies. Pick first not containing "Group", else pick absolute First.
        self.add_field_to_document(document, 'bitsight.attributed_company', next((item.get('name') for item in finding['attributed_companies'] if item.get('name') and "Group" not in item.get('name', '')), next((item.get('name') for item in finding['attributed_companies']), None)))
        self.add_field_to_document(document, 'bitsight.rolledup_observation_id',  finding.get('rolledup_observation_id'))
        self.add_field_to_document(document, 'bitsight.temporary_id',  finding.get('temporary_id'))
        
        # ---- Asset part ----
        # Scan target (asset) properties
        self.add_field_to_document(document, 'asset.observed_ips', finding.get('details', {}).get('observed_ips'))
        self.add_field_to_document(document, 'asset.port', finding.get('details', {}).get('dest_port'))
        # Geo location coordinates (extract IP from Observed IPS)
        if document.get('asset.observed_ips'):
            try:
                # IP Location lookup
                observed_ip = next((item for item in document['asset.observed_ips']), '')
                extracted_ip = next((item for item in re.findall(r'(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)', observed_ip)), '')
                df_geoip_location = geolite2.lookup(extracted_ip)
                if df_geoip_location:
                    self.add_field_to_document(document, 'asset.geo.location', {
                                                "lat": df_geoip_location.location[0],
                                                "lon": df_geoip_location.location[1]
                                            })
            except: 
                pass # Ignore it
        # Geo name (IT, CZ)
        self.add_field_to_document(document, 'asset.geo.name', finding.get('details', {}).get('geo_ip_location'))

        # ---- Finding part ----
        # extract Finding metadata 
        self.add_field_to_document(document, 'finding.comments', finding.get('comments'))
        self.add_field_to_document(document, 'finding.grade', finding.get('details', {}).get('grade'))
        self.add_field_to_document(document, 'finding.rollup_end_date', finding.get('details').get('rollup_end_date'))
        self.add_field_to_document(document, 'finding.rollup_start_date', finding.get('details').get('rollup_start_date'))
        self.add_field_to_document(document, 'finding.first_observed', finding.get('first_seen'))
        self.add_field_to_document(document, 'finding.last_observed', finding.get('last_seen'))
        self.add_field_to_document(document, 'finding.source', 'bitsight')
        self.add_field_to_document(document, 'finding.remaining_decay', finding.get('remaining_decay'))
        self.add_field_to_document(document, 'finding.risk.category', finding.get('risk_category'))
        self.add_field_to_document(document, 'finding.risk.vector.raw', finding.get('risk_vector'))
        self.add_field_to_document(document, 'finding.risk.vector.label', finding.get('risk_vector_label'))
        self.add_field_to_document(document, 'finding.severity.score', finding.get('severity'))
        self.add_field_to_document(document, 'finding.severity.category', finding.get('severity_category'))

        # findings details
        df_diligence_annotations = finding.get('details', {}).get('diligence_annotations', '')
        if df_diligence_annotations is not '':
            self.add_field_to_document(document, 'finding.diligence_annotations', json.dumps(df_diligence_annotations, indent=4, sort_keys=True))

        # Report is almost ready
        documents.append(document)

        # REPORT DUPLICATION
        # Multiple assets and remediation leads to multiple documents

        # ASSET: Multiple assets generate multiple documents
        # Tecnique: copy the document list and duplicate each field in a new one
        df_assets = finding.get('assets', [])
        if df_assets:
            new_documents = []

            # copy each document from documents and multiply it
            for single_document in documents:

                # create a new document for each asset
                for asset in df_assets:
                    new_document = copy.deepcopy(single_document) # copy the document

                    # Asset name
                    self.add_field_to_document(new_document, 'asset.name', asset.get('asset'))
                    # Asset importance
                    self.add_field_to_document(new_document, 'asset.importance', asset.get('importance'))
                    # Asset category
                    self.add_field_to_document(new_document, 'asset.category', asset.get('category'))

                    # Add document to new documents
                    new_documents.append(new_document)

            # Replace document list
            documents = copy.deepcopy(new_documents)

        # REMEDIATIONS: Multiple remediations generate multiple documents.
        # Loop over remediations and create a new document for each one
        # Tecnique: copy the document list and duplicate each field in a new one
        df_remediations = finding.get('details', {}).get('remediations', [])
        if df_remediations:
            new_documents = []

            # copy each document from documents and multiply it
            for single_document in documents:

                # create a new document for each remediation
                for remediation in df_remediations:
                    new_document = copy.deepcopy(single_document) # copy the document

                    # Add Message Field
                    self.add_field_to_document(new_document, 'finding.title', remediation.get('message'))
                    # Add Remediation Field
                    self.add_field_to_document(new_document, 'finding.solution', remediation.get('remediation_tip'))

                    # Add document to new documents
                    new_documents.append(new_document)

            # Replace document list
            documents = copy.deepcopy(new_documents)

        # Return documents
        return documents
        

    # This function adds the document to the queue. If already there, it applies some changes to CVE field
    def add_to_queue(self, company, finding):

        # Create documents and add to queue
        self.document_queue.extend(self.create_document(company, finding))


    # Push documents to Elastic Search
    def push_queue(self):

        self.logger.debug('Pushing {} bitsight documents.'.format(len(self.document_queue)))

        # Iterate over document queue
        for document in self.document_queue:
            # Push document to Elastic
            try:
                # push document
                self.elastic_client.index(index='scanwhisperer-bitsight', body=document)            
            except Exception as e:
                self.logger.error('Failed push document to Elastic Search: {}'.format(e)) 

        self.logger.debug('Pushed {} bitsight documents to Elastic Search'.format(len(self.document_queue)))

        # Clear queue after push
        self.document_queue = {}
