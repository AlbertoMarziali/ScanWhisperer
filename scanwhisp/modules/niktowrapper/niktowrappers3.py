from __future__ import absolute_import
import logging

import boto3 #AWS Python SDK


class NiktoWrapperS3(object):

    def __init__(self, verbose=False, region_name=None, access_key=None, secret_key=None, bucket_name=None):
        self.logger = logging.getLogger('NiktoWrapperS3')
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        if not all((region_name, access_key, secret_key, bucket_name)):
            raise Exception('ERROR: Missing Region, API keys or Bucket Name')

        self.verbose = verbose
        self.bucket_name = bucket_name

        self.s3 = boto3.resource('s3',
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_key,
                            region_name = region_name)

        # Check
        self.check()

        
    def check(self):
        if self.s3.Bucket(self.bucket_name).creation_date is None:
            raise Exception('ERROR: Bucket {} not found'.format(self.bucket_name))

        
    def get_new_files(self):
        files = []

        for my_bucket_object in self.s3.Bucket(self.bucket_name).objects.all():
            if not my_bucket_object.key.startswith('__'): # avoid __assetlist.txt and __branchofficelist.txt
                files.append(my_bucket_object.key)

        return files
            

    def download_file(self, remote_file_name):
        return self.s3.meta.client.get_object(Bucket=self.bucket_name, Key=remote_file_name)['Body'].read().decode('utf-8')


    def delete_file(self, remote_file_name):
        self.s3.Object(self.bucket_name, remote_file_name).delete()