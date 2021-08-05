from __future__ import absolute_import
import json
import logging
import sys
import time
from datetime import datetime

import pytz
import requests


class NessusAPI(object):

    def __init__(self, hostname=None, port=None, verbose=False, access_key=None, secret_key=None):
        self.logger = logging.getLogger('NessusAPI')
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        if not all((access_key, secret_key)):
            raise Exception('ERROR: Missing API keys.')

        self.access_key = access_key
        self.secret_key = secret_key
        self.base = 'https://{hostname}:{port}'.format(hostname=hostname, port=port)
        self.verbose = verbose

        self.session = requests.Session()
        self.session.verify = False
        self.session.stream = True
        self.session.headers = {
            'Origin': self.base,
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.8',
            'User-Agent': 'ScanWhisperer for Nessus',
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': self.base,
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive',
            'X-Cookie': None
        }

        self.session.headers['X-ApiKeys'] = 'accessKey={}; secretKey={}'.format(self.access_key, self.secret_key)


    def request(self, url, data=None, headers=None, method='POST', download=False, json_output=False):
        timeout = 0
        success = False

        method = method.lower()
        url = self.base + url
        self.logger.debug('Requesting to url {}'.format(url))

        while (timeout <= 10) and (not success):
            response = getattr(self.session, method)(url, data=data)
            if response.status_code == 401:
                if url == self.base + '/session':
                    break
                timeout += 1
            else:
                success = True

        if json_output:
            return response.json()
        if download:
            self.logger.debug('Returning data.content')
            response_data = ''
            count = 0
            for chunk in response.iter_content(chunk_size=8192):
                count += 1
                if chunk:
                    response_data += chunk.decode("utf-8")
            self.logger.debug('Processed {} chunks'.format(count))
            return response_data
        return response


    def get_scans(self):
        scans = self.request('/scans', method='GET', json_output=True)
        return scans


    def get_scan_history(self, scan_id):
        data = self.request('/scans/{scan_id}'.format(scan_id=scan_id), method='GET', json_output=True)
        return data['history']


    def get_scan_hosts(self, scan_id, history_id=None):
        host_list = {}

        if not history_id:
            query = '/scans/{scan_id}'.format(scan_id=scan_id)
        else:
            query = '/scans/{scan_id}?history_id={history_id}'.format(scan_id=scan_id, history_id=history_id)
        data = self.request(query, method='GET', json_output=True)

        for host in data['hosts']:
            if host['hostname'] not in host_list:
                if not history_id:
                    query = '/scans/{scan_id}/hosts/{host_id}'.format(scan_id=scan_id, host_id=host['host_id'])
                else:
                    query = '/scans/{scan_id}/hosts/{host_id}?history_id={history_id}'.format(scan_id=scan_id, host_id=host['host_id'], history_id=history_id)
                
                host_list[host['hostname']] = self.request(query, method='GET', json_output=True)['info']

        return host_list


    def download_scan(self, scan_id=None, history=None, export_format=""):
        running = True
        counter = 0

        data = {'format': export_format}
        if not history:
            query = '/scans/{scan_id}/export'.format(scan_id=scan_id)
        else:
            query = '/scans/{scan_id}/export?history_id={history_id}'.format(scan_id=scan_id, history_id=history)
            scan_id = str(scan_id)
        req = self.request(query, data=json.dumps(data), method='POST', json_output=True)
        try:
            file_id = req['file']
            token_id = req['token'] if 'token' in req else req['temp_token']
        except Exception as e:
            self.logger.error('{}'.format(str(e)))
        self.logger.debug('Download for file id {}'.format(str(file_id)))
        while running:
            time.sleep(2)
            counter += 2
            report_status = self.request('/scans/{scan_id}/export/{file_id}/status'.format(scan_id=scan_id, file_id=file_id), method='GET',
                                         json_output=True)
            running = report_status['status'] != 'ready'
            sys.stdout.write(".")
            sys.stdout.flush()
            # FIXME: why? can this be removed in favour of a counter?
            if counter % 60 == 0:
                self.logger.debug("Completed: {}".format(counter))
        self.logger.debug("Done: {}".format(counter))

        content = self.request('/scans/{scan_id}/export/{file_id}/download'.format(scan_id=scan_id, file_id=file_id), method='GET', download=True)
               
        return content
        

    def get_utc_from_local(self, date_time, local_tz=None, epoch=True):
        date_time = datetime.fromtimestamp(date_time)
        if local_tz is None:
            local_tz = pytz.timezone('UTC')
        else:
            local_tz = pytz.timezone(local_tz)
        local_time = local_tz.normalize(local_tz.localize(date_time))
        local_time = local_time.astimezone(pytz.utc)
        if epoch:
            naive = local_time.replace(tzinfo=None)
            local_time = int((naive - datetime(1970, 1, 1)).total_seconds())
        self.logger.debug('Converted timestamp {} in datetime {}'.format(date_time, local_time))
        return local_time

