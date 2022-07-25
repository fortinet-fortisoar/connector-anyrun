""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
from connectors.core.connector import get_logger, ConnectorError
from requests import exceptions as req_exceptions
import base64
import os
import requests
from requests.auth import HTTPBasicAuth
from os.path import join
from integrations.crudhub import make_request
from connectors.cyops_utilities.builtins import download_file_from_cyops, upload_file_to_cyops

logger = get_logger('anyrun')

TMP_DIR = '/tmp/'
PARAM_MAPPING = {
    'Clean': 'clean',
    'Office': 'office',
    'Complete': 'complete',
    'Fastest': 'fastest',
    'Public': 'public',
    'By Link': 'bylink',
    'Owner': 'owner',
    'Desktop': 'desktop',
    'Home': 'home',
    'Downloads': 'downloads',
    'App Data': 'appdata',
    'Temp': 'temp',
    'Windows': 'windows',
    'Root': 'root',
    'File': 'file',
    'URL': 'url',
    'Download': 'download'
}

#Utility Functions
def check_response(response):
    try:
        if response.ok:
            result = response.json()
            return result
        else:
            raise ConnectorError(
                'Fail To request API {0} response is : {1}'.format(str(response.url), str(response.content)))
    except Exception as e:
        raise ConnectorError(e)

def handle_upload_file_to_cyops(file_path):
    try:
        file_name = os.path.basename(file_path)
        attach_response = upload_file_to_cyops(file_path=file_path,
                                               filename=file_name,
                                               name=file_name,
                                               create_attachment=True)
        logger.debug('{0}'.format(str(type(attach_response))))
        os.remove(file_path)
        return {'file_details':attach_response}
    except Exception as err:
        os.remove(file_path)
        logger.exception('An exception occurred {0}'.format(str(err)))
        raise ConnectorError('An exception occurred {0}'.format(str(err)))

def get_config_data(config):
    host = config.get('server', None)
    if not host.startswith('http') or not host.startswith('https'):
        host = 'https://' + host
    user = config.get('user', None)
    password = config.get('password', None)
    verify_ssl = config.get('verify_ssl', True)
    return host.strip('/'), user, password, verify_ssl


def create_basic_auth(username, password):
    # password = 'test'
    auth = '{username}:{password}'.format(username=username, password=password)
    credentials = base64.b64encode(bytes(auth, 'UTF-8')).decode('utf-8')
    return credentials


def make_rest_call(endpoint, config, data=None, params=None, files=None, method='GET'):
    host, user, password, verify_ssl = get_config_data(config)
    url = "{host}/v1/{endpoint}".format(host=host, endpoint=endpoint)
    auth_token = create_basic_auth(user, password)
    auth_header = {'Authorization': 'Basic {credentials}'.format(credentials=auth_token)}
    try:
        r = requests.request(method, url, headers=auth_header, data=data, params=params, files=files, verify=verify_ssl)
        response = check_response(r)
        return response
    except req_exceptions.SSLError:
        logger.error('An SSL error occurred')
        raise ConnectorError('An SSL error occurred')
    except req_exceptions.ConnectionError:
        logger.error('A connection error occurred')
        raise ConnectorError('A connection error occurred')
    except req_exceptions.Timeout:
        logger.error('The request timed out')
        raise ConnectorError('The request timed out')
    except req_exceptions.RequestException:
        logger.error('There was an error while handling the request')
        raise ConnectorError('There was an error while handling the request')
    except Exception as e:
        raise ConnectorError(e)


def build_payload(params):
    payload = dict()
    skip_key = ['run_by']
    for key, value in params.items():
        if key in skip_key:
            continue
        if value != '':
            payload[key] = PARAM_MAPPING.get(value, value)
    logger.info('payload: {}'.format(payload))
    return payload

def handle_attachments(file_id):
    iri_type = 'attachment'
    file_name = None
    if not file_id.startswith('/api/3/'):
        file_id = '/api/3/attachments/' + file_id
    elif file_id.startswith('/api/3/files'):
        iri_type = 'file'

    if iri_type == 'attachment':
        attachment_data = make_request(file_id, 'GET')
        file_iri = attachment_data['file']['@id']
        file_name = attachment_data['file']['filename']
    else:
        file_iri = file_id

    res = download_file_from_cyops(file_iri)
    if not file_name:
        file_name = res['filename']
    logger.info("res: {}".format(res))
    file_path = join('/tmp', res['cyops_file_path'])
    files = {
        'file': (file_name, open(file_path, 'rb'))
    }
    return files    

def report_api_request(url, config, params=None, method='GET'):
    host, user, password, verify_ssl = get_config_data(config)
    try:
        response = requests.request(method, url, params=params,
                             auth=HTTPBasicAuth(user, password), verify=verify_ssl)
        
        if response.ok:
            if 'application/json' in response.headers['content-type']:
                return response.json()
            elif 'text/html' in response.headers['content-type']:
                return response.content
            elif 'content-disposition' in response.headers and 'attachment; filename=' in response.headers['content-disposition']:
                filename = response.headers['content-disposition'].split('=')[1].replace('\'','').replace('"','')
                file_path = TMP_DIR + filename
                logger.debug('Saving file content to: {}'.format(file_path))
                with open(file_path, "wb") as downloaded_file:
                    downloaded_file.write(response.content)
                return handle_upload_file_to_cyops(file_path)
        else:    
            raise ConnectorError('Fail To request API {0} response is : {1}'.format(str(response.url), str(response.content)))
    except req_exceptions.SSLError:
        logger.error('An SSL error occurred')
        raise ConnectorError('An SSL error occurred')
    except req_exceptions.ConnectionError:
        logger.error('A connection error occurred')
        raise ConnectorError('A connection error occurred')
    except req_exceptions.Timeout:
        logger.error('The request timed out')
        raise ConnectorError('The request timed out')
    except req_exceptions.RequestException:
        logger.error('There was an error while handling the request')
        raise ConnectorError('There was an error while handling the request')
    except Exception as e:
        raise ConnectorError(e)


# Operations functions


def get_report_attachments(config, params):
    try:
        uploads_report = {}
        report = get_report(config, params)
        content_files = {
                         'pcap':report['data']['analysis']['content']['pcap']['permanentUrl'],
                         'video':report['data']['analysis']['content']['video']['permanentUrl'],
                         'screenshot':report['data']['analysis']['content']['screenshots'][0]['permanentUrl'],
                         'ioc':report['data']['analysis']['reports']['IOC'],
                         'html':report['data']['analysis']['reports']['HTML'],
                         'misp':report['data']['analysis']['reports']['MISP']
                        }

        for k,v in content_files.items():
            response = report_api_request(v, config)
            uploads_report.update({k:response})

        return uploads_report  

    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)

def get_history(config, params):
    try:
        api_endpoint = 'analysis/'
        query_params = build_payload(params)
        return make_rest_call(api_endpoint, config, params=query_params)
    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)


def get_report(config, params):
    try:
        task_uuid = params.get('task_uuid')
        api_endpoint = 'analysis/{task_id}'.format(task_id=task_uuid)
        return make_rest_call(api_endpoint, config)
    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)


def run_analysis(config, params):
    try:
        files = {}
        api_endpoint = 'analysis'
        query_data = build_payload(params)
        if 'file_id' in query_data:
            file_id = query_data.get('file_id')
            query_data.pop('file_id')
            files = handle_attachments(file_id)
        return make_rest_call(api_endpoint, config, data=query_data, method='POST', files=files)
    except Exception as e:
        raise ConnectorError(e)

def get_available_environments(config, params):
    try:
        api_endpoint = 'environment'
        return make_rest_call(api_endpoint, config)
    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)
        
def get_user_limits(config, params):
    try:
        api_endpoint = 'user'
        return make_rest_call(api_endpoint, config)
    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)  

def _check_health(config):
    try:
        query_param = {'limit': 1}
        response = get_history(config, params=query_param)
        if response:
            return True
    except Exception as e:
        raise ConnectorError(e)


operations = {
    'get_history': get_history,
    'get_report': get_report,
    'run_analysis': run_analysis,
    'get_available_environments': get_available_environments,
    'get_user_limits': get_user_limits,
    'get_report_attachments': get_report_attachments
}
