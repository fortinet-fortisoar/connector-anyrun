"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import os
import traceback
from anyrun import RunTimeException
from connectors.core.connector import ConnectorError, get_logger
from connectors.cyops_utilities.builtins import (
    download_file_from_cyops,
    upload_file_to_cyops,
)

from .constants import LOGGER_NAME
from .utils import get_windows_sandbox_connector, os_connector_mapping

logger = get_logger(LOGGER_NAME)

TMP_DIR = '/tmp/'  # noqa: S108


def exceptions_handler(function):
    """ Handles errors in functions """

    def wrapper(*args, **kwargs):

        try:
            return function(*args, **kwargs)
        except RunTimeException as error:
            logger.exception(str(error))
            raise ConnectorError(f'ANY.RUN Exception: {str(error)}')
        except Exception:
            error = traceback.format_exc()
            logger.exception(error)
            raise ConnectorError(f'Unspecified Exception: {error}')

    return wrapper


def _handle_upload_file_to_cyops(filepath: str, filename: str) -> str:
    """ Loads analysis report to the cycops """
    full_path = os.path.join(filepath, filename)
    _ = upload_file_to_cyops(
        file_path=full_path, filename=filename, name=filename, create_attachment=True
    )

    os.remove(full_path)
    return filename


def _handle_attachments(file_id: str) -> bytes:
    """ Returns attachment bytes """
    if not file_id.startswith('/modules/attachments/'):
        file_id = '/modules/attachments/' + file_id

    metadata = download_file_from_cyops(file_id)
    file_name = metadata.get('cyops_file_path', None)
    file_path = os.path.join(TMP_DIR, file_name)
    with open(file_path, 'rb') as f:
        return f.read()


def _report_postfixer(task_uuid: str, report_type: str) -> str:
    """ Builds filename according to the report type """
    mapping = {
        'html': '.html',
        'misp': '_misp.json',
        'ioc': '_ioc.json',
        'stix': '_stix.json',
        'json': '_json.json',
    }

    return f'{task_uuid}_report{mapping.get(report_type, "")}'


def _stop_task(config: dict, task_uuid: str) -> dict:
    """ Stops the analysis """
    with get_windows_sandbox_connector(config) as connector:
        status_iterator = connector.get_task_status(task_uuid=task_uuid)

        for status in status_iterator:
            st = status.get('status').lower()

            if st not in {'preparing', 'completed'}:
                connector.stop_task(task_uuid)

    return {'status': 'success'}


@exceptions_handler
def get_analysis_verdict(config, params) -> dict:
    task_uuid = params.get('task_uuid')

    with get_windows_sandbox_connector(config) as connector:
        status_iterator = connector.get_task_status(task_uuid=task_uuid)

        for status in status_iterator:
            status.get('status').lower()

        verdict = connector.get_analysis_verdict(task_uuid=task_uuid)
        return {'verdict': verdict}


@exceptions_handler
def get_user_history(config, params: dict) -> list[dict]:
    with get_windows_sandbox_connector(config) as connector:
        return connector.get_analysis_history(**params)


@exceptions_handler
def get_report(config, params: dict) -> dict:
    report_type, task_uuid, is_attachment = (
        params.get('report_type', 'JSON').lower(),
        params.get('task_uuid'),
        params.get('is_attachment', False),
    )

    filename = _report_postfixer(task_uuid, report_type)
    filepath = TMP_DIR if is_attachment else None

    with get_windows_sandbox_connector(config) as connector:
        report = connector.get_analysis_report(
            task_uuid=task_uuid, report_format=report_type, filepath=filepath
        )

        if is_attachment:
            return _handle_upload_file_to_cyops(filepath, filename)

        return report


@exceptions_handler
def get_report_attachments(config, params: dict) -> dict:
    params['is_attachment'] = True
    return get_report(config, params)


@exceptions_handler
def get_user_limits(config, params=None) -> dict:
    with get_windows_sandbox_connector(config) as connector:
        return connector.get_user_limits()


@exceptions_handler
def delete_analysis(config, params) -> dict:
    task_uuid = params.get('task_uuid')

    with get_windows_sandbox_connector(config) as connector:
        _stop_task(config, task_uuid)

        return connector.delete_task(task_uuid)


@exceptions_handler
def detonate_file(config, params) -> dict:
    file_id = params.pop('attachment_iri')
    file_content = _handle_attachments(file_id)
    params['file_content'] = file_content
    params['filename'] = file_id.split('/')[-1]
    env_os = params.pop('operationSystem').lower()
    connector = os_connector_mapping.get(env_os)

    with connector(config) as conn:
        task_id = conn.run_file_analysis(**params)
        return {'task_uuid': task_id}


def detonate_url(config, params) -> dict:
    env_os = params.pop('operationSystem').lower()
    if env_os == 'windows':
        params['env_version'] = str(params['env_version'])

    connector = os_connector_mapping.get(env_os)

    with connector(config) as conn:
        task_id = conn.run_url_analysis(**params)
        return {'task_uuid': task_id}


@exceptions_handler
def _check_health(config: dict) -> bool:
    """ Checks connection to ANY.RUN """
    query_param = {'limit': 1}
    response = get_user_history(config, params=query_param)
    if response:
        return True
    return False


operations = {
    'get_user_history': get_user_history,
    'get_user_limits': get_user_limits,
    'get_report': get_report,
    'get_report_attachments': get_report_attachments,
    'detonate_file': detonate_file,
    'detonate_url': detonate_url,
    'delete_analysis': delete_analysis,
    'get_analysis_verdict': get_analysis_verdict,
}
