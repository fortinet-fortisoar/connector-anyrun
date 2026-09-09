"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, ConnectorError, get_logger
from .operations import _check_health, operations
from integrations.crudhub import make_request
from django.conf import settings
from .constants import MACRO_LIST
from .constants import LOGGER_NAME

logger = get_logger(LOGGER_NAME)


class Any_run(Connector):  # noqa: N801
    def execute(self, config, operation, params, *args, **kwargs):
        """ Executes the action """
        try:
            logger.info(f'Action name: {operation}')
            op = operations.get(operation)

            return op(config, params)
        except Exception as e:
            logger.exception(f'An exception in execute occurred {e.args}')
            raise ConnectorError(e) from e

    def check_health(self, config=None, *args, **kwargs):
        """ Checks connection to ANY.RUN """
        try:
            return _check_health(config)
        except Exception as e:
            logger.exception(f'An exception in health check occurred {e.args}')
            raise ConnectorError(e) from e

    def del_micro(self, config):
        if not settings.LW_AGENT:
            for macro in MACRO_LIST:
                try:
                    resp = make_request(f'/api/wf/api/dynamic-variable/?name={macro}', 'GET')
                    if resp['hydra:member']:
                        logger.info("resetting global variable '%s'" % macro)
                        macro_id = resp['hydra:member'][0]['id']
                        resp = make_request(f'/api/wf/api/dynamic-variable/{macro_id}/?format=json', 'DELETE')
                except Exception as e:
                    logger.error(e)

    def on_deactivate(self, config):
        self.del_micro(config)

    def on_activate(self, config):
        self.del_micro(config)

    def on_add_config(self, config, active):
        self.del_micro(config)

    def on_delete_config(self, config):
        self.del_micro(config)

    def teardown(self, config):
        self.del_micro(config)
