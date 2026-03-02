"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, ConnectorError, get_logger
from .operations import _check_health, operations
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
