"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from anyrun.connectors import SandboxConnector
from anyrun.connectors.sandbox.operation_systems import (
    AndroidConnector,
    LinuxConnector,
    WindowsConnector,
)

from .constants import VERSION


def get_windows_sandbox_connector(config: dict) -> WindowsConnector:
    """ Builds ANY.RUN Sandbox instance for the Windows OS """
    return SandboxConnector().windows(config.get('api_key'), integration=VERSION, verify_ssl=config.get('verify_ssl'))


def get_linux_sandbox_connector(config: dict) -> LinuxConnector:
    """ Builds ANY.RUN Sandbox instance for the Linux OS """
    return SandboxConnector().linux(config.get('api_key'), integration=VERSION, verify_ssl=config.get('verify_ssl'))


def get_android_sandbox_connector(config: dict) -> AndroidConnector:
    """ Builds ANY.RUN Sandbox instance for the Android OS """
    return SandboxConnector().android(config.get('api_key'), integration=VERSION, verify_ssl=config.get('verify_ssl'))


os_connector_mapping = {
    'windows': get_windows_sandbox_connector,
    'linux': get_linux_sandbox_connector,
    'android': get_android_sandbox_connector,
}
