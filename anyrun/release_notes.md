#### The following enhancements have been made to the ANY.RUN connector in version 2.0.0:

- The `ANY.RUN 1.1.0` connector has been deprecated. Please use `ANY.RUN 2.0.0` instead.
- Updated the connector label from `ANY.RUN` to `ANY.RUN Cloud Sandbox`.
- Removed the `Server Address`, `Username`, and `Password` configuration parameters.
- Added a new `API Key` parameter in the configuration section.
- New actions and playbooks added:
    - Detonate File
    - Detonate URL
    - Get Analysis Verdict
    - Delete Analysis
- In the `Get Report` action, added new parameters `Analysis ID` and `Report Type`, and removed the `Task ID` parameter.
- In the `Get Report Attachments` action, added new parameters `Analysis ID` and `Report Type`, and removed the
  `Task ID` parameter.
- Removed actions and playbooks:
    - Run Analysis
    - Get Available Environments
- Removed playbook:
    - `>>Get ANY.RUN Reputation for File`
- Added new playbooks. These playbooks perform File/URL analysis using Windows, Linux, and Android VMs, providing fast
  and detailed threat insights:
    - ANY.RUN Detonate File on Windows
    - ANY.RUN Detonate File on Linux
    - ANY.RUN Detonate File on Android
    - ANY.RUN Detonate URL on Windows
    - ANY.RUN Detonate URL on Linux
    - ANY.RUN Detonate URL on Android
