#### Following enhancements have been made to the ANY.RUN Cloud Sandbox connector in version 2.1.0:

- Renamed the connector from `ANY.RUN` to `ANY.RUN Cloud Sandbox`.
- Deprecated the ANY.RUN v1.1.0 connector. Use ANY.RUN Cloud Sandbox v2.1.0.
- Updated connector configuration:
  - Removed the following parameters:
    - Server Address
    - Username
    - Password
  - Added the parameter `API Key`.
- Renamed the following actions and playbooks:
   - `Get User Limits` is now `Retrieve Account Usage Limits`
   - `Get History` is now `Retrieve Analysis History`
   - `Get Report` is now `Retrieve Analysis Report`
   - `Get Report Attachments` is now `Retrieve Report Attachments`
- Added the following actions and playbooks:
   - Analyze File in Sandbox
   - Analyze URL in Sandbox
   - Retrieve Analysis Verdict
   - Delete Sandbox Analysis
- Updated the `Retrieve Analysis Report` action:
   - Added the parameters `Analysis ID` and `Report Type`.
   - Removed the parameter `Task ID`.
- Updated the `Retrieve Report Attachments` action:
   - Added the parameters `Analysis ID` and `Report Type`.
   - Removed the parameter `Task ID`.
- Added the following playbooks for file and URL analysis using Windows, Linux, and Android sandbox environments:
   - ANY.RUN Analyze File in Windows Sandbox
   - ANY.RUN Analyze File in Linux Sandbox
   - ANY.RUN Analyze File in Android Sandbox
   - ANY.RUN Analyze URL in Windows Sandbox
   - ANY.RUN Analyze URL in Linux Sandbox
   - ANY.RUN Analyze URL in Android Sandbox
- Removed the following playbook:
   - `>>Get ANY.RUN Reputation for File`
- Removed the following actions and playbooks:
   - Run Analysis
   - Get Available Environments


