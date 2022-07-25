# `>> Draft <<`

## 1.1.0 New actions:
- >> Get ANY.RUN Reputation for File : A module for modular enrichment 
- Get user Limits : Retrieves requests limits for the authenticated user according to the subscribed plan.
- Get Available Environements: Retrieves the list of available sandbox VMs environments.
- Get Report Attachement: Retrieves several report attachments such as the HTML report, screenshot, execution video, Misp record and many more

About the connector
ANY.RUN is an interactive malware analysis sandbox used to detect, analyze, and monitor cybersecurity threats.

This document provides information about the ANY.RUN connector, which facilitates automated interactions with ANY.RUN using FortiSOAR™ playbooks. Add the ANY.RUN connector as a step in FortiSOAR™ playbooks and perform automated operations such as retrieving analysis history or retrieving a report for the specified task ID from ANY.RUN, and running an analysis on ANY.RUN.

Version information
Connector Version: 1.0.0

Authored By: Community

Certified: No

Installing the connector
From FortiSOAR™ 5.0.0 onwards, use the Connector Store to install the connector. For the detailed procedure to install a connector, click here.
You can also use the following yum command as a root user to install connectors from an SSH session:

yum install cyops-connector-anyrun

Prerequisites to configuring the connector
You must have the FQDN of the ANY.RUN server to which you will connect and perform automated operations and credentials to access that ANY.RUN endpoint.
The FortiSOAR™ server should have outbound connectivity to port 443 on the ANY.RUN server.
Minimum Permissions Required
Not Applicable
Configuring the connector
For the procedure to configure a connector, click here

Configuration parameters
In FortiSOAR™, on the Connectors page, click the ANY.RUN connector row (if you are in the Grid view on the Connectors page) and in the Configurations tab enter the required configuration details: 

Parameter	Description
Server Address	FQDN of the ANY.RUN server to which you will connect and perform automated operations.
Username	Username to access the ANY.RUN endpoint to which you will connect and perform automated operations.
Password	Password to access the ANY.RUN endpoint to which you will connect and perform automated operations.
Verify SSL	Specifies whether the SSL certificate for the server is to be verified or not.
Actions supported by the connector
The following automated operations can be included in playbooks, and you can also use the annotations to access operations from version 4.10.0 onwards:

Function	Description	Annotation and Category
Get History	Retrieves analysis history from ANY.RUN based on input parameters you have specified.	get_history
Investigation
Get Report	Retrieves a report for the specified task ID from ANY.RUN based on task UUID you have specified. The task ID is generated when you have submitted an analysis to ANY.RUN.	get_report
Investigation
Run Analysis	Runs an analysis in ANY.RUN based on the action that you want to perform using ANY.RUN and other input parameters you have specified.	run_analysis
Investigation
operation: Get History
Input parameters
Note: All the input parameters are optional. However, if you do not specify any parameter, then no filter criterion is applied, and an unfiltered list is returned.

Parameter	Description
Team	Select this checkbox and specify the team to retrieve the history of the team. if you leave the checkbox cleared (default), then your history is retrieved.
Skip	The number of results that this operation should skip. By default, this is set to "0".
Limit	Maximum number of items that this operation should return in a single search. By default, this is set to "25". You can specify any number between 1-100.
Output
The output contains the following populated JSON schema:
{
     "error": "",
     "data": {
         "tasks": [
             {
                 "verdict": "",
                 "name": "",
                 "related": "",
                 "pcap": "",
                 "file": "",
                 "json": "",
                 "misp": "",
                 "tags": [],
                 "date": "",
                 "hashes": {
                     "ssdeep": "",
                     "head_hash": "",
                     "sha256": "",
                     "sha1": "",
                     "md5": ""
                 }
             }
         ]
     }
}

operation: Get Report
Input parameters
Parameter	Description
Task ID	UUID of that task whose report you want to retrieve from ANY.RUN. Task ID is generated from an analysis submitted to ANY.RUN.
Output
The output contains the following populated JSON schema:
{
     "error": "",
     "data": {
         "analysis": {
             "uuid": "",
             "permanentUrl": "",
             "reports": {
                 "IOC": "",
                 "MISP": "",
                 "HTML": "",
                 "graph": ""
             },
             "sandbox": {
                 "name": "",
                 "plan": {
                     "name": ""
                 }
             },
             "duration": "",
             "creation": "",
             "creationText": "",
             "tags": [],
             "options": {
                 "timeout": "",
                 "additionalTime": "",
                 "fakeNet": "",
                 "heavyEvasion": "",
                 "mitm": "",
                 "tor": {
                     "used": "",
                     "geo": ""
                 },
                 "presentation": "",
                 "video": "",
                 "hideSource": "",
                 "network": "",
                 "privacy": "",
                 "privateSample": "",
                 "automatization": {
                     "uac": ""
                 }
             },
             "scores": {
                 "verdict": {
                     "score": "",
                     "threatLevel": "",
                     "threatLevelText": ""
                 },
                 "specs": {
                     "injects": "",
                     "autostart": "",
                     "cpuOverrun": "",
                     "crashedApps": "",
                     "crashedTask": "",
                     "debugOutput": "",
                     "executableDropped": "",
                     "exploitable": "",
                     "lowAccess": "",
                     "memOverrun": "",
                     "multiprocessing": "",
                     "networkLoader": "",
                     "networkThreats": "",
                     "rebooted": "",
                     "serviceLauncher": "",
                     "spam": "",
                     "staticDetections": "",
                     "stealing": "",
                     "suspStruct": "",
                     "torUsed": "",
                     "privEscalation": "",
                     "notStarted": ""
                 }
             },
             "content": {
                 "mainObject": {
                     "type": "",
                     "permanentUrl": "",
                     "filename": "",
                     "hashes": {
                         "md5": "",
                         "sha1": "",
                         "sha256": "",
                         "ssdeep": ""
                     },
                     "info": {
                         "ext": "",
                         "file": "",
                         "mime": "",
                         "exif": {
                             "ZIP": {
                                 "ZipRequiredVersion": "",
                                 "ZipBitFlag": "",
                                 "ZipCompression": "",
                                 "ZipModifyDate": "",
                                 "ZipCRC": "",
                                 "ZipCompressedSize": "",
                                 "ZipUncompressedSize": "",
                                 "ZipFileName": ""
                             }
                         },
                         "trid": [
                             {
                                 "procent": "",
                                 "extension": "",
                                 "filetype": ""
                             }
                         ]
                     }
                 },
                 "video": {
                     "present": ""
                 },
                 "pcap": {
                     "present": "",
                     "permanentUrl": ""
                 },
                 "screenshot": [
                     {
                         "uuid": "",
                         "time": "",
                         "permanentUrl": "",
                         "thumbnailUrl": ""
                     }
                 ]
             }
         },
         "environments": {
             "os": {
                 "title": "",
                 "build": "",
                 "product": "",
                 "variant": "",
                 "productType": "",
                 "major": "",
                 "servicePack": "",
                 "softSet": "",
                 "bitness": ""
             },
             "internetExplorer": {
                 "version": "",
                 "kbnum": ""
             },
             "software": [
                 {
                     "title": "",
                     "version": ""
                 }
             ],
             "hotfixes": [
                 {
                     "title": ""
                 }
             ]
         },
         "processes": [
             {
                 "pid": "",
                 "ppid": "",
                 "uuid": "",
                 "image": "",
                 "commandLine": "",
                 "fileName": "",
                 "fileType": "",
                 "mainProcess": "",
                 "times": {
                     "start": "",
                     "monitoringSince": ""
                 },
                 "versionInfo": {
                     "company": "",
                     "description": "",
                     "version": ""
                 },
                 "context": {
                     "rebootNumber": "",
                     "integrityLevel": "",
                     "userName": ""
                 },
                 "scores": {
                     "verdict": {
                         "score": "",
                         "threatLevel": "",
                         "threatLevelText": ""
                     },
                     "monitoringReason": "",
                     "dropped": "",
                     "injected": "",
                     "loadsSusp": "",
                     "specs": {
                         "autoStart": "",
                         "crashedApps": "",
                         "debugOutput": "",
                         "executableDropped": "",
                         "exploitable": "",
                         "injects": "",
                         "knownThreat": "",
                         "lowAccess": "",
                         "network": "",
                         "networkLoader": "",
                         "stealing": "",
                         "privEscalation": ""
                     }
                 },
                 "status": "",
                 "modules": [
                     {
                         "time": "",
                         "image": ""
                     }
                 ]
             }
         ],
         "modified": {
             "files": [
                 {
                     "time": "",
                     "filename": "",
                     "size": "",
                     "type": "",
                     "threatLevel": "",
                     "process": "",
                     "info": {
                         "file": ""
                     },
                     "hashes": {
                         "head_hash": "",
                         "md5": "",
                         "sha1": "",
                         "sha256": "",
                         "ssdeep": ""
                     },
                     "permanentUrl": ""
                 }
             ],
             "registry": [
                 {
                     "key": "",
                     "name": "",
                     "value": "",
                     "operation": "",
                     "process": "",
                     "time": ""
                 }
             ]
         },
         "network": {
             "dnsRequests": [],
             "httpRequests": [],
             "connections": [],
             "threats": []
         },
         "debugStrings": [],
         "incidents": [
             {
                 "threatLevel": "",
                 "title": "",
                 "desc": "",
                 "source": "",
                 "firstSeen": "",
                 "count": "",
                 "mitre": [],
                 "events": [],
                 "process": ""
             }
         ],
         "counters": {
             "processes": {
                 "total": "",
                 "monitored": "",
                 "suspicious": "",
                 "malicious": ""
             },
             "network": {
                 "http": "",
                 "connections": "",
                 "dns": "",
                 "threats": ""
             },
             "files": {
                 "unknown": 3,
                 "text": 1,
                 "suspicious": 0,
                 "malicious": 0
             },
             "registry": {
                 "total": "",
                 "read": "",
                 "write": "",
                 "delete": ""
             }
         },
         "mitre": [
             {
                 "id": "",
                 "phases": [],
                 "name": ""
             }
         ],
         "status": ""
     }
}

operation: Run Analysis
Input parameters
Parameter	Description
Run By	Type of analysis (action) that you want to perform using ANY.RUN. You can choose from the following options: Environment, Options, or Object.
If you choose 'Environment', then you can specify the following parameters:
Operation System: Operation System (OS) on which you want to run the ANY.RUN analysis. By default, this is set to "windows", which is also its allowed value.
Bitness: Bitness of OS on which you want to run the ANY.RUN analysis. By default, this is set to "32". The allowed values are "32" and "64".
ENV Version: Version of OS on which you want to run the ANY.RUN analysis. By default, this is set to "7". The allowed values are "7", "8.1", and "10".
ENV Type: Environment preset type on which you want to run the ANY.RUN analysis. By default, this is set to "Complete". You can choose from the following options: "Clean", "Office", or "Complete"
If you choose 'Options', then you can specify the following parameters:
Network Connection State: State of the network connection on which you want to run the ANY.RUN analysis. By default, this checkbox is selected, i.e., it is set to "true".
FakeNet Feature Status: Status of the FakeNet feature on which you want to run the ANY.RUN analysis. By default, this checkbox is cleared, i.e., it is set to "false".
TOR Using: Option that is set for the TOR Using parameter on which you want to run the ANY.RUN analysis. By default, this checkbox is cleared, i.e., it is set to "false".  
HTTPS MITM Proxy: Option that is set for the HTTPS MITM proxy parameter on which you want to run the ANY.RUN analysis. By default, this checkbox is cleared, i.e., it is set to "false".  
Geo Location: Option that is set for the Geo Location parameter on which you want to run the ANY.RUN analysis. You can choose from the following options: "Fastest", "AU", "BR", "DE", "CH", "FR", "KR", "US", "RU", "GB", or "IT".
Heavy Evasion: Option that is set for the Heavy Evasion parameter on which you want to run the ANY.RUN analysis. By default, this checkbox is cleared, i.e., it is set to "false".  
Privacy Setting: Value that is set for the Privacy Settings parameter on which you want to run the ANY.RUN analysis. By default, this is set to "By Link". You can choose from the following options: "Public", "By Link", or "Owner".
Timeout: Value that is set for the Timeout parameter on which you want to run the ANY.RUN analysis. By default, this is set to "60". You can specify any number between 10-660.
Start Object From: Object from where you want to start the ANY.RUN analysis. By default, this is set to "Temp". You can choose from the following options: "Desktop", "Home", "Downloads", "App Data", "Temp", "Windows", or "Root".
If you choose 'Object', then you can specify the following parameters:
Object Type: Type of new analysis (task) that you want to run on ANY.RUN.By default, this is set to "File". You can choose from the following options: "File", "URL", or "Download".
If you choose 'File', then you can specify the following parameters:
File ID(IRI): ID or IRI value of the file that you want to upload to ANY.RUN for analysis. The file ID or IRI is used to access the file in the FortiSOAR 'Attachments' module.
Execute Command: Optional command line to be run in ANY.RUN. The supported size range is 2-256.
If you choose 'URL', then you can specify the following parameters:
URL: URL that you want to submit to ANY.RUN for analysis. The format that is required is: (http/https)://(your-link)/.  The supported size range is 5-512.
Browser Name: Name of the browser name on which you want to run the ANY.RUN analysis. By default, this is set to "Internet Explorer". You can choose from the following options: "Google Chrome", "Mozilla Firefox", "Opera", "Internet Explorer".
If you choose 'Download', then you can specify the following parameters:
URL: URL that you want to submit to ANY.RUN for analysis. The format that is required is: (http/https)://(your-link)/.  The supported size range is 5-512.
Execute Command: Optional command line to be run in ANY.RUN. The supported size range is 2-256.
User Agent: Optional user agent that you want to specify while running the analysis in ANY.RUN. The supported size range is 2-256.
Hide Source URL: Select this option, i.e., set it to "true" to hide the source URL. By default, this checkbox is cleared, i.e., it is set to "false".
Encounter UAC Prompts: Select this checkbox, i.e., set it to "true" to enable UAC prompts. By default, this checkbox is checked, i.e., it is set to "true".
Change Extension:  Select this checkbox, i.e., set it to "true" to change the extension to "valid". By default, this checkbox is checked, i.e., it is set to "true".
Output
The output contains the following populated JSON schema:
{
     "error": "",
     "data": {
         "taskid": ""
     }
}

Included playbooks
The Sample - ANY.RUN - 1.0.0 playbook collection comes bundled with the ANY.RUN connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the Automation > Playbooks section in FortiSOARTM after importing the ANY.RUN connector.

Get History
Get Report
Run Analysis
Note: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.