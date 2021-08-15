![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/whitesource-nexus-integration)](https://github.com/whitesource-ps/whitesource-nexus-integration/releases/latest) 
[![WS Nexus Integration Build and Publish](https://github.com/whitesource-ps/whitesource-nexus-integration/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/whitesource-nexus-integration/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)

# [WhiteSource for Nexus](https://github.com/whitesource-ps/ws-nexus-integration)
**ws-nexus** is a command line tool for scanning Nexus repositories.  
This tool can be deployed either on the Nexus host or on a separate machine that has access to the Nexus instance.
Supported formats: `maven2`, `npm`, `pypi`, `rubygems`, `nuget`, `docker` and `raw`.

### Prerequisites
- Nexus Repository Manager 3.x (any edition)
- Java VM > 8 
- Docker
- Python 3.5 or above

### Deployment
1. On the target machine, create a new directory (e.g. ws-nexus) and extract **ws-nexus.zip** to that directory.
2. From the command line, navigate to the ws-nexus directory and install the package:  
   `pip install -r requirements.txt`
3. Edit the **params.config** file and update the relevant parameters (see the configuration parameters below)

### Execution
From the command line, execute the command:  
`python ws-scan.py`

**Note:** If more than one version of Python is installed on the target machine, use the appropriate executables
for the installation and the execution (`pip3` and `python3` respectively)

### Configuration Parameters
```
===================================================================================================================
| Group                | Parameter         | Description                                                          |
===================================================================================================================
| Nexus Settings       | NexusBaseUrl      | Nexus instance base URL (Default: http://localhost:8081)             |
-------------------------------------------------------------------------------------------------------------------
| Nexus Settings       | NexusAuthToken    | Nexus auth token (base64 encoded)                                    |
-------------------------------------------------------------------------------------------------------------------
| Nexus Settings       | NexusUser         | Nexus username. Required if NexusAuthToken not specified             |
-------------------------------------------------------------------------------------------------------------------
| Nexus Settings       | NexusPassword     | Nexus password. Required if NexusAuthToken not specified             |
-------------------------------------------------------------------------------------------------------------------
| Nexus Settings       | InteractiveMode   | When set to True, a list of repository names will be displayed and   |
|                      |                   | you will be prompted to select the ones you wish to scan             |
-------------------------------------------------------------------------------------------------------------------
| Nexus Settings       | NexusAltDocker    | Allow specifying sepcific registry URL (host:port) to download docker|
|                      | RegistryAddress   | images (i.e when registry is under NAT due to Nexus K8S deployment)  |
===================================================================================================================
| WhiteSource Settings | WSApiKey          | WhiteSource API Key. Can be found under the 'Integrate' tab in your  |
|                      |                   | WhiteSource organization.                                            |
-------------------------------------------------------------------------------------------------------------------
| WhiteSource Settings | WSProductName     | The WhiteSource product that will aggregate all scanned repositories |
-------------------------------------------------------------------------------------------------------------------
| WhiteSource Settings | WSCheckPolicies   | Whether to enable WhiteSource policy check for scanned repositories  |
-------------------------------------------------------------------------------------------------------------------
| WhiteSource Settings | WSUrl             | WhiteSource server URL. Can be found under the 'Integrate' tab in    |
|                      |                   | your WhiteSource organization.                                       |
===================================================================================================================
| General Settings     | NexusRepositories | Comma-separated list of repository names to scan.                    |
|                      |                   | If empty and InteractiveMode=False, all repositories will be scanned |
-------------------------------------------------------------------------------------------------------------------
| General Settings     | ThreadCount       | Multi-threading speeds up the scan preperation phase, but it depends |
|                      |                   | on your environment capabilities  (Default: 5)                       |
===================================================================================================================
```

### Exit Codes
```
=================================================================================================
| Code | Message            | Description                                                       |
=================================================================================================
|  0   | SUCCESS            |                                                                   |
-------------------------------------------------------------------------------------------------
|  1   | FAILED             | Prerequisites, configuration or general errors                    |
-------------------------------------------------------------------------------------------------
| -1   | ERROR              | WhiteSource scan general error                                    |
-------------------------------------------------------------------------------------------------
| -2   | POLICY_VIOLATION   | WhiteSource policy violation                                      |
-------------------------------------------------------------------------------------------------
| -3   | CLIENT_FAILURE     | WhiteSource scan client side error                                |
-------------------------------------------------------------------------------------------------
| -4   | CONNECTION_FAILURE | WhiteSource agent was failed to connect to the application server |
-------------------------------------------------------------------------------------------------
| -5   | SERVER_FAILURE     | WhiteSource scan server side error                                |
=================================================================================================
```

### Author
WhiteSource Software ©
