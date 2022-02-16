[![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)](https://www.whitesourcesoftware.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/v/release/whitesource-ps/whitesource-nexus-integration)](https://github.com/whitesource-ps/whitesource-nexus-integration/releases/latest)
[![WS Nexus Integration Build and Publish](https://github.com/whitesource-ps/whitesource-nexus-integration/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/whitesource-nexus-integration/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)
[![PyPI](https://img.shields.io/pypi/v/ws-nexus-integration?style=plastic)](https://pypi.org/project/ws-nexus-integration/)

# [WhiteSource for Nexus](https://github.com/whitesource-ps/ws-nexus-integration)
**ws-nexus-integration** is a command line tool to scan Nexus repositories.  
This tool can be deployed either on the Nexus host or on a separate machine that has access to the Nexus instance.
Supported formats: `maven2`, `npm`, `pypi`, `rubygems`, `nuget`, `docker` and `raw`.

### Prerequisites
- Nexus Repository Manager 3.x (any edition)
- Java VM > 8
- Docker
- Python 3.7 or above

## Install and utilization from PyPi (simplest)
1. Install ws-nexus-integration: `pip install ws-nexus-integration` 
 * Note: to scan Docker repository on the Nexus execute: `pip install ws-nexus-integration[DOCKER]`
2. Download and edit _params.config_ (available on git)
3. Execute `ws_nexus_integration <path/to/params.config>`

### Configuration Parameters
```
===================================================================================================================
| Group                | Parameter         | Description                                                          |
===================================================================================================================
| Nexus Settings       | NexusBaseUrl      | Nexus instance base URL (Default: http://localhost:8081)             |
-------------------------------------------------------------------------------------------------------------------
| Nexus Settings       | NexusAuthToken    | Nexus auth token (base64 encoded)                                    |
-------------------------------------------------------------------------------------------------------------------
| Nexus Settings       | NexusUser         | Nexus username. Required if NexusAuthToken is not specified          |
-------------------------------------------------------------------------------------------------------------------
| Nexus Settings       | NexusPassword     | Nexus password. Required if NexusAuthToken is not specified          |
-------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------
| Nexus Settings       | NexusAltDocker    | Allow specifying specific registry URL (host:port) to download docker|
|                      | RegistryAddress   | images (i.e, when registry is under NAT due to Nexus K8S deployment).|
===================================================================================================================
| WhiteSource Settings | WSApiKey          | WhiteSource API Key, can be found under the 'Integrate' tab in your  |
|                      |                   | WhiteSource organization.                                            |
-------------------------------------------------------------------------------------------------------------------
| WhiteSource Settings | WSProductName     | The WhiteSource product that will aggregate all scanned repositories.|
-------------------------------------------------------------------------------------------------------------------
| WhiteSource Settings | WSCheckPolicies   | Whether to enable WhiteSource policy check for scanned repositories. |
-------------------------------------------------------------------------------------------------------------------
| WhiteSource Settings | WSLang            | (Optional) allow passing a comma seperated list of suffices of       |
|                      |                   | artifacts to scan in Docker (default: empty).                        |
-------------------------------------------------------------------------------------------------------------------
| WhiteSource Settings | WSUrl             | WhiteSource server URL, can be found under the 'Integrate' tab in    |
|                      |                   | your WhiteSource organization.                                       |
===================================================================================================================
| General Settings     | NexusRepositories | Comma-separated list of repository names to scan.                    |
|                      |                   |                                                                      |
-------------------------------------------------------------------------------------------------------------------
| General Settings     | NexusExcludedRepos| Comma-separated list of repository names to excluded from scan.      |
|                      | itories           |                                                                      |
-------------------------------------------------------------------------------------------------------------------
| General Settings     | ThreadCount       | Multi-threading speeds up the scan preperation phase, but it depends |
|                      |                   | on your environment capabilities (default: 5).                       |
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
| -4   | CONNECTION_FAILURE | WhiteSource agent failed to connect to the application server.    |
-------------------------------------------------------------------------------------------------
| -5   | SERVER_FAILURE     | WhiteSource scan server side error                                |
=================================================================================================
```
