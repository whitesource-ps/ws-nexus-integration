import subprocess
import base64
import json
import logging
import os
import re
from configparser import ConfigParser
from distutils.util import strtobool
from multiprocessing import Pool, Manager
from typing import Union, List, Tuple
from urllib.parse import urlparse, urljoin

import docker
import requests
import sys
import platform
import ws_sdk.ws_errors
from ws_sdk import WS, ws_constants

from ws_nexus_integration._version import __version__, __tool_name__

is_debug = logging.DEBUG if bool(os.environ.get("DEBUG", 0)) else logging.INFO
logger = logging.getLogger(__tool_name__)
logger.setLevel(is_debug)
formatter = logging.Formatter('%(levelname)s %(asctime)s %(thread)d %(name)s: %(message)s')
s_handler = logging.StreamHandler()
s_handler.setFormatter(formatter)
logger.addHandler(s_handler)
# logger.propagate = False

SUPPORTED_FORMATS = {'maven2', 'npm', 'pypi', 'rubygems', 'nuget', 'raw', 'docker'}
DOCKER_TIMEOUT = 600
VER_3_26 = ["3", "26"]

config = None


class Config:
    # @dataclass
    # class Config:
    #     nexus_base_url: str
    #     nexus_alt_docker_registry_address: str
    #     nexus_user: str
    #     nexus_password: str
    #     nexus_auth_token: str
    #     nexus_repos: str
    #     headers: dict

    def __init__(self, conf: dict) -> str:
        def convert_to_basic_string(user_name: str, password: str):
            auth_string_plain = f"{user_name}:{password}"
            basic_bytes = base64.b64encode(bytes(auth_string_plain, "utf-8"))
            basic_string = str(basic_bytes)[2:-1]

            return basic_string

        def get_nexus_auth_token(nexus_user: str, nexus_password: str) -> str:
            nexus_auth_token = conf.get('Nexus Settings', 'NexusAuthToken', fallback=None)
            if nexus_auth_token:
                logger.debug(f"Using Nexus authentication token")
            else:
                logger.debug('Converting user and password to basic string')
                try:
                    nexus_auth_token = convert_to_basic_string(nexus_user, nexus_password)
                except KeyError:
                    logger.error("Nexus username or password are missing from the configuration file")
                    sys.exit(1)

            return nexus_auth_token

        def generate_dirs():
            for k, v in self.__dict__.items():
                if k.endswith("_dir") and not os.path.exists(v):
                    logger.debug(f"Directory {v} does not exist and will be created")
                    os.mkdir(v)

        def set_lang_include(includes: str):
            inc_l = includes.split(',') if len(includes) else None
            if inc_l:
                ret_l = []
                for i in inc_l:
                    ret_l += ws_constants.LibMetaData.LangSuffix.__dict__[i]
                self.ws_conn.ua_conf.set_include_suffices_to_scan(ret_l)

        # Nexus Settings
        self.nexus_base_url = conf.get('Nexus Settings', 'NexusBaseUrl', fallback='http://localhost:8081').strip('/')
        self.nexus_alt_docker_registry_address = conf.get('Nexus Settings', 'NexusAltDockerRegistryAddress', fallback=None)
        self.nexus_user = conf.get('Nexus Settings', 'NexusUser', fallback=None)
        self.nexus_password = conf['Nexus Settings']['NexusPassword']
        self.nexus_auth_token = get_nexus_auth_token(self.nexus_user, self.nexus_password)
        self.nexus_repos = conf.get('Nexus Settings', 'NexusRepositories')
        if self.nexus_repos:
            self.defined_nexus_repo_l = [repo.strip() for repo in self.nexus_repos.split(',')]
        self.nexus_exc_repos = conf['Nexus Settings'].get('NexusExcludedRepositories')
        if self.nexus_exc_repos:
            self.nexus_exc_repos_l = [repo.strip() for repo in self.nexus_exc_repos.split(',')]
        else:
            self.nexus_exc_repos_l = []
        self.nexus_docker_repos_images_include = conf.get('Nexus Settings', 'NexusDockerReposImagesIncludes', fallback='.*.*')
        if self.nexus_docker_repos_images_include == '':
            self.nexus_docker_repos_images_include = '.*'
        self.nexus_docker_repos_images_include_l = [repo.strip() for repo in self.nexus_docker_repos_images_include.split(',')]

        self.headers = {'Authorization': f'Basic {self.nexus_auth_token}',
                        'accept': 'application/json'}
        # Mend Settings
        self.product_name = conf.get('Mend Settings', 'WSProductName', fallback='Nexus')
        self.check_policies = conf.getboolean('Mend Settings', 'WSCheckPolicies', fallback=False)
        self.policies = 'true' if self.check_policies else 'false'
        ws_name = f"ws-{__tool_name__.replace('_', '-')}"
        base_dir = conf.get('General Settings', 'WorkDir')
        if not base_dir:
            base_dir = f"c:/tmp/ws-{ws_name}" if sys.platform == "win32" else f"/tmp/{ws_name}"
        self.base_dir = base_dir
        self.is_docker_scan = False
        self.scan_dir = os.path.join(self.base_dir, '_wstemp')
        self.proxyurl = conf.get('General Settings', 'proxyurl', fallback="")
        self.proxyuser = conf.get('General Settings', 'proxyuser', fallback="")
        self.proxypsw = conf.get('General Settings', 'proxypsw', fallback="")
        java_bin = conf.get('General Settings', 'JavaBin', fallback="java")
        self.apikey = conf['Mend Settings']['WSApiKey']
        self.ws_url = conf.get('Mend Settings', 'WSUrl')
        self.ws_conn = WS(user_key=conf['Mend Settings']['WSUserKey'],
                          token=conf['Mend Settings']['WSApiKey'],
                          url=conf.get('Mend Settings', 'WSUrl'),
                          java_bin=java_bin if java_bin else "java",
                          ua_path=self.base_dir,
                          proxy_url=self.proxyurl,
                          tool_details=(f"ps-{__tool_name__.replace('_', '-')}", __version__))
        set_lang_include(conf['Mend Settings'].get('WSLang', "").replace(" ", ""))

        # General Settings
        self.threads_number = conf.getint('General Settings', 'ThreadCount', fallback=5)
        generate_dirs()


def set_nexus_resources_url(full_version: str) -> str:
    ver = full_version.strip("Nexus/ (OSS)").split(".")
    if ver[0] < VER_3_26[0] or (ver[0] == VER_3_26[0] and ver[1] < VER_3_26[1]):
        resources_url = "/service/rest/beta/repositories"
    else:
        resources_url = "/service/rest/v1/repositorySettings"
    logger.debug(f"Using repository: {resources_url}")

    return resources_url


def retrieve_nexus_repositories(conf : None) -> List[str]:
    def get_nexus_ver(nexus_version):
        if nexus_version:
            logger.info(f"Nexus Version: {nexus_version}")
        else:
            logger.warning("Server headers does not contain Nexus version. Assuming >=3.26")
            nexus_version = "3.26"

        return nexus_version

    def get_valid_repositories(repos) -> List[str]:
        valid_repos = []
        for repo in repos:
            repo_format = repo.get("format")
            if repo_format in SUPPORTED_FORMATS:
                repo_name = repo["name"]
                valid_repos.append(repo_name)
            else:
                logger.warning(f"Repository: {repo['name']} is unsupported format: {repo_format}. Skipping")

        return valid_repos

    logger.debug("Sending request for retrieving Nexus repository list")
    repositories, resp_headers = call_nexus_api("/service/rest/v1/repositories", include_resp_headers=True, conf=conf)
    try:
        config.nexus_version = get_nexus_ver(resp_headers.get('Server'))
        existing_nexus_repository_list = get_valid_repositories(repositories)
    except:
        config.nexus_version = ""
        existing_nexus_repository_list = []
    return existing_nexus_repository_list


def get_items_from_repo(repo_name: str, conf) -> List[dict]:
    logger.info(f'Handling repository: {repo_name}')
    repo_comp_url = f'/service/rest/v1/components?repository={repo_name}'

    all_repo_items = []
    continuation_token = None

    while True:
        cur_repo_comp_url = repo_comp_url
        if continuation_token is not None:
            cur_repo_comp_url += f"&continuationToken={continuation_token}"
        cur_comp_resp = call_nexus_api(cur_repo_comp_url, conf=conf)
        continuation_token = None

        if isinstance(cur_comp_resp, dict):  # TODO: RECONSIDER REMOVING AS THIS SHOULDN'T HAPPEN
            all_repo_items.extend(cur_comp_resp.get('items', []))
            continuation_token = cur_comp_resp.get('continuationToken')

        if continuation_token is None:
            break

    logger.debug(f"Found {len(all_repo_items)} items in repository: '{repo_name}'")

    return all_repo_items


def scan_components_from_repositories(selected_repos, conf):
    for repo_name in selected_repos:
        all_repo_items = get_items_from_repo(repo_name, conf)

        if not all_repo_items:
            logger.debug(f'No artifacts found in {repo_name}')
        else:
            logger.debug(f'Found {len(all_repo_items)} artifacts in {repo_name}')
            logger.info('Retrieving artifacts...')

            manager = Manager()
            docker_images_q = manager.Queue()
            with Pool(config.threads_number) as pool:
                cur_dest_folder = None
                artifacts_to_scan = pool.starmap(repo_worker, [(comp, repo_name, cur_dest_folder, config.headers, config, docker_images_q)
                                                               for i, comp in enumerate(all_repo_items)])

            if len(artifacts_to_scan) > 0 and os.path.exists(os.path.join(config.scan_dir, repo_name)):
                execute_scan(config, repo_name)


def call_nexus_api(url: str,
                   headers: dict = None,
                   include_resp_headers: bool = False,
                   method: str = "get",
                   conf = None,
                   **kwargs) -> Union[dict, bytes, Tuple[List[dict], dict]]:
    if headers is None:
        headers = config.headers

    if not url.startswith("http"):
        url = urljoin(config.nexus_base_url, url)

    logger.info(f"Calling Nexus URL: {url}")
    try:
        if conf:
            is_https = "https://" in conf.proxyurl
            proxy_ = conf.proxyurl.replace("https://", "").replace("http://", "")
            if "@" not in proxy_ and conf.proxyuser and conf.proxypsw:
                proxy_ = f"{conf.proxyuser}:{conf.proxypsw}@" + proxy_
            proxy = proxy_ if conf.proxyurl else ""
            if is_https:
                proxies = {"https": f"https://{proxy}"} if proxy else {}
            else:
                proxies = {"http": f"http://{proxy}"} if proxy else {}
        else:
            proxies = {}
        try:
            resp = requests.request(method=method, url=url, proxies=proxies, headers=headers,
                                    verify=not bool(proxies),  **kwargs)
            if 400 <= resp.status_code < 500:
                if isinstance(resp.reason, bytes):
                    try:
                        reason = resp.reason.decode("utf-8")
                    except UnicodeDecodeError:
                        reason = resp.reason.decode("iso-8859-1")
                else:
                    reason = resp.reason
                logger.error(f"The request for getting repos failed. Reason: {reason}.Check credentials (Nexus token or pair username/password)")
                sys.exit(-1)
            resp.raise_for_status()
        except Exception as err:
            try:
                proxy_ = proxies["http"]
            except:
                try:
                    proxy_ = proxies["https"]
                except:
                    proxy_ = ""
            if proxy_:
                curl_command = [
                    'curl',
                    '--proxy', f'{proxy_}',
                    '--insecure',
                    url
                ]
            else:
                curl_command = [
                    'curl',
                    '--insecure',
                    url
                ]
            try:
                resp = subprocess.run(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except:
                logger.error(f"Received Error on endpoint: {url}")
    except requests.exceptions.RequestException:
        logging.exception(f"Received Error on endpoint: {url}")
        raise

    try:
        ret = json.loads(resp.text)
    except:
        try:
            ret = json.loads(resp.stdout)
        except Exception as err: #json.decoder.JSONDecodeError:
            logger.debug("Response is not JSON")
            try:
                ret = resp.content
            except:
                ret = None
        #else:
        #    ret = None
    logger.debug(f"Response return type: {type(ret)}")

    if include_resp_headers:
        try:
            ret = ret, resp.headers
        except:
            ret = ret, None

    return ret


def handle_docker_repo(component: dict, conf) -> tuple:
    """
    Locally pull Docker Image from a given repository (component)
    :param component:
    :param conf: global config
    :return: Retrieve Docker Image ID so UA will only scan images downloaded from Nexus
    """

    def get_repos_as_dict(c) -> dict:
        """
        Convert repository data into dictionary
        :returns name -> repo dictionary
        :rtype: dict
        """
        repos_list = call_nexus_api(conf.nexus_base_url + conf.resources_url, c.headers, conf=conf)
        logger.debug(f"found {len(repos_list)} repositories")
        repo_dict = {}
        for r in repos_list:
            repo_dict[r['name']] = r

        return repo_dict

    def pull_docker_image(image_name, docker_url, uname, upsw):
        try:
            login_command = ["docker", "login", docker_url, "-u", uname, "-p", upsw]
            subprocess.run(login_command, check=True)
            pull_command = f'docker pull {docker_url}/{image_name}'
            subprocess.run(pull_command, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error: Failed to pull image {image_name}. Exit code {e.returncode}")
        except Exception as e:
            logger.error(f"Error: {e}")

    def get_docker_repo_url(repository: dict) -> str:
        """
        Retrieves Repository URL with port
        :param repository:
        :return: Image ID in form of string
        """

        https_port = repository['docker'].get('httpsPort')
        http_port = repository['docker']['httpPort']
        parsed_url = urlparse(repository['url'])
        if http_port:
            r_url = f"{parsed_url.hostname}:{http_port}"
        elif https_port:
            r_url = f"{parsed_url.hostname}:{https_port}"
        else:
            logger.error("Unable to get repository port. Using default URL")
            r_url = f"{parsed_url.hostname}:{parsed_url.port}"
        logger.debug(f"Returned docker repo URL: {r_url}")

        return r_url

    image_full_name = None
    is_image_exists_locally = None
    ret = None
    dl_url = component['assets'][0]["downloadUrl"]
    logger.debug(f"Component repository: {component['repository']}")
    logger.debug(f"Getting manifest file from: {dl_url}")
    manifest = call_nexus_api(dl_url, conf.headers, conf=conf)
    repos = get_repos_as_dict(conf)

    repo = repos.get(component['repository'])

    if conf.nexus_alt_docker_registry_address:
        docker_repo_url = conf.nexus_alt_docker_registry_address
        logger.info(f"Using user-defined docker registry URL: {docker_repo_url}")
    elif repo:
        logger.debug(f"Repository data: {repo}")
        docker_repo_url = get_docker_repo_url(repo)

    if docker_repo_url:
        image_name = f"{docker_repo_url}/{manifest['name']}"
        image_full_name = f"{image_name}:{manifest['tag']}"

        temp = '(?:% s)' % '|'.join(conf.nexus_docker_repos_images_include_l)
        if re.match(temp, image_full_name):
            logger.info(f"Pulling Docker image: {image_full_name}")
            try:
                if conf:
                    is_https = "https://" in conf.proxyurl
                    proxy_ = conf.proxyurl.replace("https://", "").replace("http://", "")
                    if "@" not in proxy_ and conf.proxyuser and conf.proxypsw:
                        proxy_ = f"{conf.proxyuser}:{conf.proxypsw}@" + proxy_
                    proxy = proxy_ if conf.proxyurl else ""
                else:
                    proxy = ""
                if proxy:
                    if is_https:
                        os.environ['HTTPS_PROXY'] = f"https://{proxy}"
                    else:
                        os.environ['HTTP_PROXY'] = f"http://{proxy}"

                os.environ['DOCKER_CLIENT_DEBUG'] = '1'
                docker_client = docker.from_env(timeout=DOCKER_TIMEOUT)
                local_image = docker_client.images.list(image_full_name)
                is_image_exists_locally = True if local_image.__len__() == 1 else False

                # Configuring Nexus user and password are mandatory for non-anonymous Docker repositories
                try:
                    docker_client.login(username=conf.nexus_user, password=conf.nexus_password, registry=docker_repo_url)
                    pull_res = docker_client.images.pull(image_full_name)
                    logger.debug(f"Image ID: {image_full_name} successfully pulled")
                except Exception as err:
                    if install_docker(proxy=proxy if proxy else None) != -100:
                        pull_docker_image(image_full_name, docker_repo_url, conf.nexus_user, conf.nexus_password)
                        logger.debug(f"Image ID: {image_full_name} successfully pulled")
                    else:
                        logging.exception(f"Error loading image: {image_full_name}")

                ret = f"{image_name} {manifest['tag']}"  # removing : operator in favour of docker.includeSingleScan

            except docker.errors.DockerException:
                logging.exception(f"Error loading image: {image_full_name}")
    else:
        logger.warning(f"Repository was not found for {component['repository']}. Skipping")

    return ret, is_image_exists_locally, image_full_name


def install_docker(proxy = None):
    def check_docker_installed():
        try:
            return subprocess.run(['docker', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).returncode == 0
        except Exception as e:
            logger.error(f"Error:{e}")
            return False

    result = -100
    try:
        # Detect the operating system
        system = platform.system()
        if not check_docker_installed():
            if system == "Linux":
                # Run the installation command for Docker on Linux
                if proxy:
                    install_command = f"curl -fsSL https://get.docker.com -o get-docker.sh --proxy {proxy} --insecure && sudo sh get-docker.sh"
                else:
                    install_command = "curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh"
                result = subprocess.run(install_command, shell=True, check=True).returncode
            elif system == "Windows":
                # Run the installation command for Docker on Windows
                if proxy:
                    install_command = f"Invoke-WebRequest -UseBasicParsing -Uri https://desktop.docker.com/win/stable/Docker%20Desktop%20Installer.exe -OutFile DockerInstaller.exe -Proxy {proxy}; Start-Process -Wait -FilePath .\DockerInstaller.exe"
                else:
                    install_command = f"Invoke-WebRequest -UseBasicParsing -Uri https://desktop.docker.com/win/stable/Docker%20Desktop%20Installer.exe -OutFile DockerInstaller.exe ; Start-Process -Wait -FilePath .\DockerInstaller.exe"
                result = subprocess.run(["powershell", "-Command", install_command], check=True).returncode
            else:
                logger.warning("Unsupported operating system: ", system)
                return result

            logger.info("Docker has been installed successfully.")
        else:
            logger.info("Docker has been installed successfully already.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error: Docker installation failed with exit code {e.returncode}.")
    except Exception as e:
        logger.error(f"Error: {e}")
    return result


def repo_worker(comp, repo_name, cur_dest_folder, headers, conf, d_images_q):
    all_components = []
    component_assets = comp['assets']
    logger.debug(f"Handling component ID: {comp['id']} on repository: {comp['repository']} Format: {comp['format']}")
    if comp['format'] == 'nuget':
        cur_dest_folder = os.path.join(conf.scan_dir, repo_name)

        comp_name = '{}.{}.nupkg'.format(comp['name'], comp['version'])
        all_components.append(comp_name)
    elif re.match('(maven).*', comp['format']):
        cur_dest_folder = os.path.join(conf.scan_dir, repo_name)

        component_assets_size = len(component_assets)
        for asset in range(0, component_assets_size):
            comp_name = component_assets[asset]['path'].rpartition('/')[-1]
            if comp_name.split(".")[-1] == "jar":
                all_components.append(comp_name)
    elif comp['format'] == 'docker':
        image_id, is_image_exists_locally, image_full_name = handle_docker_repo(comp, conf)
        if image_id:
            d_images_q.put(image_id)
            conf.is_docker_scan = True
            conf.ws_conn.ua_conf.docker_includeSingleScan = image_id
            execute_scan(conf, repo_name)
            if is_image_exists_locally:
                logger.info(f"{image_full_name} already exists locally prior to the scan - won't be removed")
            else:
                if conf:
                    is_https = "https://" in conf.proxyurl
                    proxy_ = conf.proxyurl.replace("https://", "").replace("http://", "")
                    if "@" not in proxy_ and conf.proxyuser and conf.proxypsw:
                        proxy_ = f"{conf.proxyuser}:{conf.proxypsw}@" + proxy_
                    proxy = proxy_ if conf.proxyurl else ""
                else:
                    proxy = ""
                if proxy:
                    if is_https:
                        os.environ['HTTPS_PROXY'] = f"https://{proxy}"
                    else:
                        os.environ['HTTP_PROXY'] = f"http://{proxy}"
                docker_c = docker.from_env(timeout=DOCKER_TIMEOUT)
                docker_c.images.remove(image=image_full_name, force=True)
                logger.info(f"{image_full_name} image was scanned successfully and will be removed from the local environment")

    else:
        comp_name = component_assets[0]['path'].rpartition('/')[-1]
        cur_dest_folder = os.path.join(conf.scan_dir, repo_name)

        all_components.append(comp_name)

    for comp_name in all_components:
        comp_worker(repo_name, component_assets, cur_dest_folder, headers, comp_name, conf)
    return all_components


def comp_worker(repo_name, component_assets, cur_dest_folder, headers, comp_name, conf = None):
    logger.info(f"Downloading '{comp_name}' component from: '{repo_name}' to {cur_dest_folder}")
    comp_download_url = component_assets[0]["downloadUrl"]
    comp_data = call_nexus_api(comp_download_url, headers, conf=conf)
    logger.debug(f"Download URL: {comp_download_url}")
    os.makedirs(cur_dest_folder, exist_ok=True)

    with open(os.path.join(cur_dest_folder, comp_name), 'wb' if isinstance(comp_data, bytes) else 'w') as f:
        if isinstance(comp_data, dict):
            json.dump(comp_data, f)
        else:
            f.write(comp_data)
    logger.info(f'Component {comp_name} has successfully downloaded')


def execute_scan(config, repo_name) -> int:
    config.ws_conn.ua_conf.productName = config.product_name
    config.ws_conn.ua_conf.checkPolicies = strtobool(config.policies)
    config.ws_conn.ua_conf.forceCheckAllDependencies = strtobool(config.policies)
    config.ws_conn.ua_conf.offline = True if os.environ.get("OFFLINE", "").lower() == "true" else False

    if config.is_docker_scan:
        config.ws_conn.ua_conf.resolveAllDependencies = True
        config.ws_conn.ua_conf.archiveExtractionDepth = 3
        config.ws_conn.ua_conf.archiveIncludes = list(ws_constants.UAArchiveFiles.ALL_ARCHIVE_FILES)
        ret = config.ws_conn.scan_docker(product_name=config.product_name)
    else:
        # config.ws_conn.ua_conf.projectPerFolder = True
        ret = config.ws_conn.scan(scan_dir=os.path.join(config.scan_dir, repo_name),
                                  product_name=config.product_name, project_name=repo_name)
    logger.debug(f"Unified Agent standard output:\n {ret[1]}")
    try:
        app_status = get_scan_result_by_curl(config.ws_conn, ret[2])
        #config.ws_conn.get_last_scan_process_status(ret[2])
    except ws_sdk.ws_errors.WsSdkServerInsufficientPermissions:
        logger.debug("Insufficient permissions to execute call")
    except Exception as err:
        pass
    return ret[0]


def get_repos_to_scan() -> List[str]:
    all_repos = retrieve_nexus_repositories(conf=config)
    logger.debug(f"The following repositories were found: {all_repos}")
    repos_to_scan = []
    if config.nexus_repos:
        for defined_repo in config.defined_nexus_repo_l:
            if defined_repo in all_repos:
                repos_to_scan.append(defined_repo)
                logger.debug(f"Repository: '{defined_repo}' was added to scan")
            else:
                logger.error(f"User defined repository: '{defined_repo}' was not found in Nexus and will be skipped")
        if not repos_to_scan:
            logger.error("No configured repositories were found in Nexus. Nothing to scan.")
            exit(-1)
    else:
        repos_to_scan = all_repos

    if config.nexus_exc_repos:
        logger.info(f"Repositories: {config.nexus_exc_repos_l} are excluded from the scan")
        repos_to_scan = [repo for repo in repos_to_scan if repo not in config.nexus_exc_repos_l]

    logger.info(f'The following repositories will be scanned: {repos_to_scan}')

    return repos_to_scan


def read_conf_file(conf_file: str) -> ConfigParser:
    if os.path.isfile(conf_file):
        logger.debug(f"Using configuration file: '{conf_file}'")
        c = ConfigParser()
        c.optionxform = str
        c.read(conf_file)
        return c
    else:
        print("""Missing configuration file. Be sure to create params.config file with the following values:\"
[Nexus Settings]
NexusBaseUrl=
NexusAuthToken=
NexusUser=
NexusPassword=
NexusRepositories=
NexusExcludedRepositories=
NexusAltDockerRegistryAddress=


[Mend Settings]
WSUserKey=
WSApiKey=
WSProductName=Nexus
WSCheckPolicies=False
WSUrl=
WSLang=

[General Settings]
ThreadCount=1
WorkDir=
JavaBin=
                    """)
        exit(-1)


def get_scan_result_by_curl(conn, request_token):
    proxies = conn.proxies
    try:
        proxy_ = proxies["http"]
    except:
        try:
            proxy_ = proxies["https"]
        except:
            proxy_ = ""

    curl_command = [
            'curl',
            conn.api_url,
            '--header', 'Content-Type: application/json',
            '--data', '{"requestType": "getRequestState", '
                      '"orgToken": "'+config.apikey+'", '
                                                    '"userKey": "'+conn.user_key+'","requestToken": "'+request_token+'"}',
            '--proxy', proxy_,
            '--insecure',
        ]
    try:
        rs = subprocess.run(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return json.loads(rs.stdout)["requestState"]
    except:
        return "UNKNOWN"


def main():
    global config
    conf_file = 'params.config'
    if len(sys.argv) > 1:
        conf_file = sys.argv[1]
    params_f = read_conf_file(conf_file)
    config = Config(params_f)

    #res = get_scan_result_by_curl(config.ws_conn, "jksdfhjsfdhjsd")
    '''
    rs_1 = config.ws_conn.call_ws_api(request_type="getOrganizationProjectVitals",
                kv_dict={"orgToken": config.apikey})
    curl_command = [
        'curl',
        'https://app-eu.whitesourcesoftware.com/api/v1.3',
        '--header', 'Content-Type: application/json',
        '--data', '{"requestType": "getOrganizationProjectVitals", "orgToken": "'+config.apikey+'"}',
        '--proxy', config.proxyurl,
        '--insecure',
        #'--data', '{"requestType": "getProjectAlertsByType", "userKey": "c67a40509d8843a98fb4e16c94d3dfb5bdbfde598edd4f508b7eca6396039aa1",'
        #          '"alertType": "SECURITY_VULNERABILITY", "projectToken": "d1fbbc267d8543c59a9d16b745e79bd2b5678f6bb3d5425088c4f1c0ecc6b52d",'
        #'"fromDate": "2023-05-08", "toDate": "2023-05-09"}'
    ]
    rs = subprocess.run(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, shell=True)
    '''
    selected_repositories = get_repos_to_scan()
    config.resources_url = set_nexus_resources_url(config.nexus_version)
    scan_components_from_repositories(selected_repositories, config)


if __name__ == '__main__':
    main()
