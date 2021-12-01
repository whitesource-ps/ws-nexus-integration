#!/usr/bin/env python3
import base64
import json
import logging
import os
import re
import subprocess
import sys
from configparser import ConfigParser
from multiprocessing import Pool, Manager
from typing import Union
from urllib.parse import urlparse
from ws_nexus_integration._version import __version__, __tool_name__
import requests


# constants
UA_NAME = 'wss-unified-agent'
UA_JAR_NAME = UA_NAME + '.jar'
UA_CONFIG_NAME = UA_NAME + '.config'
URL_UA_JAR = 'https://unified-agent.s3.amazonaws.com/wss-unified-agent.jar'
URL_UA_CONFIG = "https://unified-agent.s3.amazonaws.com/wss-unified-agent.config"
SAAS_URL = 'https://saas.whitesourcesoftware.com/agent'
SAAS_EU_URL = 'https://saas-eu.whitesourcesoftware.com/agent'
APP_URL = 'https://app.whitesourcesoftware.com/agent'
APP_EU_URL = 'https://app-eu.whitesourcesoftware.com/agent'
SUPPORTED_FORMATS = {'maven2', 'npm', 'pypi', 'rubygems', 'nuget', 'raw', 'docker'}
DOCKER_TIMEOUT = 600
VER_3_26 = ["3", "26"]
UA_OFFLINE_MODE = 'true' if os.environ.get("OFFLINE") else 'false'

config = None

logger = logging.getLogger(__name__)
logger.setLevel(level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO)
sysout_handler = logging.StreamHandler(stream=sys.stdout)
sysout_handler.setFormatter(logging.Formatter(fmt='%(levelname)s %(asctime)s %(process)s: %(message)s',
                                              datefmt='%y-%m-%d %H:%M:%S'))
logger.addHandler(sysout_handler)


class Configuration:
    def __init__(self, conf_file) -> str:
        def convert_to_basic_string(user_name: str, password:str):
            """
            Encode username and password per RFC 7617
            :param user_name:
            :param password:
            :return:
            """
            auth_string_plain = f"{user_name}:{password}"
            basic_bytes = base64.b64encode(bytes(auth_string_plain, "utf-8"))
            basic_string = str(basic_bytes)[2:-1]

            return basic_string

        def get_nexus_auth_token(nexus_user: str, nexus_password: str) -> str:
            nexus_auth_token = conf.get('Nexus Settings', 'NexusAuthToken')
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

        conf = ConfigParser()
        conf.optionxform = str
        conf.read(conf_file)
        # Nexus Settings
        self.nexus_base_url = conf.get('Nexus Settings', 'NexusBaseUrl', fallback='http://localhost:8081').strip('/')
        self.nexus_alt_docker_registry_address = conf.get('Nexus Settings', 'NexusAltDockerRegistryAddress', fallback=None)
        self.nexus_user = conf['Nexus Settings']['NexusUser']
        self.nexus_password = conf['Nexus Settings']['NexusPassword']
        self.nexus_auth_token = get_nexus_auth_token(self.nexus_user, self.nexus_password)
        self.nexus_config_input_repositories = conf.get('Nexus Settings', 'NexusRepositories')
        self.nexus_ip = self.nexus_base_url.split('//')[1].split(':')[0]
        self.headers = {'Authorization': f'Basic {self.nexus_auth_token}',
                        'accept': 'application/json'}
        # WhiteSource Settings
        self.user_key = conf['WhiteSource Settings']['WSUserKey']
        self.api_key = conf['WhiteSource Settings']['WSApiKey']
        self.product_name = conf.get('WhiteSource Settings', 'WSProductName', fallback='Nexus')
        self.check_policies = conf.getboolean('WhiteSource Settings', 'WSCheckPolicies', fallback=False)
        self.policies = 'true' if self.check_policies else 'false'
        self.ws_url = conf.get('WhiteSource Settings', 'WSUrl', fallback=SAAS_URL)
        if not self.ws_url.endswith('/agent'):
            self.ws_url = self.ws_url + '/agent'
        # General Settings
        self.interactive_mode = conf.getboolean('General Settings', 'InteractiveMode', fallback=False)
        self.threads_number = conf.getint('General Settings', 'ThreadCount', fallback=5)
        ws_name = f"ws-{__tool_name__.replace('_', '-')}"
        self.base_dir = conf.get('General Settings', 'WorkDir', fallback=f"c:/tmp/ws-{ws_name}" if sys.platform == "win32" else f"/tmp/{ws_name}")
        self.log_dir = os.path.join(self.base_dir, 'logs')
        self.scan_dir = os.path.join(self.base_dir, '_wstemp')
        self.log_file_with_path = os.path.join(self.log_dir, f"{ws_name}.log")
        self.ws_log_dir = os.path.join(self.base_dir, 'whitesource')
        self.ua_dir = os.path.join(self.base_dir, 'ua')
        self.ws_env_var = {**os.environ, **{'WS_USERKEY': self.user_key,
                                            'WS_APIKEY': self.api_key,
                                            'WS_PROJECTPERFOLDER': 'true',
                                            'WS_PRODUCTNAME': self.product_name,
                                            'WS_WSS_URL': self.ws_url,
                                            'WS_INCLUDES': '**/*.*',
                                            'WS_CHECKPOLICIES': self.policies,
                                            'WS_FORCECHECKALLDEPENDENCIES': self.policies,
                                            'WS_OFFLINE': UA_OFFLINE_MODE,
                                            'WS_SCANCOMMENT': f"agent:ps-{__tool_name__.replace('_','-')};agentVersion:{__version__}"}
                           }
        generate_dirs()
        # file logging
        logger.addHandler(logging.FileHandler(self.log_file_with_path))


def set_resources_url(full_version: str):
    ver = full_version.strip("Nexus/ (OSS)").split(".")
    if ver[0] < VER_3_26[0] or (ver[0] == VER_3_26[0] and ver[1] < VER_3_26[1]):
        config.resources_url = "/service/rest/beta/repositories"
    else:
        config.resources_url = "/service/rest/v1/repositorySettings"
    logger.debug(f"Using repository: {config.resources_url}")


def print_header(hdr_txt: str):
    hdr_txt = ' {0} '.format(hdr_txt)
    hdr = '\n{0}\n{1}\n{0}'.format(('=' * len(hdr_txt)), hdr_txt)
    print(hdr)


def define_nexus_parameters():
    global config
    """
    Build Nexus URLs according to configuration

    :return: URLs for repositories and components endpoints
    """
    logger.info('Getting region parameters')
    nexus_api_url = config.nexus_base_url + '/service/rest/v1'
    nexus_api_url_repos = nexus_api_url + '/repositories'
    nexus_api_url_components = nexus_api_url + '/components'

    return nexus_api_url_repos, nexus_api_url_components


def retrieve_nexus_repositories(nexus_api_url_repos):
    """
    Retrieves the list of repositories from Nexus
    :param nexus_api_url_repos:
    :return:
    """
    logger.info("Sending request for retrieving Nexus repository list")
    try:
        response_repository_headers = requests.get(nexus_api_url_repos, headers=config.headers)
        json_response_repository_headers = json.loads(response_repository_headers.text)
    except requests.RequestException:
        logger.info("Failed to retrieve Nexus repositories. Verify Nexus URL and credentials and try again.")
        sys.exit(1)

    logger.debug(f" Nexus Headers: {response_repository_headers.headers}")
    config.nexus_version = response_repository_headers.headers.get('Server')
    if config.nexus_version:
        logger.info(f"Nexus Version: {config.nexus_version}")
    else:
        logger.warning("Server headers does not contain Nexus version. Assuming >=3.26")
        config.nexus_version = "3.26"

    existing_nexus_repository_list = []
    for json_repository in json_response_repository_headers:
        repo_format = json_repository.get("format")
        if repo_format in SUPPORTED_FORMATS:
            rep_name = json_repository["name"]
            existing_nexus_repository_list.append(rep_name)
        else:
            logger.warning(f"Repository: {json_repository['name']} is unsupported format: {repo_format}. Skipping")

    return existing_nexus_repository_list


def validate_selected_repositories(nexus_input_repositories, existing_nexus_repository_list):
    """
    Validate selected repositories when running in configMode=False, mostly for testing

    :param nexus_input_repositories:
    :param existing_nexus_repository_list:
    :return:
    """
    try:
        selected_repositories = [existing_nexus_repository_list[int(n)] for n in nexus_input_repositories]
    except Exception:
        # ToDo - After adding input validation to nexus_user_input_repositories (under main() function),
        #        this validation can be removed
        logger.error("There are no such repositories in your Nexus environment, please select the number from the list of the existing repositories")
        sys.exit(1)

    logger.info('Getting region parameters has finished')
    return selected_repositories


def validate_selected_repositories_from_config(nexus_input_repositories, existing_nexus_repository_list):
    """
    Validate selected repositories when running in configMode=True (production mode)
    :param nexus_input_repositories:
    :param existing_nexus_repository_list:
    :return:
    """
    existing_nexus_repository_set = set(existing_nexus_repository_list)
    user_selected_repos_list = list(nexus_input_repositories.split(","))
    user_selected_repos_set = set(user_selected_repos_list)
    missing_repos = user_selected_repos_set - existing_nexus_repository_set
    if missing_repos:
        logger.error(f'Could not find the following repositories: {",".join(missing_repos)}')
        logger.error("Specified repositories not found or their format is not supported, check params.config and try again")
        sys.exit(1)
    # ToDo - only ws_exit if ALL specified repos not found, continue scan if some were found.

    logger.info('Getting region parameters has finished')
    return user_selected_repos_list


def download_components_from_repositories(selected_repositories, nexus_api_url_components, threads_number):
    """
    Download all components from selected repositories and save to folder

    :param selected_repositories:
    :param nexus_api_url_components:
    :param threads_number:
    :return:
    """
    for repo_name in selected_repositories:
        logger.info(f'Repository: {repo_name}')

        repo_comp_url = f'{nexus_api_url_components}?repository={repo_name}'
        continuation_token = "init"
        all_repo_items = []

        logger.info('Validate artifact list')
        while continuation_token:
            if continuation_token != 'init':
                cur_repo_comp_url = f'{repo_comp_url}&continuationToken={continuation_token}'
            else:
                cur_repo_comp_url = repo_comp_url
            cur_response_repo = requests.get(cur_repo_comp_url, headers=config.headers)
            cur_json_response_cur_components = json.loads(cur_response_repo.text)
            for item in cur_json_response_cur_components['items']:
                all_repo_items.append(item)
            continuation_token = cur_json_response_cur_components['continuationToken']

        if not all_repo_items:
            logger.info(f'No artifacts found in {repo_name}')
            logger.info(' -- > ')
        else:
            cur_dest_folder = os.path.join(config.scan_dir, repo_name)
            os.makedirs(cur_dest_folder, exist_ok=True)

            logger.info('Retrieving artifacts...')

            manager = Manager()
            docker_images_q = manager.Queue()
            with Pool(threads_number) as pool:
                pool.starmap(repo_worker, [(comp, repo_name, cur_dest_folder, config.headers, config, docker_images_q)
                                           for i, comp in enumerate(all_repo_items)])
            # Updating UA env vars to include Docker images from Nexus
            docker_images = set()
            while not docker_images_q.empty():
                docker_images.add(docker_images_q.get(block=True, timeout=0.05))

            if docker_images:
                logger.info(f"Found total {len(docker_images)} docker images")
                config.ws_env_var['WS_DOCKER_SCANIMAGES'] = 'True'
                config.ws_env_var['WS_DOCKER_INCLUDES'] = ",".join(docker_images)
                config.ws_env_var['WS_PROJECTPERFOLDER'] = 'False'
                config.ws_env_var['WS_SCANPACKAGEMANAGER'] = 'True'
                config.ws_env_var['WS_RESOLVEALLDEPENDENCIES'] = 'False'

            logger.info(' -- > ')


def call_nexus_api(url: str, headers: dict) -> Union[dict, bytes]:
    logger.debug(f"Calling Nexus URL: {url}")
    ret = None
    try:
        resp = requests.get(url, headers=headers)
    except requests.RequestException:
        logger.exception(f"Received Error on endpoint: {url}")
    if resp.status_code != 200:
        logging.error(f"Error calling API return code {resp.status_code} Error: {resp.reason} ")
    else:
        try:
            ret = json.loads(resp.text)
        except json.decoder.JSONDecodeError:
            ret = resp.content

    return ret


def handle_docker_repo(component: dict, conf) -> str:
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
        repos_list = call_nexus_api(conf.nexus_base_url + conf.resources_url, c.headers)
        logger.debug(f"found {len(repos_list)} repositories")
        repo_dict = {}
        for r in repos_list:
            repo_dict[r['name']] = r

        return repo_dict

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
    ret = None
    dl_url = component['assets'][0]["downloadUrl"]
    logger.debug(f"Component repository: {component['repository']}")
    logger.debug(f"Getting manifest file from: {dl_url}")
    manifest = call_nexus_api(dl_url, conf.headers)
    repos = get_repos_as_dict(conf)

    try:
        import docker
    except ImportError:
        logger.error("Found Docker repository but Docker package is not installed.")
        return ret

    repo = repos.get(component['repository'])

    ret = None

    if conf.nexus_alt_docker_registry_address:
        docker_repo_url = conf.nexus_alt_docker_registry_address
        logger.info(f"Using user-defined docker registry URL: {docker_repo_url}")
    elif repo:
        logger.debug(f"Repository data: {repo}")
        docker_repo_url = get_docker_repo_url(repo)

    if docker_repo_url:
        image_name = f"{docker_repo_url}/{manifest['name']}:{manifest['tag']}"
        logger.info(f"Pulling Docker image: {image_name}")
        try:
            docker_client = docker.from_env(timeout=DOCKER_TIMEOUT)
            # Configuring Nexus user and password are mandatory for non-anonymous Docker repositories
            docker_client.login(username=conf.nexus_user, password=conf.nexus_password, registry=docker_repo_url)
            pull_res = docker_client.images.pull(image_name)
            image_id = pull_res.id.split(':')[1][0:12]
            logger.debug(f"Image ID: {image_id} successfully pulled")
            ret = image_id  # Shorten ID to match docker images IMAGE ID
        except docker.errors.DockerException:
            logger.exception(f"Error loading image: {image_name}")
    else:
        logger.warning(f"Repository was not found for {component['repository']}. Skipping")

    return ret


def repo_worker(comp, repo_name, cur_dest_folder, headers, conf, d_images_q):
    """

    :param d_images_q:
    :param conf:
    :param comp:
    :param repo_name:
    :param cur_dest_folder:
    :param headers:
    """

    all_components = []
    component_assets = comp['assets']
    logger.debug(f"Handling component ID: {comp['id']} on repository: {comp['repository']} Format: {comp['format']}")
    if comp['format'] == 'nuget':
        comp_name = '{}.{}.nupkg'.format(comp['name'], comp['version'])
        all_components.append(comp_name)
    elif re.match('(maven).*', comp['format']):
        component_assets_size = len(component_assets)
        for asset in range(0, component_assets_size):
            comp_name = component_assets[asset]['path'].rpartition('/')[-1]
            if comp_name.split(".")[-1] == "jar":
                all_components.append(comp_name)
    elif comp['format'] == 'docker':
        image_id = handle_docker_repo(comp, conf)
        if image_id:
            d_images_q.put(image_id)
    else:
        comp_name = component_assets[0]['path'].rpartition('/')[-1]
        all_components.append(comp_name)

    for comp_name in all_components:
        comp_worker(repo_name, component_assets, cur_dest_folder, headers, comp_name)


def comp_worker(repo_name, component_assets, cur_dest_folder, headers, comp_name):
    """

    :param repo_name:
    :param component_assets:
    :param cur_dest_folder:
    :param headers:
    :param comp_name:
    """
    logger.info(f'Downloading {comp_name} component from {repo_name}')
    comp_download_url = component_assets[0]["downloadUrl"]
    response = call_nexus_api(comp_download_url, headers)
    logger.debug(f"Download URL: {comp_download_url}")
    path = os.path.dirname(f'{cur_dest_folder}/{comp_name}')
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)
    with open(f'{cur_dest_folder}/{comp_name}', 'wb') as f:
        f.write(response)
        logger.info(f'Component {comp_name} has successfully downloaded')


def download_unified_agent_and_config():
    """
    Download unified agent and config file if there are not exist in the default or specified folder
    :return:
    """
    logger.info('Verifying agent parameters')
    ua_jar_with_path = f'{config.ua_dir}/{UA_JAR_NAME}'
    ua_conf_with_path = f'{config.ua_dir}/{UA_CONFIG_NAME}'

    if not os.path.isdir(config.ua_dir):
        logger.info(f'Creating directory "{config.ua_dir}"')
        os.makedirs(config.ua_dir, exist_ok=True)

    if not os.path.isfile(ua_jar_with_path):
        logger.info('(this may take a few minutes on first run)')
        logger.info('Downloading WhiteSource agent')

        r = requests.get(URL_UA_JAR)
        with open(ua_jar_with_path, 'wb') as f:
            f.write(r.content)

        r = requests.get(URL_UA_CONFIG)
        with open(ua_conf_with_path, 'wb') as f:
            f.write(r.content)

    logger.info('WhiteSource agent download complete')

    return ua_jar_with_path


def whitesource_scan() -> int:
    global config
    logger.info('Starting WhiteSource scan')
    return_code = subprocess.run(['java', '-jar', config.ua_jar_with_path, '-d', config.scan_dir, '-logLevel', 'ERROR'],
                                 env=config.ws_env_var, stdout=subprocess.DEVNULL).returncode

    return_msg = 'SUCCESS'
    if return_code != 0:
        return_code = return_code - 4294967296
        if return_code == -1:
            return_msg = 'ERROR'
        elif return_code == -2:
            return_msg = 'POLICY_VIOLATION'
        elif return_code == -3:
            return_msg = 'CLIENT_FAILURE'
        elif return_code == -4:
            return_msg = 'CONNECTION_FAILURE'
        elif return_code == -5:
            return_msg = 'SERVER_FAILURE'
        elif return_code == -6:
            return_msg = 'PRE_STEP_FAILURE'
        else:
            return_msg = 'FAILED'

    logger.info('WhiteSource scan complete')
    logger.info(f'Result: {return_msg} ({return_code})')

    return return_code


def main():
    global config
    print_header('WhiteSource for Nexus')

    conf_file = '../config/params.config'
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        logger.debug(f"Using configuration file: {sys.argv[1]}")
        conf_file = sys.argv[1]

    config = Configuration(conf_file)
    logger.info("Starting")

    nexus_api_url_repos, nexus_api_url_components = define_nexus_parameters()
    config.ua_jar_with_path = download_unified_agent_and_config()
    existing_nexus_repository_list = retrieve_nexus_repositories(nexus_api_url_repos)
    set_resources_url(config.nexus_version)

    if not config.interactive_mode:
        nexus_input_repositories = config.nexus_config_input_repositories
        if not nexus_input_repositories:
            selected_repositories = existing_nexus_repository_list
            logger.info('No repositories specified, all repositories will be scanned')
        else:
            logger.info('Validate specified repositories')
            selected_repositories = validate_selected_repositories_from_config(nexus_input_repositories,
                                                                               existing_nexus_repository_list)
    else:
        print_header('Available Repositories')
        print('Only supported repositories will be available for the WS scan')

        for number, entry in enumerate(existing_nexus_repository_list):
            print(f'   {number} - {entry}')

        nexus_input_repositories_str = input('Select repositories to scan by entering their numbers '
                                             '(space delimited list): ')
        # ToDo - Validate this input - only allow values in range of len(existing_nexus_repository_map)
        nexus_user_input_repositories = nexus_input_repositories_str.split()

        selected_repositories = validate_selected_repositories(nexus_user_input_repositories,
                                                               existing_nexus_repository_list)

    download_components_from_repositories(selected_repositories, nexus_api_url_components, config.threads_number)

    print_header('WhiteSource Scan')

    return whitesource_scan()


if __name__ == '__main__':
    main()

