#!/usr/bin/env python3
import base64
import json
import logging
import os
import re
import sys
from configparser import ConfigParser
from distutils.util import strtobool
from multiprocessing import Pool, Manager
from typing import Union
from urllib.parse import urlparse, urljoin

from ws_nexus_integration._version import __version__, __tool_name__
import requests
from ws_sdk import WSClient, ws_constants

SUPPORTED_FORMATS = {'maven2', 'npm', 'pypi', 'rubygems', 'nuget', 'raw', 'docker'}
DOCKER_TIMEOUT = 600
VER_3_26 = ["3", "26"]

config = None

logging.basicConfig(level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
                    handlers=[logging.StreamHandler(stream=sys.stdout)],
                    format='%(levelname)s %(asctime)s %(thread)d %(name)s: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('docker').setLevel(logging.WARNING)


class Configuration:
    # @dataclass
    # class Config:
    #     nexus_base_url: str
    #     nexus_alt_docker_registry_address: str
    #     nexus_user: str
    #     nexus_password: str
    #     nexus_auth_token: str
    #     nexus_repos: str
    #     nexus_ip: str
    #     headers: dict

    def __init__(self) -> str:
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
            nexus_auth_token = conf.get('Nexus Settings', 'NexusAuthToken', fallback=None)
            if nexus_auth_token:
                logging.debug(f"Using Nexus authentication token")
            else:
                logging.debug('Converting user and password to basic string')
                try:
                    nexus_auth_token = convert_to_basic_string(nexus_user, nexus_password)
                except KeyError:
                    logging.error("Nexus username or password are missing from the configuration file")
                    sys.exit(1)

            return nexus_auth_token

        def generate_dirs():
            for k, v in self.__dict__.items():
                if k.endswith("_dir") and not os.path.exists(v):
                    logging.debug(f"Directory {v} does not exist and will be created")
                    os.mkdir(v)

        def set_lang_include(includes: str):
            inc_l = includes.split(',') if len(includes) else None
            if inc_l:
                ret_l = []
                for i in inc_l:
                    ret_l += ws_constants.LibMetaData.LangSuffix.__dict__[i]
                self.ws_conn.ua_conf.set_include_suffices_to_scan(ret_l)

        def read_conf_file():
            conf_file = 'params.config'
            if len(sys.argv) > 1:
                conf_file = sys.argv[1]

            if os.path.isfile(conf_file):
                logging.debug(f"Using configuration file: '{conf_file}'")
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
NexusAltDockerRegistryAddress=


[WhiteSource Settings]
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

        conf = read_conf_file()
        # Nexus Settings
        self.nexus_base_url = conf.get('Nexus Settings', 'NexusBaseUrl', fallback='http://localhost:8081').strip('/')
        self.nexus_alt_docker_registry_address = conf.get('Nexus Settings', 'NexusAltDockerRegistryAddress', fallback=None)
        self.nexus_user = conf.get('Nexus Settings', 'NexusUser', fallback=None)
        self.nexus_password = conf['Nexus Settings']['NexusPassword']
        self.nexus_auth_token = get_nexus_auth_token(self.nexus_user, self.nexus_password)
        self.nexus_repos = conf.get('Nexus Settings', 'NexusRepositories')
        self.nexus_ip = self.nexus_base_url.split('//')[1].split(':')[0]
        self.headers = {'Authorization': f'Basic {self.nexus_auth_token}',
                        'accept': 'application/json'}
        # WhiteSource Settings
        self.product_name = conf.get('WhiteSource Settings', 'WSProductName', fallback='Nexus')
        self.check_policies = conf.getboolean('WhiteSource Settings', 'WSCheckPolicies', fallback=False)
        self.policies = 'true' if self.check_policies else 'false'
        ws_name = f"ws-{__tool_name__.replace('_', '-')}"
        base_dir = conf.get('General Settings', 'WorkDir')
        if not base_dir:
            base_dir = f"c:/tmp/ws-{ws_name}" if sys.platform == "win32" else f"/tmp/{ws_name}"
        self.base_dir = base_dir
        self.is_docker_scan = False
        self.scan_dir = os.path.join(self.base_dir, '_wstemp')
        java_bin = conf.get('General Settings', 'JavaBin', fallback="java")
        self.ws_conn = WSClient(user_key=conf['WhiteSource Settings']['WSUserKey'],
                                token=conf['WhiteSource Settings']['WSApiKey'],
                                url=conf.get('WhiteSource Settings', 'WSUrl'),
                                java_bin=java_bin if java_bin else "java",
                                ua_path=self.base_dir,
                                tool_details=(f"ps-{__tool_name__.replace('_', '-')}", __version__))
        set_lang_include(conf.get('WhiteSource Settings', 'WSLang').replace(" ", ""))

        # General Settings
        self.threads_number = conf.getint('General Settings', 'ThreadCount', fallback=5)
        generate_dirs()


def set_nexus_resources_url(full_version: str):
    ver = full_version.strip("Nexus/ (OSS)").split(".")
    if ver[0] < VER_3_26[0] or (ver[0] == VER_3_26[0] and ver[1] < VER_3_26[1]):
        config.resources_url = "/service/rest/beta/repositories"
    else:
        config.resources_url = "/service/rest/v1/repositorySettings"
    logging.debug(f"Using repository: {config.resources_url}")


def retrieve_nexus_repositories():
    def get_nexus_ver(nexus_version):
        if nexus_version:
            logging.info(f"Nexus Version: {nexus_version}")
        else:
            logging.warning("Server headers does not contain Nexus version. Assuming >=3.26")
            nexus_version = "3.26"

        return nexus_version

    def get_valid_repositories(repos):
        valid_repos = []
        for repo in repos:
            repo_format = repo.get("format")
            if repo_format in SUPPORTED_FORMATS:
                repo_name = repo["name"]
                valid_repos.append(repo_name)
            else:
                logging.warning(f"Repository: {repo['name']} is unsupported format: {repo_format}. Skipping")

        return valid_repos

    logging.debug("Sending request for retrieving Nexus repository list")
    repositories, resp_headers = call_nexus_api("/service/rest/v1/repositories", include_resp_headers=True)
    config.nexus_version = get_nexus_ver(resp_headers.get('Server'))
    existing_nexus_repository_list = get_valid_repositories(repositories)

    return existing_nexus_repository_list


def validate_selected_repositories(nexus_input_repositories, existing_nexus_repository_list):
    selected_repositories = [existing_nexus_repository_list[int(n)] for n in nexus_input_repositories]
    if not selected_repositories:
        logging.error("No repositories were found to be scanned")
        sys.exit(1)

    return selected_repositories


def download_components_from_repositories(selected_repos):
    for repo_name in selected_repos:
        logging.info(f'Repository: {repo_name}')
        repo_comp_url = f'{config.nexus_base_url}/service/rest/v1/components?repository={repo_name}'
        continuation_token = "init"
        all_repo_items = []

        logging.info('Validate artifact list')
        while continuation_token:
            if continuation_token != 'init':
                cur_repo_comp_url = f'{repo_comp_url}&continuationToken={continuation_token}'
            else:
                cur_repo_comp_url = repo_comp_url
            cur_comp_response = call_nexus_api(cur_repo_comp_url)
            for item in cur_comp_response['items']:
                all_repo_items.append(item)
            continuation_token = cur_comp_response['continuationToken']

        if not all_repo_items:
            logging.debug(f'No artifacts found in {repo_name}')
        else:
            cur_dest_folder = os.path.join(config.scan_dir, repo_name)
            os.makedirs(cur_dest_folder, exist_ok=True)
            logging.info('Retrieving artifacts...')

            manager = Manager()
            docker_images_q = manager.Queue()
            with Pool(config.threads_number) as pool:
                pool.starmap(repo_worker, [(comp, repo_name, cur_dest_folder, config.headers, config, docker_images_q)
                                           for i, comp in enumerate(all_repo_items)])
            # Updating UA env vars to include Docker images from Nexus
            docker_images = set()
            while not docker_images_q.empty():
                docker_images.add(docker_images_q.get(block=True, timeout=0.05))

            if docker_images:
                config.is_docker_scan = True
                logging.info(f"Found total {len(docker_images)} docker images")
                config.docker_images = docker_images


def call_nexus_api(url: str, headers: dict = None, include_resp_headers: bool = False) -> Union[dict, bytes]:
    if headers is None:
        headers = config.headers

    if not url.startswith("http"):
        url = urljoin(config.nexus_base_url, url)
    logging.debug(f"Calling Nexus URL: {url}")
    ret = None
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logging.error(f"Error calling API return code {resp.status_code} Error: {resp.reason}")
        else:
            try:
                ret = json.loads(resp.text)
            except json.decoder.JSONDecodeError:
                ret = resp.content

        if include_resp_headers:
            ret = ret, resp.headers
    except requests.RequestException:
        logging.exception(f"Received Error on endpoint: {url}")

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
        logging.debug(f"found {len(repos_list)} repositories")
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
            logging.error("Unable to get repository port. Using default URL")
            r_url = f"{parsed_url.hostname}:{parsed_url.port}"
        logging.debug(f"Returned docker repo URL: {r_url}")

        return r_url
    ret = None
    dl_url = component['assets'][0]["downloadUrl"]
    logging.debug(f"Component repository: {component['repository']}")
    logging.debug(f"Getting manifest file from: {dl_url}")
    manifest = call_nexus_api(dl_url, conf.headers)
    repos = get_repos_as_dict(conf)

    try:
        import docker
    except ImportError:
        logging.error("Found Docker repository but Docker package is not installed.")
        return ret

    repo = repos.get(component['repository'])

    ret = None

    if conf.nexus_alt_docker_registry_address:
        docker_repo_url = conf.nexus_alt_docker_registry_address
        logging.info(f"Using user-defined docker registry URL: {docker_repo_url}")
    elif repo:
        logging.debug(f"Repository data: {repo}")
        docker_repo_url = get_docker_repo_url(repo)

    if docker_repo_url:
        image_name = f"{docker_repo_url}/{manifest['name']}"
        image_full_name = f"{image_name}:{manifest['tag']}"
        logging.info(f"Pulling Docker image: {image_name}")
        try:
            docker_client = docker.from_env(timeout=DOCKER_TIMEOUT)
            # Configuring Nexus user and password are mandatory for non-anonymous Docker repositories
            docker_client.login(username=conf.nexus_user, password=conf.nexus_password, registry=docker_repo_url)
            pull_res = docker_client.images.pull(image_full_name)
            logging.debug(f"Image ID: {image_full_name} successfully pulled")
            ret = image_name
        except docker.errors.DockerException:
            logging.exception(f"Error loading image: {image_name}")
    else:
        logging.warning(f"Repository was not found for {component['repository']}. Skipping")

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
    logging.debug(f"Handling component ID: {comp['id']} on repository: {comp['repository']} Format: {comp['format']}")
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
    logging.info(f'Downloading {comp_name} component from {repo_name}')
    comp_download_url = component_assets[0]["downloadUrl"]
    comp_data = call_nexus_api(comp_download_url, headers)
    logging.debug(f"Download URL: {comp_download_url}")
    os.makedirs(cur_dest_folder, exist_ok=True)

    with open(os.path.join(cur_dest_folder, comp_name), 'wb') as f:
        f.write(comp_data)
    logging.info(f'Component {comp_name} has successfully downloaded')


def execute_scan():
    config.ws_conn.ua_conf.productName = config.product_name
    config.ws_conn.ua_conf.checkPolicies = strtobool(config.policies)
    config.ws_conn.ua_conf.forceCheckAllDependencies = strtobool(config.policies)
    config.ws_conn.ua_conf.offline = True if os.environ.get("OFFLINE", "").lower() == "true" else False

    if config.is_docker_scan:
        config.ws_conn.ua_conf.resolveAllDependencies = True
        config.ws_conn.ua_conf.archiveExtractionDepth = ws_constants.UAArchiveFiles.ARCHIVE_EXTRACTION_DEPTH_MAX
        config.ws_conn.ua_conf.archiveIncludes = ws_constants.UAArchiveFiles.ALL_ARCHIVE_FILES
        ret = config.ws_conn.scan_docker(product_name=config.product_name, docker_images=config.docker_images)
    else:
        config.ws_conn.ua_conf.projectPerFolder = True
        ret = config.ws_conn.scan(scan_dir=config.scan_dir, product_name=config.product_name)
    logging.debug(f"Unified Agent standard output:\n {ret[1]}")

    return ret[0]


def get_repos_to_scan():
    def validate_selected_repos_from_config(nexus_input_repositories, existing_nexus_repository_list):
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
            logging.error(f'Could not find the following repositories: {",".join(missing_repos)}')
            logging.error(
                "Specified repositories not found or their format is not supported, check params.config and try again")
            sys.exit(1)

        logging.info('Getting region parameters has finished')

        return user_selected_repos_list

    all_repos = retrieve_nexus_repositories()
    if config.nexus_repos:
        logging.info('Validate specified repositories')
        repos_to_scan = validate_selected_repos_from_config(config.nexus_repos, all_repos)
    else:
        repos_to_scan = all_repos
        logging.info('No specific repositories specified, all repositories will be scanned')

    return repos_to_scan


def main():
    global config
    config = Configuration()
    selected_repositories = get_repos_to_scan()
    set_nexus_resources_url(config.nexus_version)
    download_components_from_repositories(selected_repositories)
    return_code = execute_scan()

    return return_code


if __name__ == '__main__':
    main()
