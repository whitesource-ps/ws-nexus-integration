import logging
from unittest.mock import patch, MagicMock, mock_open
import pytest
from ws_nexus_integration import nexus_integration
logger = logging.getLogger(__name__)


@pytest.fixture
def patched_docker(mocker):
    mock_docker_from_env = mocker.MagicMock(name="mock_docker_client")
    mock_docker_from_env = mock_docker_from_env.from_env
    #
    # _module = mocker.MagicMock('mock_docker')
    # _module.from_env.return_value = mock_docker_from_env
    # mocker.patch.dict("sys.modules", {"docker": _module})
    #
    # yield mock_docker_from_env

    # mock_docker = mocker.MagicMock(name="mock_docker")
    # mock_docker_from_env = mock_docker.from_env

    _module = mocker.MagicMock(name="mock_docker")
    _module.DockerClient.return_value = mocker.MagicMock(name="mock_docker_client")
    mocker.patch.dict("sys.modules", {"docker_client": _module})

    yield mock_docker_from_env


@pytest.fixture
def patched_os(mocker):
    mocker.patch('os.makedirs')

class TestClass:
    @pytest.fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog
        with patch('ws_nexus_integration.nexus_integration.config') as mock_config:
            mock_config.configure_mock(scan_dir="SCAN_DIR",
                                       threads_number=2,
                                       nexus_base_url="http://NEXUS_URL",
                                       headers={},
                                       product_name="PRODUCT_NAME",
                                       policies="False")
            self.mock_config = mock_config
            yield

    def test_set_nexus_resources_url(self):
        assert nexus_integration.set_nexus_resources_url('Nexus/3.37.3-02 (OSS)') == "/service/rest/v1/repositorySettings"

    @patch('ws_nexus_integration.nexus_integration.call_nexus_api')
    def test_retrieve_nexus_repositories(self, mock_call_nexus_api):
        mock_call_nexus_api.return_value = ([], {})
        assert isinstance(nexus_integration.retrieve_nexus_repositories(), list)

    @patch('ws_nexus_integration.nexus_integration.call_nexus_api')
    def test_get_items_from_repo(self, mock_call_nexus_api):
        mock_call_nexus_api.side_effect = [{'continuationToken': "CONT_TOKEN", 'items': [{"ITEM": 1}]},
                                           {'continuationToken':  None, 'items': [{"ITEM": 2}]}]
        ret = nexus_integration.get_items_from_repo(repo_name="REPO_NAME")

        assert isinstance(ret, list) and len(ret) == 2

    @patch('multiprocessing.pool.Pool.starmap')
    @patch('ws_nexus_integration.nexus_integration.get_items_from_repo')
    def test_download_components_from_repositories(self, mock_get_items_from_repo, mock_starmap):
        with self._caplog.at_level(logging.DEBUG, logger='nexus_integration'):
            mock_get_items_from_repo.return_value = [{}]

            nexus_integration.scan_components_from_repositories(["REPO_NAME1"])

            assert 'Retrieving artifacts...' in self._caplog.text

    @patch('ws_nexus_integration.nexus_integration.requests.request')
    def test_call_nexus_api(self, mock_requests):
        mock_requests.return_value.text = '{"key": "val"}'
        ret = nexus_integration.call_nexus_api(url="/endpoint")

        assert {"key": "val"} == ret

    # @patch('ws_nexus_integration.nexus_integration.call_nexus_api')       # TODO TBD NEED TO MOCK docker
    # def test_handle_docker_repo_alt_docker_registry(self, mock_call_nexus_api, patched_docker):
    #     component = {'assets': [{'downloadUrl': "URL"}],
    #                  'repository': "REPOSITORY"}
    #     mock_call_nexus_api.side_effect = [{'name': "NAME", 'tag': "TAG"}, []]
    #
    #     mock_config = copy.copy(self.mock_config)
    #     mock_config.configure_mock(nexus_alt_docker_registry_address="NEXUS_ALT_DOCKER_REGISTRY_ADDRESS")
    #     ret = nexus_integration.handle_docker_repo(component=component, conf=mock_config)
    #
    #     assert ret

    @patch('ws_nexus_integration.nexus_integration.comp_worker')
    def test_repo_worker(self, mock_comp_worker):
        with self._caplog.at_level(logging.DEBUG, logger='nexus_integration'):
            comp = {'assets': [{'path': "/PATH/TO/name.nupkg"}],
                    'id': "ID",
                    'repository': "REPOSITORY",
                    'format': "FORMAT",
                    'name': "NAME",
                    'version': "VERSION"}
            nexus_integration.repo_worker(comp=comp,
                                          repo_name="REPO_NAME",
                                          cur_dest_folder="CUR_DEST_FOLDER",
                                          headers="HEADERS",
                                          conf=self.mock_config.headers,
                                          d_images_q=None)

            assert "Handling component ID: ID on repository: REPOSITORY Format: FORMAT" in self._caplog.text

    @patch('ws_nexus_integration.nexus_integration.comp_worker')
    def test_repo_worker_nuget(self, mock_comp_worker):
        with self._caplog.at_level(logging.DEBUG, logger='nexus_integration'):
            comp = {'assets': [{'path': "/PATH/TO/name.jar"}],
                    'id': "ID",
                    'repository': "REPOSITORY",
                    'format': "nuget",
                    'name': "NAME",
                    'version': "VERSION"}
            nexus_integration.repo_worker(comp=comp,
                                          repo_name="REPO_NAME",
                                          cur_dest_folder="CUR_DEST_FOLDER",
                                          headers="HEADERS",
                                          conf=self.mock_config.headers,
                                          d_images_q=None)

            assert "Handling component ID: ID on repository: REPOSITORY Format: nuget" in self._caplog.text

    @patch('ws_nexus_integration.nexus_integration.comp_worker')
    def test_repo_worker_maven(self, mock_comp_worker):
        with self._caplog.at_level(logging.DEBUG, logger='nexus_integration'):
            comp = {'assets': [{'path': "/PATH/TO"}],
                    'id': "ID",
                    'repository': "REPOSITORY",
                    'format': "maven",
                    'name': "NAME",
                    'version': "VERSION"}
            nexus_integration.repo_worker(comp=comp,
                                          repo_name="REPO_NAME",
                                          cur_dest_folder="CUR_DEST_FOLDER",
                                          headers="HEADERS",
                                          conf=self.mock_config.headers,
                                          d_images_q=None)

            assert "Handling component ID: ID on repository: REPOSITORY Format: maven" in self._caplog.text

    @patch('ws_nexus_integration.nexus_integration.handle_docker_repo')
    @patch('ws_nexus_integration.nexus_integration.comp_worker')
    def test_repo_worker_docker(self, mock_comp_worker, mock_handle_docker_repo):
        mock_handle_docker_repo.return_value = None
        with self._caplog.at_level(logging.DEBUG, logger='nexus_integration'):
            comp = {'assets': [{'path': "/PATH/TO/name.nupkg"}],
                    'id': "ID",
                    'repository': "REPOSITORY",
                    'format': "docker",
                    'name': "NAME",
                    'version': "VERSION"}
            nexus_integration.repo_worker(comp=comp,
                                          repo_name="REPO_NAME",
                                          cur_dest_folder="CUR_DEST_FOLDER",
                                          headers="HEADERS",
                                          conf=self.mock_config.headers,
                                          d_images_q=None)

            assert "Handling component ID: ID on repository: REPOSITORY Format: docker" in self._caplog.text

    @patch("builtins.open", new_callable=mock_open, read_data="data")
    @patch('ws_nexus_integration.nexus_integration.call_nexus_api')
    def test_comp_worker(self, mock_call_nexus_api, mock_open, patched_os):
        mock_call_nexus_api.return_value = b''
        with self._caplog.at_level(logging.DEBUG, logger='nexus_integration'):
            nexus_integration.comp_worker(repo_name="REPO_NAME",
                                          component_assets=[{'downloadUrl': "DOWNLOAD_URL"}],
                                          cur_dest_folder="DEST/FOLDER",
                                          headers=self.mock_config.headers,
                                          comp_name="COMP_NAME")

        assert "Downloading 'COMP_NAME' component from: 'REPO_NAME'" in self._caplog.text

    def test_execute_scan(self):
        self.mock_config.configure_mock(is_docker_scan=False)
        self.mock_config.ws_conn = MagicMock()
        self.mock_config.ws_conn.scan.side_effect = [(0, "UA OUTPUT", "SUPPORT_TOKEN"), "APP_STATUS"]
        ret = nexus_integration.execute_scan()

        assert ret == 0

    def test_execute_scan_docker(self):
        self.mock_config.configure_mock(is_docker_scan=True)
        self.mock_config.ws_conn = MagicMock()
        self.mock_config.ws_conn.scan_docker.side_effect = [(0, "UA OUTPUT", "SUPPORT_TOKEN"), "APP_STATUS"]
        ret = nexus_integration.execute_scan()

        assert ret == 0

    @patch('ws_nexus_integration.nexus_integration.retrieve_nexus_repositories')
    def test_get_repos_to_scan_all(self, mock_retrieve_nexus_repositories):
        self.mock_config.configure_mock(nexus_repos=None)
        mock_retrieve_nexus_repositories.return_value = ["REPO1", "REPO2"]
        ret = nexus_integration.get_repos_to_scan()

        assert ret == ["REPO1", "REPO2"]

    @patch('ws_nexus_integration.nexus_integration.retrieve_nexus_repositories')
    def test_get_repos_to_scan_defined(self, mock_retrieve_nexus_repositories):
        self.mock_config.configure_mock(nexus_repos="REPO1", defined_nexus_repo_l=["REPO1"])
        mock_retrieve_nexus_repositories.return_value = ["REPO1", "REPO2"]
        ret = nexus_integration.get_repos_to_scan()

        assert ret == ["REPO1"]

    @patch('ws_nexus_integration.nexus_integration.retrieve_nexus_repositories')
    def test_get_repos_to_scan_excluded(self, mock_retrieve_nexus_repositories):
        self.mock_config.configure_mock(nexus_repos=None, nexus_exc_repos="REPO1", nexus_exc_repos_l=["REPO1"])
        mock_retrieve_nexus_repositories.return_value = ["REPO1", "REPO2"]
        ret = nexus_integration.get_repos_to_scan()

        assert ret == ["REPO2"]


if __name__ == '__main__':
    pytest.main()
