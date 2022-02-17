import logging
from unittest.mock import patch, MagicMock
import pytest
from ws_nexus_integration import nexus_integration
logger = logging.getLogger(__name__)


class TestClass:
    @pytest.fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog
        with patch('ws_nexus_integration.nexus_integration.config') as mock_config:
            mock_config.configure_mock(scan_dir="SCAN_DIR",
                                       threads_number=2,
                                       nexus_base_url="http://NEXUS_URL",
                                       headers={})
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

            nexus_integration.download_components_from_repositories(["REPO_NAME1"])

            assert 'Retrieving artifacts...' in self._caplog.text

    @patch('ws_nexus_integration.nexus_integration.requests.request')
    def test_call_nexus_api(self, mock_requests):
        mock_requests.return_value.text = '{"key": "val"}'
        ret = nexus_integration.call_nexus_api(url="/endpoint")

        assert {"key": "val"} == ret


if __name__ == '__main__':
    pytest.main()
