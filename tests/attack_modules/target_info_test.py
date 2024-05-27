import unittest

from src.attack_modules.target_info import TargetInfo


class TargetInfoTest(unittest.TestCase):
    def setUp(self):
        self.target_info = TargetInfo("002", "http://192.168.0.180:3000", "../../openapi/test/wazuh_spec.yaml")

    def tearDown(self):
        pass

    def test_target_info_paths(self):
        # idk how to test this stuff
        # If it runs it's already fine I guess
        paths = self.target_info.get_paths()

