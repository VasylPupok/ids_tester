import unittest
import yaml

from src.attack_modules.open_api_3_parser import OpenAPIParser, HTTPMethod


class OpenAPI3ParserTest(unittest.TestCase):
    def setUp(self):
        self.parser = OpenAPIParser(open_api_spec_path="../../openapi/juice-shop.yml")
        self.maxDiff = None

    def test_openapi_3_parser(self) -> None:
        with open("../../openapi/juice-shop.yml", "r") as yaml_file:
            yaml_processed = yaml.safe_load(yaml_file)
        self.assertNotEqual(self.parser.processed_dict, yaml_processed)

    def test_openapi_3_parser_swagger_2(self) -> None:
        with open("../../openapi/test/dbaas.yaml", "r") as yaml_file:
            yaml_processed = yaml.safe_load(yaml_file)
        parser = OpenAPIParser(open_api_spec_path="../../openapi/test/dbaas.yaml")
        self.assertEqual(str(yaml_processed), str(parser.processed_dict))

    def test_deadly_wazuh_file(self) -> None:
        parser = OpenAPIParser(open_api_spec_path="../../openapi/test/wazuh_spec.yaml")
        self.assertTrue(len(parser.processed_dict) > 0)
        l = parser.filter_path_by_method(HTTPMethod.GET)
        for url, info in l:
            self.assertTrue(HTTPMethod.GET.value in parser.get_paths()[url])
            self.assertEqual(parser.get_paths()[url][HTTPMethod.GET.value], info)
