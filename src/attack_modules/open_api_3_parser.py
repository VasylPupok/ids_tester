import enum

import yaml
import json


class HTTPMethod(enum.Enum):
    """
    This enum represents all possible HTTP methods
    """
    GET = 'get'
    POST = 'post'
    PATCH = 'patch'
    PUT = 'put'
    DELETE = 'delete'
    HEAD = 'head'
    OPTIONS = 'options'


class OpenAPIParser:
    """
    This class responsible for parsing OpenAPI 3.0 specifications
    Also provides some methods for convenient access to some parts of specification
    WARNING: This class is written by myself, therefore it's definitely buggy
    DO NOT USE THIS IN SERIOUS PROJECTS
    """

    def __init__(self, open_api_spec: dict = {}, open_api_spec_path: str = None):
        if open_api_spec_path is not None:
            with open(open_api_spec_path, "r") as file:
                if open_api_spec_path.endswith(".json"):
                    open_api_spec = json.load(file)
                else:
                    open_api_spec = yaml.safe_load(file)
        self.processed_dict = OpenAPIParser.__process_dict(open_api_spec, open_api_spec)

    @staticmethod
    def __process_dict(initial_dict: dict, current_dict: dict) -> dict:
        result = {}
        for key in current_dict:
            value = current_dict[key]
            if key == "$ref":
                val = OpenAPIParser.__process_ref(initial_dict, value)
                return val
            elif isinstance(value, dict):
                result[key] = OpenAPIParser.__process_dict(initial_dict, value)
            elif isinstance(value, list):
                result[key] = OpenAPIParser.__process_list(initial_dict, value)
            else:
                result[key] = value
        return result

    @staticmethod
    def __process_list(initial_dict: dict, current_list: list) -> list:
        result = []
        for item in current_list:
            if isinstance(item, dict):
                result.append(OpenAPIParser.__process_dict(initial_dict, item))
            elif isinstance(item, list):
                result.append(OpenAPIParser.__process_list(initial_dict, item))
            else:
                result.append(item)
        return result

    @staticmethod
    def __process_ref(initial_dict: dict, ref_string: str) -> dict | list | str:
        tree_path = list(
            filter(
                lambda s: len(s) > 0,
                ref_string.replace("#", "").replace("~0", "~").replace("~1", "/").split("/")
            )
        )
        val = initial_dict
        for key in tree_path:
            val = val[key]
        if isinstance(val, dict):
            return OpenAPIParser.__process_dict(initial_dict, val)
        elif isinstance(val, list):
            return OpenAPIParser.__process_list(initial_dict, val)
        else:
            return val

    def __getitem__(self, key):
        """
        Accessing an items in parsed dictionary by key
        Is same as self.processed_dict[key]

        :param key: key to access items in parsed dictionary
        :return: values inside the parsed dictionary by key
        """
        return self.processed_dict[key]

    def __str__(self):
        return str(self.processed_dict)

    def get_paths(self) -> dict:
        """
        Get all paths described in Open API specification
        :return: dictionary with urls of all endpoints and info about methods and params
        """
        return self.processed_dict['paths']

    def filter_path_by_method(self, method: HTTPMethod) -> list[(str, dict)]:
        """
        Filter out paths and leaves only endpoints with given method
        Stores results as pairs (url, endpoint_info)

        :param method: method, which will be used to filter data
        :return: list of tuples with url and dictionary with info about params and endpoint
        """
        paths = self.get_paths()
        filtered_paths = []
        for url in paths:
            if method.value in paths[url]:
                filtered_paths.append((url, paths[url][method.value]))
        return filtered_paths
