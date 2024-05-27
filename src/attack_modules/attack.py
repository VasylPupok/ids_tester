from typing import Any

import requests


class Attacker:

    def __init__(self, hostname: str):
        self.host = hostname

    def attack(self, method: str,
               format_endpoint: str,
               path_params: dict[str, Any] = {},
               query_params: dict[str, Any] = {},
               header_params: dict[str, Any] = {},
               body: dict[str, Any] = {}
               ) -> requests.Response:
        url = f"{self.host}/{format_endpoint}".format_map(path_params).format_map(query_params)
        return requests.request(method, url, headers=header_params, json=body, verify=False)

