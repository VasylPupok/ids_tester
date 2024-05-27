import requests
from requests.auth import HTTPBasicAuth


class WazuhAPI:
    """
    This class handles connection and requests to Wazuh indexer
    This class responsible for authorization handling and
    retrieving data about Wazuh agents
    """

    WAZUH_API_PORT = 55000
    OPENSEARCH_API_PORT = 9200
    LOGIN_ENDPOINT = "security/user/authenticate"

    def __init__(
            self,
            hostname: str,
            credentials: tuple[str, str] = None,
            elastic_credentials: tuple[str, str] = None,
            token: str = None,
    ):
        """
        Creates a connection to Wazuh server API

        :param hostname: name of designated Wazuh server.
        :param credentials: pair of credentials (login, password) from Wazuh server
        :param token: JWT obtained from Wazuh server. If credentials provided, value of token will be discarded
        """
        self.hostname = hostname
        if credentials is None:
            if token is None:
                raise ValueError("Either credentials or token must be provided")
            self.token = token
        else:
            self.token = WazuhAPI.get_wazuh_api_token(hostname, credentials[0], credentials[1])

        if elastic_credentials is None:
            raise ValueError("Elastic credentials must be provided")
        elif not self.__verify_elastic_credentials(elastic_credentials[0], elastic_credentials[1]):
            raise ValueError("Invalid elastic credentials or any other issues with Elastic server")
        else:
            self.elastic_credentials = HTTPBasicAuth(elastic_credentials[0], elastic_credentials[1])

    @staticmethod
    def get_wazuh_api_token(hostname: str, login: str, passwd: str) -> str | requests.Response:
        """
        Gets JWT token from Wazuh API. Credentials should be from Wazuh API
        To get those credentials, print sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt

        :param hostname: server hostname
        :param login: login of Wazuh API.
        :param passwd: password of Wazuh API
        :return: JWT string or requests.Response object in case of failure
        """
        response = requests.post(
            f"https://{hostname}:{WazuhAPI.WAZUH_API_PORT}/{WazuhAPI.LOGIN_ENDPOINT}",
            auth=HTTPBasicAuth(login, passwd),
            verify=False
        )
        if response.status_code == 200:
            token = response.json()["data"]["token"]
        else:
            return response
        return token

    def __verify_elastic_credentials(self, login: str, passwd: str) -> bool:
        """
        Gets JWT token from ElasticSearch API. Credentials should be from ElasticSearch API user
        To get those credentials, print sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt

        :param hostname: server hostname
        :param login: login of Wazuh API.
        :param passwd: password of Wazuh API
        :return: JWT string or requests.Response object in case of failure
        """
        response = requests.get(f"https://{self.hostname}:{WazuhAPI.OPENSEARCH_API_PORT}",
                                auth=HTTPBasicAuth(login, passwd), verify=False)
        return response.status_code == 200

    def __get_default_headers(self) -> dict:
        """
        This method helps to get rid of boilerplate of
        creating JSON header with JWT token for accessing Wazuh API

        :return: HTTP header with mandatory values
        """
        return {'Content-Type': 'application/json', 'Authorization': f'Bearer {self.token}'}

    def __get_default_elastic_headers(self) -> dict:
        """
        This method helps to get rid of boilerplate of
        creating JSON header with JWT token for accessing Wazuh API

        :return: HTTP header with mandatory values
        """
        return {'Content-Type': 'application/json', 'Authorization': f'Bearer {self.elastic_token}'}

    def get_api_info(self) -> requests.Response:
        """
        This method requests API info from Wazuh API

        :return: requests.Response object with info about Wazuh API server
        """
        response = requests.get(
            f"https://{self.hostname}:{WazuhAPI.WAZUH_API_PORT}/?pretty=true",
            headers=self.__get_default_headers(),
            verify=False
        )
        return response

    def get_agent_alerts(self, agent_id: str, rule_id: str | None = None, size=13) -> dict:
        """
        This method returns last {size} alerts for given agent
        If rule_id is given, filters output for given rule_id
        Method uses wazuh_alerts* filter for ElasticSearch API

        :param agent_id: id of agent. Should be a number string with length of 3 (example: "001")
        :param rule_id: id of triggered rule. If not set alerts are not filtered by rule
        :param size: number of alerts in json
        :return: response from Elasticsearch API in JSON format
        """
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": f"{agent_id}"}}
                    ]
                }

            }
        }

        if rule_id is not None:
            body["query"]["bool"]["must"].append({"term": {"rule.id": f"{rule_id}"}})

        response = requests.post(
            f"https://{self.hostname}:{WazuhAPI.OPENSEARCH_API_PORT}/wazuh-alerts*/_search?size={size}",
            auth=self.elastic_credentials, json=body, verify=False
        )
        return response.json()

    def get_agent_alerts_number(self, agent_id: str, rule_id: str | None = None) -> int | None:
        """
        This method returns total number of alerts for given agent
        Method uses wazuh_alerts* filter for ElasticSearch API


        :param agent_id: id of agent. Should be a number string with length of 3 (example: "001")
        :param rule_id: if not None returns number of only this type of alerts
        :return: total number of alerts for all time
        or None when such agent does not exist or in case of any other error
        """
        response = self.get_agent_alerts(agent_id, rule_id=rule_id)
        try:
            alerts = int(response['hits']['total']['value'])
        except KeyError:
            return None
        return alerts

    def send_alert(self, alert: str | dict[str, str]) -> requests.Response:
        """
        This method sends alert to Wazuh

        :param alert: alert message
        :return: response.Response from Wazuh REST API
        """
        headers = self.__get_default_headers()
        body = {
            "events": [str(alert)]
        }
        return requests.post(
            f"https://{self.hostname}:{WazuhAPI.WAZUH_API_PORT}/events",
            headers=headers,
            json=body,
            verify=False
        )
