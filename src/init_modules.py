import json

from alert_view.wazuh_api import WazuhAPI
from attack_modules.target_info import TargetInfo
from attacks_db.db_connection import AttackDbConnection


class Initializer:
    def __init__(self, path: str):
        with open(path, encoding="utf-8") as config:
            config_json = json.load(config)
        self.server_info = WazuhAPI(
            config_json["wazuh_server"]["hostname"],
            (
                config_json["wazuh_server"]["credentials"]["login"],
                config_json["wazuh_server"]["credentials"]["password"]
            ),
            (
                config_json["wazuh_server"]["elastic_credentials"]["login"],
                config_json["wazuh_server"]["elastic_credentials"]["password"]
            )
        )
        self.db_connection = AttackDbConnection(
            config_json["db_connection"]["host"],
            config_json["db_connection"]["username"],
            config_json["db_connection"]["password"],
            config_json["db_connection"]["database"]
        )
        self.targets = [TargetInfo(i["id"], i["url"], i["open_api_path"]) for i in config_json["targets"]]