import init_modules
from src.attack_modules.attack import Attacker


def main(args: tuple = ()) -> int:
    config = init_modules.Initializer("../config/config.json")
    techniques = config.db_connection.get_all_techniques()

    for target in config.targets:
        attacker = Attacker(target.hostname)
        paths = target.get_paths()

        for technique in techniques:
            payloads = config.db_connection.get_payloads_used_in_technique(technique)
            expected_alerts = config.db_connection.get_alerts_triggered_by_technique(technique)

            for path in paths:
                for method in path.methods:
                    params = method.parameters
                    schema = method.schema

                    for payload in payloads:
                        path_params = {
                            p: payload.payload
                            for p in filter(lambda p: p.location == 'path', params)
                        }
                        query_params = {
                            p: payload.payload
                            for p in filter(lambda p: params[p].location == 'query', params)
                        }
                        header_params = {
                            p: payload.payload
                            for p in filter(lambda p: params[p].location == 'header', params)
                        }
                        body = {}
                        if schema is not None:
                            for p in schema.properties:
                                name = p.name
                                if name == 'array':
                                    body[name] = payload.payload # should pass array params properly
                                elif name == 'object':
                                    body[name] = payload.payload # should pass object params properly
                                else:
                                    body[name] = payload.payload

                        alert_stats_before = {
                            alert: config.server_info.get_agent_alerts_number(target.id, alert.rule_id)
                            for alert in expected_alerts
                        }

                        attacker.attack(method.name, target.hostname, path_params, query_params, header_params, body)

                        for alert in expected_alerts:
                            new_alerts = config.server_info.get_agent_alerts_number(target.id, alert.rule_id)
                            if new_alerts <= alert_stats_before[alert]:
                                config.server_info.send_alert(
                                    str(
                                        {
                                            "agent_id": target.id,
                                            "message" : "Trigger failure",
                                            "rule_id" : alert.rule_id,
                                            "technique" : {
                                                "name" : technique.name,
                                                "id" : technique.uid
                                            },
                                            "payload" : payload
                                        }
                                    )
                                )
    return 0


if __name__ == '__main__':
    exit(main())
