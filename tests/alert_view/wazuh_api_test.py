import unittest

from src.alert_view.wazuh_api import WazuhAPI


class WazuhApiTest(unittest.TestCase):
    def setUp(self):
        self.api = WazuhAPI(
            "192.168.0.38",
            ("wazuh", "XKSz07d9ZssaOlr7TSU3ZOM52PC?x1lb"),
            ("admin", "O6jvltJoE++9VsA7AW67Z17PRH8DzX5+")
        )

    def test_get_agent_alerts_number(self) -> None:
        num = self.api.get_agent_alerts_number("002")
        if num is None:
            self.fail("Response code is not 200")
        self.assertGreater(num, 0)

    def test_get_agent_alerts(self):
        response = self.api.get_agent_alerts("002", size=15)
        self.assertEqual(len(response['hits']['hits']), 15)
        for hit in response['hits']['hits']:
            self.assertEqual(hit['_source']['agent']['id'], "002")


    def test_send_alert(self) -> None:
        response = self.api.send_alert("Alert test")
        self.assertEqual(response.status_code, 200)
        response_json = response.json()
        self.assertEqual(
            str(response_json),
            "{'data': {'affected_items': ['Alert test'], 'total_affected_items': 1, 'total_failed_items': 0, "
            "'failed_items': []}, 'message': 'All events were forwarded to analisysd', 'error': 0}"
        )

    def test_send_alert_json(self) -> None:
        json = {'name': 'JSON Test alert', 'alert_content': 'Test json format of alert'}
        response = self.api.send_alert(json)
        self.assertEqual(response.status_code, 200)
        response_json = response.json()
        self.assertEqual(
            str(response_json),
            "{'data': {"
            "'affected_items': [\"{'name': 'JSON Test alert', 'alert_content': 'Test json format of alert'}\"], "
            "'total_affected_items': 1, 'total_failed_items': 0, "
            "'failed_items': []}, 'message': 'All events were forwarded to analisysd', 'error': 0}"
        )
