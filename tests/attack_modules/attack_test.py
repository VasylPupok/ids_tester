import unittest


from src.attack_modules.attack import Attacker


class AttackerTest(unittest.TestCase):
    def setUp(self):
        self.attacker = Attacker("http://192.168.0.8:3000")

    def tearDown(self):
        pass

    def test_attack(self) -> None:
        response = self.attacker.attack("get",'/')
        self.assertEqual(response.status_code, 200)

    def test_post_attack(self) -> None:
        response = self.attacker.attack("post","/orders", body={
            "cid" : "JS0815DE",
            "orderLines" : [
                {
                    "productId" : 1,
                    "quantity" : 1,
                    "customerReference" : "PO0000001"
                }

            ],
            "orderLinesData" : '['
                               '{"productId": 12,'
                               '"quantity": 10000,'
                               '"customerReference": ["PO0000001.2", "SM20180105|042"],'
                               '"couponCode": "pes[Bh.u*t"},'
                               '{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}'
                               ']'
        })
        self.assertEqual(response.status_code, 200)
