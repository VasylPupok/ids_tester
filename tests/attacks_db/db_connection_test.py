import unittest
import mysql.connector as db_connector

from src.attacks_db import db_connection


class DbConnectionTest(unittest.TestCase):
    """
    This class tests AttackDbConnection class functional
    """

    def setUp(self) -> None:
        self.db = db_connection.AttackDbConnection("localhost", "root", "root", "ids_test")
        self.lib_db_connection = db_connector.connect(
            host="localhost",
            user="root",
            password="root",
            database="ids_test",
            auth_plugin='mysql_native_password'
        )

    def tearDown(self) -> None:
        self.db.disconnect()
        self.lib_db_connection.disconnect()

    def test_all_payloads(self) -> None:
        """
        Test for all_payloads() method
        It tests output of this method against result
        of query SELECT * FROM ids_test.payloads
        performed by mysql library
        """
        all_payloads = self.db.get_all_payloads()

        my_cursor = self.lib_db_connection.cursor()
        my_cursor.execute("SELECT * FROM ids_test.payloads")
        all_lib_payloads = my_cursor.fetchall()
        my_cursor.close()
        self.assertEqual(len(all_payloads), len(all_lib_payloads))

        for p, lib_p in zip(all_payloads, all_lib_payloads):
            self.assertEqual(p.uid, lib_p[0])
            self.assertEqual(p.payload, lib_p[1])

    def test_all_techniques(self) -> None:
        """
        Test for all_techniques() method
        It tests output of this method against result
        of query SELECT * FROM ids_test.techniques
        performed by mysql library
        """
        
        all_techniques = self.db.get_all_techniques()

        my_cursor = self.lib_db_connection.cursor()
        my_cursor.execute("SELECT * FROM ids_test.techniques")
        all_lib_techniques = my_cursor.fetchall()
        my_cursor.close()
        self.assertEqual(len(all_techniques), len(all_lib_techniques))

        for t, lib_t in zip(len(all_techniques), len(all_lib_techniques)):
            self.assertEqual(t.uid, lib_t[0])
            self.assertEqual(t.name, lib_t[1])
