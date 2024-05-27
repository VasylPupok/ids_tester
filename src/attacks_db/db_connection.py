from src.attacks_db import entities
import mysql.connector


class AttackDbConnection:
    """
    This class is responsible for database connection retention
    and provides interface to conveniently interact with payloads database
    """

    def __init__(self, host, user, password, db_name) -> None:
        """
        Constructor of this class makes connection to payloads database
        Does not verify database schema, therefore, it's users responsibility
        to connect to right db

        :param host: host address of the payloads database
        :param user: username of the payloads database connection
        :param password: password for corresponding database connection
        :param db_name: name of db, where payloads are stored
        """
        self.db_connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=db_name,
            auth_plugin='mysql_native_password'
        )

    def disconnect(self) -> None:
        """
        This method closes the connection to the database
        """
        self.db_connection.disconnect()

    def get_all_payloads(self) -> list[entities.Payload]:
        """
        This function dumps list of all payloads in database
        and return them as list of entities.Payload objects
        :return: list of all payloads
        """
        my_cursor = self.db_connection.cursor()
        my_cursor.execute(f"SELECT * FROM payloads")
        query_result = my_cursor.fetchall()
        result = [entities.Payload(i[0], i[1]) for i in query_result]
        my_cursor.close()
        return result

    def get_payload(self, payload_id) -> entities.Payload | None:
        """
        Returns a payload by its id

        :param payload_id: id of payload
        :return: entities.Payload or None, if there is no such payload in db
        """
        my_cursor = self.db_connection.cursor()
        my_cursor.execute(f"SELECT * FROM payloads WHERE payload_id = {payload_id}")
        result = my_cursor.fetchone()
        my_cursor.close()
        if result is None:
            return None
        return entities.Payload(payload_id, result[1])

    def get_all_techniques(self) -> list[entities.Technique]:
        """
        This function dumps list of all attack techniques in database
        and return them as list of entities.Technique objects
        :return: list of all attack techniques
        """
        my_cursor = self.db_connection.cursor()
        my_cursor.execute(f"SELECT * FROM techniques")
        query_result = my_cursor.fetchall()
        result = [entities.Technique(i[0], i[1]) for i in query_result]
        my_cursor.close()
        return result

    def get_technique(self, technique_id) -> entities.Technique | None:
        """
        Returns a technique by its id

        :param technique_id: id of technique
        :return: entities.Technique or None, if there is no such technique in db
        """
        my_cursor = self.db_connection.cursor()
        my_cursor.execute(f"SELECT * FROM techniques WHERE technique_id = {technique_id}")
        result = my_cursor.fetchone()
        my_cursor.close()
        if result is None:
            return None
        return entities.Technique(technique_id, result[1])

    def get_all_wazuh_alert(self) -> list[entities.Alert]:
        """
        This function dumps list of all alerts in database
        and return them as list of entities.Alert objects
        :return: list of all alerts
        """
        my_cursor = self.db_connection.cursor()
        my_cursor.execute(f"SELECT * FROM alerts")
        query_result = my_cursor.fetchall()
        result = [entities.Alert(i[0], i[1]) for i in query_result]
        my_cursor.close()
        return result

    def get_wazuh_alert(self, alert_id) -> entities.Alert | None:
        """
        Returns an wazuh_alert by it's id

        :param alert_id: alert, which is being used by attacks
        :return: entities.Alert ot None, if there is no such alert in db
        """
        my_cursor = self.db_connection.cursor()
        query = f"SELECT * FROM alerts WHERE alert_id = f{alert_id}"
        my_cursor.execute(query)
        result = my_cursor.fetchone()
        my_cursor.close()
        if result is None:
            return None
        return entities.Alert(alert_id, result[1])

    def get_payloads_used_in_technique(self, technique: int | entities.Technique) -> list[entities.Payload] | None:
        """
        Returns a list of payloads that are used in the given technique
        :param technique: entities.Technique or id of corresponding technique. Will return empty list if technique is not existent, or it does not have any payloads
        :return: list of payloads or None if type of parameter type is wrong
        """
        if isinstance(technique, int):
            technique_id = technique
        elif isinstance(technique, entities.Technique):
            technique_id = technique.uid
        else:
            return None
        cursor = self.db_connection.cursor()
        cursor.execute(
            f"SELECT * FROM payloads WHERE payload_id in "
            f"(SELECT payload_id FROM used_in WHERE technique_id = {technique_id})"
        )
        result = cursor.fetchall()
        cursor.close()
        return [entities.Payload(i[0], i[1]) for i in result]

    def get_alerts_triggered_by_technique(self, technique: int | entities.Technique) -> list[entities.Alert] | None:
        """
        Returns a list of alerts that are triggered by given technique
        :param technique: entities.Technique or id of corresponding technique. Will return empty list if technique is not existent, or it does not trigger any alerts
        :return: list of alerts or None if type of parameter type is wrong
        """
        if isinstance(technique, int):
            technique_id = technique
        elif isinstance(technique, entities.Technique):
            technique_id = technique.uid
        else:
            return None
        cursor = self.db_connection.cursor()
        cursor.execute(f"SELECT * FROM alerts WHERE alerts.alert_id in "
                         f"(SELECT alerts.alert_id FROM triggers WHERE triggers.technique_id = {technique_id})"
                         )
        result = cursor.fetchall()
        cursor.close()
        return [entities.Alert(i[0], i[1]) for i in result]

    def get_techniques_by_alert(self, alert: int | entities.Alert) -> list[entities.Technique] | None:
        """
        This function finds all techniques which trigger given alert
        :param alert: entities.Alert or id of corresponding alert. Will return empty list if alert is not existent, or it is not triggered by any technique
        :return: list of techniques or None if type of parameter type is wrong
        """
        if isinstance(alert, int):
            alert_id = alert
        elif isinstance(alert, entities.Alert):
            alert_id = alert.uid
        else:
            return None
        cursor = self.db_connection.cursor()
        cursor.execute(f"SELECT * FROM techniques WHERE techniques.technique_id in "
                       f"(SELECT techniques.technique_id FROM triggers WHERE triggers.alert_id = {alert_id})"
                       )
        result = cursor.fetchall()
        cursor.close()
        return [entities.Technique(i[0], i[1]) for i in result]

    def get_techniques_by_payload(self, payload: int | entities.Payload) -> list[entities.Technique] | None:
        """
        This function finds all techniques which use given payload
        :param payload: entities.Payload or id of corresponding payload. Will return empty list if payload is not existent, or it does not use any technique
        :return: list of techniques or None if type of parameter type is wrong
        """
        if isinstance(payload, int):
            payload_id = payload
        elif isinstance(payload, entities.Alert):
            payload_id = payload.uid
        else:
            return None
        cursor = self.db_connection.cursor()
        cursor.execute(f"SELECT * FROM techniques WHERE techniques.technique_id in "
                       f"(SELECT techniques.technique_id FROM used_in WHERE used_in.payload_id = {payload_id})"
                       )
        result = cursor.fetchall()
        cursor.close()
        return [entities.Technique(i[0], i[1]) for i in result]
