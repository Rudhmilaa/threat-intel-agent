import json
import requests


def convert_to_ui_format(data):
    """
    Convert saved Kibana objects from Kibana API format to file format used by Kibana UI.

    :param data: Kibana objects as returned from the Kibana API
    :type data: dict
    :return: Converted saved Kibana objects records
    :rtype: dict
    """
    for element in data:
        _attributes = element.pop('attributes', None)
        if _attributes:
            element['_source'] = _attributes
        _id = element.pop('id', None)
        if _id:
            element['_id'] = _id
        _migrationVersion = element.pop('migrationVersion', None)
        if _migrationVersion:
            element['_migrationVersion'] = _migrationVersion
        _type = element.pop('type', None)
        if _type:
            element['_type'] = _type
        _updated_at = element.pop('updated_at', None)
        if _updated_at:
            element['_updated_at'] = _updated_at
        _version = element.pop('version', None)
        if _version:
            element['_version'] = _version
    return data


def convert_from_ui_format(data):
    """
    Convert saved Kibana objects from file format used by Kibana UI to Kibana API format.

    :param data: Kibana objects as returned from the Kibana UI
    :type data: dict
    :return: Converted saved Kibana objects records
    :rtype: dict
    """
    for element in data:
        _attributes = element.pop('_source', None)
        if _attributes:
            element['attributes'] = _attributes
        _id = element.pop('_id', None)
        if _id:
            element['id'] = _id
        _migrationVersion = element.pop('_migrationVersion', None)
        if _migrationVersion:
            element['migrationVersion'] = _migrationVersion
        _type = element.pop('_type', None)
        if _type:
            element['type'] = _type
        _updated_at = element.pop('_updated_at', None)
        if _updated_at:
            element['updated_at'] = _updated_at
        _version = element.pop('_version', None)
        if _version:
            element['version'] = _version
    return data


class StingarKibana:

    """
    Kibana API interface for saving and loading Kibana objects.
    """

    def __init__(self, host='kibana', port=5601):
        """
        :param host: Kibana hostname / IP address
        :type host: str
        :param port: Kibana port
        :type port: int
        """
        self.base_url = "http://%s:%s/kibana/api" % (host, port)
        self.session = requests.session()
        self.session.headers = {'Content-Type': 'application/json'}
        self.session.headers = {'kbn-version': '8.2.3'}

    def get_current_objects(self, index_pattern=True, dashboard=True, visualization=True, search=True,
                            name="", id_only=False):
        """
        Get current Kibana objects from Kibana API.

        :param index_pattern: Return index pattern objects from Kibana API
        :type index_pattern: bool
        :param dashboard: Return dashboard objects from Kibana AP
        :type dashboard: bool
        :param visualization: Return visualization objects from Kibana API
        :type visualization: bool
        :param search: Return search objects from Kibana API
        :type search: bool
        :param name: Name of Kibana object to fetch
        :type name: str
        :param id_only: Return only the id of the Kibana object
        :type id_only: bool
        :return: Current Kibana objects from Kibana API
        :rtype: dict
        """
        url = "%s/saved_objects/_find" % self.base_url

        object_types = []
        if index_pattern:
            object_types.append("index-pattern")
        if dashboard:
            object_types.append("dashboard")
        if visualization:
            object_types.append("visualization")
        if search:
            object_types.append("search")

        params = list()
        params.append(("per_page", 10000))
        params.append(("search", name))
        params.append(("search_fields", "title"))
        if id_only:
            params.append(("fields", "id"))
        params.append(("type", object_types))
        results = self.session.get(url, params=params)
        saved_objects = results.json().get('saved_objects', [])
        return saved_objects

    def import_objects(self, dashboard_data, force=True):
        """
        Import saved Kibana objects to Kibana API in Kibana API JSON format.

        :param dashboard_data: JSON blob for saved Kibana objects
        :type dashboard_data: str
        :param force: Force the loading of Kibana objects even if they already exist in Kibana
        :type force: bool
        :return: JSON response from Kibana API. Will contain saved objects if import was successful.
        :rtype: dict
        """
        data = {"objects": json.loads(dashboard_data)}
        params = {}
        if force:
            params['force'] = True
        url = "%s/saved_objects/_import" % self.base_url
        """
        ^^^ 
        TEST REPLACEMENT FOR DEPRECATED 
        url = "%s/kibana/dashboards/import" % self.base_url
        """
        results = self.session.post(url, params=params, data=json.dumps(data))
        return results.json()
