import json
import falcon
from resources import es
from util import json_converter


class SensorsResource(object):
    """
    Honeypot Sensor API endpoint.

    Handles sensor status records as returned by the honeypots to Elasticsearch.
    """

    def on_get(self, req, resp):
        """
        Get all honeypot sensor records.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = es.get_sensors(req.params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class SensorResource(object):

    def on_get(self, req, resp, ident):
        """
        Get single honeypot sensor record by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the honeypot sensor record
        """
        results = es.get_sensor(ident=ident)
        if not results:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "Sensor Not Found",
                 "description": "Sensor with id '" + ident + "' not found."}]})
        else:
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    def on_delete(self, req, resp, ident):
        """
        Delete single honeypot sensor by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the honeypot sensor 
        """
        results = es.delete_sensor(ident=ident) 
        if not results:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "Sensor Not Found",
                 "description": "Sensor with id '" + ident + "' not found."}]})
        else:
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

class StopSensorResource(object):
    """
    Handles sensor management request sent from UI and passed to Langstroth for delopyment via Ansible playbooks
    """
    def on_put(self, req, resp, ident):
        """
        Stop honeypot sensor via Langstroth.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: Falcon response
        """
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": "Stop:" + ident}, default=json_converter, ensure_ascii=False)
	#print("API received the Manage Sensor request" + req + " : " + resp + " : id: " + ident) 
        #resp.status = falcon.HTTP_200

class StartSensorResource(object):
    """
    Handles sensor management request sent from UI and passed to Langstroth for delopyment via Ansible playbooks
    """
    def on_put(self, req, resp, ident):
        """
        Stop honeypot sensor via Langsrtoth.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: Falcon response
        """
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": "Start:" + ident}, default=json_converter, ensure_ascii=False)

class RestartSensorResource(object):
    """
    Handles sensor management request sent from UI and passed to Langstroth for delopyment via Ansible playbooks
    """
    def on_put(self, req, resp, ident):
        """
        Restart honeypot sensor via Langsrtoth.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: Falcon response
        """
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": "Restart:" + ident}, default=json_converter, ensure_ascii=False)
