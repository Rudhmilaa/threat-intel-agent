import json
import base64
import logging
import binascii
import datetime

import falcon

from resources import kb, db
from util import json_converter


class KibanaObjectsResource(object):
    """
    Kibana objects API endpoint for fetching objects from the Kibana API.
    """

    def on_get(self, req, resp):
        """
        Get all Kibana object records as returned by the Kibana API.

        :param req: Falcon request
        :param resp: Falcon response
        """
        name = req.params.get('name', '')
        id_only = req.params.get('id_only', 'false')
        object_type = req.params.get('type', '')

        params = dict()
        params['name'] = name
        if id_only.lower() == "true":
            params['id_only'] = True

        if object_type == "dashboard":
            params['dashboard'] = True
            params['visualization'] = False
            params['index_pattern'] = False
            params['search'] = False

        results = kb.get_current_objects(**params)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "Kibana Objects Not Found.",
                 "description": "Unable to fetch Kibana objects."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class KibanaObjectsLoadActiveResource(object):
    """
    Kibana saved objects API endpoint for loading currently active Kibana config.
    """

    def on_post(self, req, resp):
        """
        Load saved Kibana objects into Kibana for record currently set to 'active'.

        :param req: Falcon request
        :param resp: Falcon response
        """
        saved_objects = db.get_kibana_objects({"active": 1})
        if len(saved_objects) == 0:
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [
                {"title": "Kibana Objects Not Found.",
                 "description": "No saved Kibana objects found."}]})
            return
        b64_objects = saved_objects[0].get('objects', '')
        try:
            objects = base64.b64decode(b64_objects)
        except (binascii.Error, TypeError, ValueError) as e:
            logging.error(e)
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [
                {"title": "Can't decode base64.",
                 "description": "Kibana object not stored in valid base64 format."}]})
            return
        results = kb.import_objects(objects, force=True)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class KibanaObjectsLoadResource(object):
    """
    Kibana saved objects API endpoint for loading Kibana config.
    """

    def on_post(self, req, resp, ident):
        """
        Load saved Kibana objects into Kibana by id and set status to 'active'.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the saved Kibana objects record
        """
        record = db.set_kibana_objects_active(ident)
        if not record:
            resp.text = json.dumps({"errors": [
                {"title": "Saved Objects Not Found",
                 "description": "Saved objects record with ident %s not found." % ident}]})
        b64_objects = record.get('objects', '')
        try:
            objects = base64.b64decode(b64_objects)
        except (binascii.Error, TypeError, ValueError) as e:
            logging.error(e)
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [
                {"title": "Can't decode base64.",
                 "description": "Kibana object not stored in valid base64 format."}]})
            return
        results = kb.import_objects(objects, force=True)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class KibanaObjectsSaveResource(object):
    """
    Kibana saved objects API endpoint for saving current Kibana config into database.
    """

    def on_post(self, req, resp):
        """
        Create new saved Kibana objects record from current objects in Kibana.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = kb.get_current_objects()

        description = "default"
        active = 1
        created = datetime.datetime.now()
        objects = json.dumps(results)
        results = db.create_kibana_object(active=active, description=description, created=created, objects=objects)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class KibanaSavedObjectsResource(object):
    """
    Kibana saved objects API endpoint.
    """

    def on_get(self, req, resp):
        """
        Get all saved Kibana objects records.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = db.get_kibana_objects(req.params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class KibanaSavedObjectResource(object):
    """
    Kibana saved objects API endpoint.
    """

    def on_get(self, req, resp, ident):
        """
        Get single saved Kibana objects records by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the saved Kibana objects record
        :type ident: str
        """
        results = db.get_kibana_object(ident=ident)
        if not results:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "User Not Found",
                 "description": "User with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)
