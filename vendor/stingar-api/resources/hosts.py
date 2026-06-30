import json

import falcon
from falcon.media.validators import jsonschema

from resources import db
from schemas import host_schema
from util import json_converter


class HostsResource(object):
    """
    Honeypot hosts API endpoint.
    """

    def on_get(self, req, resp):
        """
        Get all honeypot host records.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = db.get_hosts(params=req.params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    @jsonschema.validate(host_schema)
    def on_post(self, req, resp):
        """
        Create new honeypot host record.

        :param req: Falcon request
        :param resp: Falcon response
        """
        params = req.media
        address = params['address']
        if db.get_hosts({"address": address}):
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [
                {"title": "Host Exists",
                 "description": "Host with address '" + address + "' already exists."}]})
        else:
            results = db.create_host(**params)
            resp.status = falcon.HTTP_200
            resp.text = json.dumps(results, default=json_converter, ensure_ascii=False)


class HostResource(object):
    """
    Honeypot host API endpoint
    """

    def on_get(self, req, resp, ident):
        """
        Get single honeypot host record.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of honeypot host record
        :type ident: str
        """
        results = db.get_host(ident=ident)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "Host Not Found",
                 "description": "Host with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    @jsonschema.validate(host_schema)
    def on_put(self, req, resp, ident):
        """
        Update single honeypot host record.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of honeypot host record
        :type ident: str
        """
        params = req.media
        if not db.get_host(ident=ident):
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "Deployment Not Found",
                 "description": "Deployment with id '" + ident + "' not found."}]})
        else:
            results = db.update_host(ident, **params)
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    def on_delete(self, req, resp, ident):
        """
        Delete single honeypot host record.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of honeypot host record
        :type ident: str
        """
        results = db.delete_host(ident)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "Host Not Found",
                 "description": "Host with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)
