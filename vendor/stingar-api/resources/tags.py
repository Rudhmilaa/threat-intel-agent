import json

import falcon
from falcon.media.validators import jsonschema

from resources import db
from schemas import tag_schema
from util import json_converter


class TagsResource(object):
    """
    Honeypot tag API endpoint
    """

    def on_get(self, req, resp):
        """
        Get all honeypot tag records.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = db.get_tags(req.params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    @jsonschema.validate(tag_schema)
    def on_post(self, req, resp):
        """
        Create new honeypot tag record.

        :param req: Falcon request
        :param resp: Falcon response
        """
        params = req.media
        results = db.create_tag(**params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class TagResource(object):
    """
    Honeypot tag API endpoint.
    """

    def on_get(self, req, resp, ident):
        """
        Get single honeypot tag record.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of honeypot tag record
        :type ident: str
        """
        results = db.get_tag(ident=ident)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "Tag Not Found",
                 "description": "Tag with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    def on_delete(self, req, resp, ident):
        """
        Delete single honeypot tag record.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of honeypot tag record
        :type ident: str
        """
        results = db.delete_tag(ident=ident)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "Tag Not Found",
                 "description": "Tag with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)
