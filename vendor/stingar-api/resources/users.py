import json
import logging

import falcon
from falcon.media.validators import jsonschema

from resources import db
from schemas import user_schema, auth_schema
from util import json_converter


class UsersResource(object):
    """
    STINGAR users API endpoint.
    """

    def on_get(self, req, resp):
        """
        Get all STINGAR user records.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = db.get_users(req.params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    @jsonschema.validate(user_schema)
    def on_post(self, req, resp):
        """
        Create new STINGAR user record.

        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            params = req.media
        except Exception as e:
            logging.warning(e)
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [
                {"title": "Missing Data",
                 "description": "Malformed POST body."}]})
            return

        username = params.get("username")
        password = params.get("password", "")
        email = params.get("email", "")

        if not username:
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [
                {"title": "Missing Data",
                 "description": "Missing username parameter in POST body."}]})
            return

        if db.get_user_by_username(username=username):
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [
                {"title": "User Exists",
                 "description": "User with username '" + username + "' already exists."}]})
        else:
            results = db.create_user(username=username, email=email, password=password)
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class UserResource(object):
    """
    STINGAR user API endpoint.
    """

    def on_get(self, req, resp, ident):
        """
        Get single STINGAR user record by id

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of STINGAR user record
        :type ident: str
        """
        results = db.get_user(ident=ident)
        if not results:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "User Not Found",
                 "description": "User with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    @jsonschema.validate(user_schema)
    def on_put(self, req, resp, ident):
        """
        Update single STINGAR user record by id

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of STINGAR user record
        :type ident: str
        """
        try:
            params = req.media
        except Exception as e:
            logging.warning(e)
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [
                {"title": "Missing Data",
                 "description": "Malformed POST body."}]})
            return

        email = params.get("email", "")
        password = params.get("password", "")

        if not db.get_user(ident=ident):
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "User Not Found",
                 "description": "User with id '" + ident + "' not found."}]})
        else:
            results = db.update_user(ident=ident, email=email, password=password)
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    def on_delete(self, req, resp, ident):
        """
        Delete single STINGAR user record by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of STINGAR user record
        :type ident: str
        """
        results = db.delete_user(ident)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "User Not Found",
                 "description": "User with ident '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class AuthenticationResource(object):
    """
    API endpoint for validating authentication of STINGAR user.
    """

    @jsonschema.validate(auth_schema)
    def on_post(self, req, resp):
        """
        Validate whether user credentials are valid.

        :param req: Falcon request
        :param resp: Falcon response
        """
        params = req.media
        username = params['username']
        password = params['password']
        results = db.get_user_password(username=username, password=password)
        if not results:
            resp.status = falcon.HTTP_401
            resp.text = json.dumps({"errors": [
                {"title": "Authentication Failed",
                 "description": "Incorrect username or password."}]})
        else:
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class TokenResource(object):
    """
    API endpoint for handling STINGAR user API tokens.
    """

    def on_get(self, req, resp, ident):
        """
        Get API token for single user by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of STINGAR user record
        :type ident: str
        """
        results = db.get_user(ident=ident)
        if not results:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "User Not Found",
                 "description": "User with Id '" + ident + "' not found."}]})

        else:
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"token": results['token']}, default=json_converter, ensure_ascii=False)

    def on_put(self, req, resp, ident):
        """
        Update API token for single user by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of STINGAR user record
        :type ident: str
        """
        results = db.update_user(ident=ident, update_token=True)
        if not results:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "User Not Found",
                 "description": "User with Id '" + ident + "' not found."}]})
        else:
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)
