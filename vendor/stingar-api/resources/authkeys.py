import json

import falcon
from falcon.media.validators import jsonschema

from resources import db
from schemas import authkey_schema
from util import json_converter, generate_keypair, encrypt_data


class AuthKeysResource(object):
    """
    SSH Authentication Key API endpoint
    """

    def __init__(self, passphrase, salt):
        """
        Initialize encryption passphrase and salt for SSH authentication key records

        :param passphrase: Encryption passphrase
        :type passphrase: str
        :param salt: Encryption salt
        :type salt: str
        """
        self.passphrase = bytes(passphrase or '', 'utf8')
        self.salt = bytes(salt or '', 'utf8')

    def on_get(self, req, resp):
        """
        Get SSH authentication key records.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = db.get_authkeys(req.params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    @jsonschema.validate(authkey_schema)
    def on_post(self, req, resp):
        """
        Create new SSH authentication key
        :param req: Falcon request
        :param resp: Falcon response
        """
        if not (self.passphrase and self.salt):
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [
                {"title": "Cannot Generate Keys",
                 "description": "Passphrase and salt not set. Please configure these values in stingar.env to generate new keys."}]})
            return
        params = req.media
        name = params['name']
        public_key, private_key = generate_keypair()
        enc_pk = encrypt_data(self.passphrase,
                              self.salt,
                              private_key)
        results = db.create_authkey(name=name,
                                    public_key=public_key.decode("utf8"),
                                    private_key=enc_pk.decode("utf8"))
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class AuthKeyResource(object):
    """
    SSH Authentication Key API endpoint
    """

    def on_get(self, req, resp, ident):
        """
        Get single SSH authentication key record by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the authentication key record
        :type ident: str
        """
        results = db.get_authkey(ident=ident)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "AuthKey Not Found",
                 "description": "AuthKey with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    def on_delete(self, req, resp, ident):
        """
        Delete single SSH authentication key record by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the authentication key record
        :type ident: str
        """
        results = db.delete_authkey(ident=ident)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "AuthKey Not Found",
                 "description": "AuthKey with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)
