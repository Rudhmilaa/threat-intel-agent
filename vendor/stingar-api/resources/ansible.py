import json

import falcon

from resources import es
from util import json_converter


class AnsibleLogsResource(object):

    """
    Ansible Log API endpoint
    """

    def on_get(self, req, resp):
        """
        Get Ansible logs.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = es.get_ansible_logs(req.params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)
