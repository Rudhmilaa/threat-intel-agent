import json

import falcon

from resources import es
from util import json_converter


class IndicatorResource(object):
    """
    Indicator API endpoint for getting list of indicators.
    """

    def on_get(self, req, resp):
        """
        Get list of honeypot indicators.

        :param req: Falcon request
        :param resp: Falcon response
        """
        params = dict(req.params)
        df = req.get_param('format') or ''
        if df:
            del(params['format'])

        results = es.get_indicators(**params)

        # Apply delimited specified by 'format' parameter
        resp.status = falcon.HTTP_200
        if df == 'newline':
            resp.text = "\n".join(results)
        elif df == 'space':
            resp.text = " ".join(results)
        elif df == 'comma':
            resp.text = ",".join(results)
        else:
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=True)
