import json
import os
from datetime import datetime, timedelta

import dateutil.parser
import falcon

from resources import es
from util import json_converter


def _parse_sessions_date_range(date_range_str):
    """
    Parse SESSIONS_DEFAULT_DATE_RANGE (e.g. 24h, 7d) to timedelta.
    Default 24h to stay under typical Elasticsearch 10k hit limit.
    """
    val = (date_range_str or '24h').strip().lower()
    try:
        if val.endswith('d'):
            return timedelta(days=int(val[:-1]))
        if val.endswith('h'):
            return timedelta(hours=int(val[:-1]))
        return timedelta(hours=24)
    except (ValueError, TypeError):
        return timedelta(hours=24)


def _validate_date_range(from_date, to_date, max_days=90):
    """
    Validate from_date and to_date. Raises ValueError if invalid.
    """
    if not from_date or not to_date:
        return
    try:
        from datetime import datetime
        fd = dateutil.parser.parse(str(from_date))
        td = dateutil.parser.parse(str(to_date))
        if fd > td:
            raise ValueError("from_date must be before or equal to to_date")
        delta = td - fd
        if delta.days > max_days:
            raise ValueError(f"Date range cannot exceed {max_days} days")
    except ValueError as e:
        if "from_date" in str(e) or "exceed" in str(e):
            raise
        raise ValueError("Invalid from_date or to_date format (use ISO 8601, e.g. YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")


def _validate_src_ip_filter(value):
    """
    Validate IP address or CIDR format for src_ip filter.
    Returns True if valid, raises ValueError with message if invalid.
    Rejects CIDR with prefix_len < 16 (too broad; causes backend errors).
    """
    if not value or not isinstance(value, str):
        raise ValueError("src_ip filter is required")
    value = value.strip()
    if not value:
        raise ValueError("src_ip filter cannot be empty")

    try:
        import ipaddress
        # Try single IP first
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            pass
        # Try CIDR
        try:
            network = ipaddress.ip_network(value, strict=False)
            # Reject /0-/7 and /9-/15 (cause backend crash). Allow /8, /16, /17-/32.
            if network.prefixlen <= 7 or (9 <= network.prefixlen <= 15):
                raise ValueError(
                    f"CIDR prefix /{network.prefixlen} is not supported. Use /8, /16, or /24 (e.g. 10.0.0.0/8, 147.224.0.0/16)"
                )
            return True
        except ValueError as e:
            if "too broad" in str(e):
                raise
            pass
        raise ValueError(f"Invalid IP or CIDR format: {value}")
    except ImportError:
        # Fallback: basic regex for IPv4 and CIDR
        import re
        ipv4 = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        ipv4_cidr = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
        if re.match(ipv4, value) or re.match(ipv4_cidr, value):
            return True
        raise ValueError(f"Invalid IP or CIDR format: {value}")


class SessionResource(object):
    """
    Honeypot session data API endpoint.
    """

    def on_get(self, req, resp, ident):
        """
        Get honeypot session record by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the honeypot session record
        """
        results = es.get_session(ident=ident)
        if not results:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "Session Not Found",
                 "description": "Session with id '" + ident + "' not found."}]})
        else:
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    def on_delete(self, req, resp, ident):
        """
        Delete honeypot session records by sensor id.

        :param req: Falcon request
        :param resp: Falcon response
        :param uuid: id of the honeypot sensor_id 
        """
        #Debug results = es.delete_sessions_by_sensor_id(uuid=ident)
        results = es.delete_sessions(uuid=ident)

class SessionsResource(object):

    def on_get(self, req, resp):
        """
        Get all honeypot session records.

        :param req: Falcon request
        :param resp: Falcon response
        """
        params = dict(req.params)
        src_ip = params.pop('src_ip', None)
        to_dt = datetime.utcnow()
        # Apply default date range when not specified
        if 'from_date' not in params and 'to_date' not in params:
            delta = _parse_sessions_date_range(
                os.environ.get('SESSIONS_DEFAULT_DATE_RANGE', '24h')
            )
            if src_ip is not None:
                today = to_dt.strftime('%Y-%m-%d')
                yesterday = (to_dt - timedelta(days=1)).strftime('%Y-%m-%d')
                params['index_name'] = f"stingar-{yesterday},stingar-{today}"
            from_dt = to_dt - delta
            params['from_date'] = from_dt.strftime('%Y-%m-%dT%H:%M:%S')
            params['to_date'] = to_dt.strftime('%Y-%m-%dT%H:%M:%S')
        else:
            # Custom from_date/to_date provided: use date-specific indices
            from_date = params.get('from_date')
            to_date = params.get('to_date')
            try:
                _validate_date_range(from_date, to_date)
            except ValueError as e:
                resp.status = falcon.HTTP_400
                resp.text = json.dumps({
                    "errors": [{
                        "title": "Invalid date range",
                        "description": str(e)
                    }]
                })
                return
            params['index_name'] = es._build_date_specific_indices(from_date, to_date)
        if src_ip is not None:
            try:
                _validate_src_ip_filter(src_ip)
            except ValueError as e:
                resp.status = falcon.HTTP_400
                resp.text = json.dumps({
                    "errors": [{
                        "title": "Invalid src_ip filter",
                        "description": str(e)
                    }]
                })
                return
            params['src_ip'] = src_ip

        try:
            results = es.get_sessions(params)
        except ValueError as e:
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({
                "errors": [{
                    "title": "Invalid src_ip filter",
                    "description": str(e)
                }]
            })
            return
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    #def on_delete_sessions_by_sensor_id(self, req, resp, uuid):
    def on_delete(self, req, resp, ident):
        """
        Delete honeypot session records by sensor id.

        :param req: Falcon request
        :param resp: Falcon response
        :param uuid: id of the honeypot sensor_id 
        """
        #DEBUG results = es.delete_sessions_by_sensor_id(uuid=ident)
        results = es.delete_sessions(uuid=ident)
