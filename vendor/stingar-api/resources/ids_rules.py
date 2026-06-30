"""
IDS Rules API endpoints for extracting Suricata rules from honeypot signatures.
"""

import json
import os
from datetime import datetime, timedelta

import falcon

from resources import es
from util import json_converter
from util.suricata_rules import generate_rules
from util.snort_rules import generate_snort_rules
from services.ids_rules_feed import get_feed_state, get_cache_path, generate_rules_and_cache, is_cache_fresh


def _parse_date(val, default):
    """Parse date string; return default if invalid or None."""
    if not val:
        return default
    try:
        return datetime.fromisoformat(val.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return default


def _parse_rule_types(val):
    """Parse comma-separated rule types into list."""
    if not val:
        return ['hassh', 'ja3']
    return [x.strip().lower() for x in val.split(',') if x.strip()]


def _parse_format(val):
    """Parse format param; suricata or snort. Default suricata."""
    fmt = (val or 'suricata').strip().lower()
    return fmt if fmt in ('suricata', 'snort') else 'suricata'


def _generate_rules_for_format(signatures, fmt):
    """Generate rules text for the given format."""
    if fmt == 'snort':
        return generate_snort_rules(signatures)
    return generate_rules(signatures)


class IDSRulesResource(object):
    """
    IDS Rules API: extract signatures and return JSON.
    """

    def on_get(self, req, resp):
        """
        Get extracted signatures from honeypot sessions.

        Query params: from_date, to_date, app, rule_types, limit
        """
        to_date = _parse_date(req.get_param('to_date'), datetime.utcnow())
        from_date = _parse_date(
            req.get_param('from_date'),
            to_date - timedelta(days=7)
        )
        app_filter = (req.get_param('app') or 'all').lower()
        if app_filter not in ('cowrie', 'dionaea', 'all'):
            app_filter = 'all'
        rule_types = _parse_rule_types(req.get_param('rule_types'))
        limit = min(int(req.get_param('limit') or 500), 1000)

        results = es.get_signatures(
            from_date=from_date.isoformat(),
            to_date=to_date.isoformat(),
            app_filter=app_filter,
            rule_types=rule_types,
            limit=limit
        )

        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class IDSRulesPreviewResource(object):
    """
    IDS Rules Preview: return Suricata rules as text for display in UI.
    Same params as export; returns text/plain for editable preview.
    """

    def on_get(self, req, resp):
        """
        Get extracted rules as text for preview. Query params same as IDSRulesResource.
        """
        to_date = _parse_date(req.get_param('to_date'), datetime.utcnow())
        from_date = _parse_date(
            req.get_param('from_date'),
            to_date - timedelta(days=7)
        )
        app_filter = (req.get_param('app') or 'all').lower()
        if app_filter not in ('cowrie', 'dionaea', 'all'):
            app_filter = 'all'
        rule_types = _parse_rule_types(req.get_param('rule_types'))
        limit = min(int(req.get_param('limit') or 500), 1000)
        fmt = _parse_format(req.get_param('format'))

        results = es.get_signatures(
            from_date=from_date.isoformat(),
            to_date=to_date.isoformat(),
            app_filter=app_filter,
            rule_types=rule_types,
            limit=limit
        )

        rules_text = _generate_rules_for_format(results.get('signatures', []), fmt)

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/plain; charset=utf-8'
        resp.text = rules_text


class IDSRulesExportResource(object):
    """
    IDS Rules Export: return Suricata .rules file for download.
    """

    def on_get(self, req, resp):
        """
        Export Suricata rules as downloadable file.

        Query params: same as IDSRulesResource
        """
        to_date = _parse_date(req.get_param('to_date'), datetime.utcnow())
        from_date = _parse_date(
            req.get_param('from_date'),
            to_date - timedelta(days=7)
        )
        app_filter = (req.get_param('app') or 'all').lower()
        if app_filter not in ('cowrie', 'dionaea', 'all'):
            app_filter = 'all'
        rule_types = _parse_rule_types(req.get_param('rule_types'))
        limit = min(int(req.get_param('limit') or 500), 1000)
        fmt = _parse_format(req.get_param('format'))

        results = es.get_signatures(
            from_date=from_date.isoformat(),
            to_date=to_date.isoformat(),
            app_filter=app_filter,
            rule_types=rule_types,
            limit=limit
        )

        rules_text = _generate_rules_for_format(results.get('signatures', []), fmt)
        filename = 'stingar-honeypot-snort.rules' if fmt == 'snort' else 'stingar-honeypot.rules'

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/plain; charset=utf-8'
        resp.set_header(
            'Content-Disposition',
            f'attachment; filename="{filename}"'
        )
        resp.text = rules_text


class IDSRulesFeedResource(object):
    """
    IDS Rules Feed: serve rules for IDS devices. On-demand generation with 5-minute cache.
    If cache is fresh, serve from disk; otherwise generate, cache, and serve. No 503 on cold start.
    """

    def on_get(self, req, resp):
        """Serve rules file. Cache-first; generate on miss."""
        from resources.store_config import read_stingar_env

        fmt = _parse_format(req.get_param('format'))
        cache_path = get_cache_path(fmt)
        env = read_stingar_env()
        ttl = int(env.get('IDS_RULES_FEED_CACHE_TTL', '300'))
        date_range_str = env.get('IDS_RULES_FEED_DATE_RANGE', '30d')

        if is_cache_fresh(cache_path, ttl):
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    rules_text = f.read()
            except OSError as e:
                resp.status = falcon.HTTP_500
                resp.media = {'errors': [{'title': 'Internal Server Error', 'description': str(e)}]}
                return
        else:
            try:
                rules_text, _ = generate_rules_and_cache(fmt, date_range_str)
            except Exception as e:
                resp.status = falcon.HTTP_500
                resp.media = {'errors': [{'title': 'Internal Server Error', 'description': str(e)}]}
                return

        filename = 'stingar-honeypot-snort.rules' if fmt == 'snort' else 'stingar-honeypot.rules'
        resp.status = falcon.HTTP_200
        resp.content_type = 'text/plain; charset=utf-8'
        resp.set_header('Content-Disposition', f'inline; filename="{filename}"')
        resp.set_header('Cache-Control', f'max-age={ttl}')
        resp.text = rules_text


class IDSRulesStatusResource(object):
    """
    IDS Rules Status: last generation time and signature counts.
    Requires API-KEY.
    """

    def on_get(self, req, resp):
        """Return feed status: last_generated, counts, feed_url."""
        state = get_feed_state()
        resp.status = falcon.HTTP_200
        resp.media = {
            'data': {
                'last_generated': state.get('last_generated'),
                'total_hassh': state.get('total_hassh', 0),
                'total_ja3': state.get('total_ja3', 0),
                'total_ja3s': state.get('total_ja3s', 0),
                'total_ssh_software': state.get('total_ssh_software', 0),
                'date_range': state.get('date_range'),
                'feed_url': '/api/v2/ids-rules/feed',
                'feed_url_suricata': '/api/v2/ids-rules/feed?format=suricata',
                'feed_url_snort': '/api/v2/ids-rules/feed?format=snort'
            }
        }
