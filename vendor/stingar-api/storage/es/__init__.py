from datetime import timedelta

import dateutil.parser
import ipaddress
import elasticsearch
from elasticsearch import Elasticsearch
from elasticsearch_dsl import A, Q, Search
from storage.es.documents import Session, Sensor, DeploymentLog
from util.rule_registry import get_apps_for_rule_types


class StingarES:

    """
    Elasticsearch API interface for accessing STINGAR elasticsearch documents.
    """

    def __init__(self, host='elasticsearch'):
        self.es = Elasticsearch([{'host': host, 'port': 9200, 'scheme': 'http'}])

    def get_sessions(self, params):
        """
        Get honeypot sessions from Elasticsearch.

        :param params: Filter parameters for Sessions by Elasticsearch field name
        :type params: dict
        :return: List of Session records
        :rtype: list
        """
        # Build exclusions
        exclusions = None
        show_data = params.pop('show_data', 'false')
        show_ttylog = params.pop('show_ttylog', 'false')
        sort_field = params.pop('sort', '-start_time')
        start_at = params.pop('start_at', '1')
        rows_per_page = params.pop('rows_per_page', '20')
        index_name = params.pop('index_name', Session.Index.name)
        if show_data == 'false':
            exclusions = ("hp_data",)
        elif show_ttylog == 'false':
            exclusions = ("hp_data.ttylog",)

        return self._get_documents(index_name=index_name, exclusions=exclusions,
                                   sort_field=sort_field, date_field="start_time",
                                   start_at=start_at, rows_per_page=rows_per_page, **params)

    def get_session(self, ident):
        """
        Get single honeypot session from Elasticsearch.

        :param ident: Id of Session record
        :type ident: str
        :return: Session record
        :type: dict
        """
        return self._get_document(index_name=Session.Index.name, ident=ident)

    def get_sensors(self, params):
        """
        Get all sensor objects from Elasticsearch.

        :return: List of Sensor records
        :rtype: list
        """
        sort_field = params.pop('sort', '-created')
        start_at = params.pop('start_at', '1')
        rows_per_page = params.pop('rows_per_page', '5000')
        return self._get_documents(index_name=Sensor.Index.name,
                                   sort_field=sort_field, date_field="created",
                                   start_at=start_at, rows_per_page=rows_per_page, **params)

    def get_sensor(self, ident):
        """
        Get single Sensor record from Elasticsearch.

        :param ident: Id of Sensor record
        :type ident: str
        :return: Sensor record
        :type: dict
        """
        return self._get_documents(index_name=Sensor.Index.name, uuid=ident)

    def delete_sensor(self, ident):
        """
        Delete Sensor record from Elasticsearch.

        :param ident: Id of Sensor
        :type ident: str
        :return: Sensor record
        :type: dict
        """
        # remove all associated sessions.
        d = self.delete_sessions(uuid=ident)

        return self._delete_document(document_type=Sensor, ident=ident)

    def delete_sessions(self, uuid):
        """
        Delete all session records from Elasticsearch.

        :param uuid: Id of Sensor
        :type uuid: str
        :return: Number of deleted sessions
        :type: int
        """
        return self._delete_by_query(uuid=uuid)

    def get_ansible_logs(self, params):
        """
        Get Ansible logs from Elasticsearch.

        :param params: Filter parameters for Ansible Log by Elasticsearch field name
        :type params: dict
        :return: List of Ansible log records
        :rtype: list
        """
        sort_field = params.pop('sort', '-ts')
        start_at = params.pop('start_at', '1')
        rows_per_page = params.pop('rows_per_page', '100')
        match = ("deployment_uuid", "deployment_id", "event")
        return self._get_documents(index_name=DeploymentLog.Index.name, match=match,
                                   sort_field=sort_field, date_field="ts",
                                   start_at=start_at, rows_per_page=rows_per_page, **params)

    def _build_date_specific_indices(self, from_date, to_date):
        """
        Build comma-separated index names from date range (e.g. stingar-2024-03-01,stingar-2024-03-02).
        Falls back to stingar-* if dates are missing or unparseable.
        """
        if not from_date or not to_date:
            return Session.Index.name
        try:
            fd = dateutil.parser.parse(str(from_date))
            td = dateutil.parser.parse(str(to_date))
            if fd > td:
                return Session.Index.name
            indices = []
            current = fd.date()
            end = td.date()
            while current <= end:
                indices.append(f"stingar-{current.isoformat()}")
                current += timedelta(days=1)
            return ','.join(indices) if indices else Session.Index.name
        except (ValueError, TypeError):
            return Session.Index.name

    def get_signatures(self, from_date=None, to_date=None, app_filter='all', rule_types=None, limit=500):
        """
        Extract unique HASSH (Cowrie) and JA3 (Dionaea) signatures from honeypot sessions.

        When app_filter is 'all', runs separate queries per app so Cowrie volume does not
        crowd out Dionaea results (single query limited to 10k hits would favor the dominant app).

        Results are sorted by most recent first (start_time descending). When limit is applied,
        only the N most recent unique signatures per type within the date range are returned.

        Uses date-specific indices (e.g. stingar-2024-03-01,stingar-2024-03-02) instead of stingar-*
        to reduce Elasticsearch query cost.

        :param from_date: Start of date range (ISO 8601 or YYYY-MM-DD)
        :param to_date: End of date range
        :param app_filter: 'cowrie', 'dionaea', or 'all'
        :param rule_types: List of rule types to extract: hassh, ja3, ja3s, ssh_software
        :param limit: Max unique signatures to return per type (most recent by date)
        :return: dict with signatures list and summary
        """
        if rule_types is None:
            rule_types = ['hassh', 'ja3']

        index_name = self._build_date_specific_indices(from_date, to_date)
        signatures = []
        seen_hashes = set()
        scroll_size = 3000  # Reduced from 10k to lower ES load; enough for limit=500 unique per type

        def process_hit(hit, target_app, extractors):
            doc = hit.to_dict()
            hp = doc.get('hp_data') or doc.get('hpData') or {}
            app_name = doc.get('app', '')
            if app_name != target_app:
                return
            src_ip = doc.get('src_ip', '')
            start_time = doc.get('start_time')
            ts_str = start_time.isoformat() if hasattr(start_time, 'isoformat') else str(start_time)

            for sig_type, get_hash in extractors:
                h = get_hash(hp)
                if not h or not isinstance(h, str):
                    continue
                key = (sig_type, h)
                if key not in seen_hashes:
                    seen_hashes.add(key)
                    if len([x for x in signatures if x['type'] == sig_type]) < limit:
                        signatures.append({
                            'type': sig_type,
                            'hash': h,
                            'source': target_app,
                            'count': 1,
                            'first_seen': ts_str,
                            'src_ips': [src_ip] if src_ip else []
                        })
                else:
                    for sig in signatures:
                        if sig['type'] == sig_type and sig['hash'] == h:
                            sig['count'] += 1
                            if src_ip and src_ip not in sig.get('src_ips', []):
                                sig.setdefault('src_ips', []).append(src_ip)
                            break

        def run_query(app_term):
            s = Search(index=index_name, using=self.es)
            # Only fetch fields needed for signature extraction; exclude ttylog and other large hp_data
            s = s.source(includes=[
                'hp_data.kex', 'hp_data.version', 'hp_data.ja3', 'hp_data.ja3s',
                'hpData.kex', 'hpData.version', 'hpData.ja3', 'hpData.ja3s',
                'app', 'src_ip', 'start_time'
            ])
            s = self._build_date_filter(s, field_name='start_time', from_date=from_date, to_date=to_date)
            s = s.filter('term', app=app_term)
            # Sort descending so limit returns the most recent rules by date
            s = s.sort('-start_time')
            s = s[0:scroll_size]
            try:
                return s.execute()
            except elasticsearch.exceptions.NotFoundError:
                return []

        apps_to_query = []
        if app_filter == 'all':
            apps_to_query = get_apps_for_rule_types(rule_types)
        else:
            for app, extractors in get_apps_for_rule_types(rule_types):
                if app == app_filter:
                    apps_to_query.append((app, extractors))
                    break

        for target_app, extractors in apps_to_query:
            response = run_query(target_app)
            for hit in response:
                process_hit(hit, target_app, extractors)

        total_hassh = len([s for s in signatures if s['type'] == 'hassh'])
        total_ja3 = len([s for s in signatures if s['type'] == 'ja3'])
        total_ja3s = len([s for s in signatures if s['type'] == 'ja3s'])
        total_ssh_software = len([s for s in signatures if s['type'] == 'ssh_software'])

        return {
            'signatures': signatures,
            'summary': {
                'total_hassh': total_hassh,
                'total_ja3': total_ja3,
                'total_ja3s': total_ja3s,
                'total_ssh_software': total_ssh_software,
                'date_range': {'from': from_date, 'to': to_date}
            }
        }

    def get_indicators(self, from_date=None, to_date=None, start_at=0, rows_per_page=20):
        """
        Get list of indicators from Elasticsearch

        :param from_date: Start date and time in the format "%Y-%m-%d_%H:%M:%S"
        :type from_date: str
        :param to_date: End date and time in the format "%Y-%m-%d_%H:%M:%S"
        :type to_date: str
        :param start_at: which entry to start at (for pagination)
        :type start_at: int
        :param rows_per_page: Maximum number of records to return
        :type rows_per_page: int
        :return: List of indicators
        :rtype: list
        """
        hits = []
        s = Search(index="stingar-*", using=self.es)

        s = self._build_date_filter(s, field_name="start_time", from_date=from_date, to_date=to_date)

        # Aggregate on src_ip
        a = A('terms', field='src_ip.keyword', size=int(rows_per_page))
        s.aggs.bucket("indicators", a)
        end_at = int(start_at) + int(rows_per_page)
        s = s[int(start_at):end_at]

        response = s.execute()
        for bucket in response.aggregations.indicators.buckets:
            hits.append(bucket.key)
        return hits

    @staticmethod
    def _build_date_filter(search, field_name, from_date=None, to_date=None):
        """
        Constructs a date filter for an Elasticsearch query

        :param search: elasticsearch-dsl Search object
        :type search: Search
        :param field_name: Name of date field to filter on
        :type field_name: str
        :param from_date: Start date and time in the format "%Y-%m-%d_%H:%M:%S"
        :type from_date: str
        :param to_date: End date and time in the format "%Y-%m-%d_%H:%M:%S"
        :type to_date: str
        :return: elasticsearch-dls Search object with applied filter
        :rtype: Search
        """
        from_dt, to_dt = None, None
        if from_date:
            from_dt = dateutil.parser.parse(from_date)
        if to_date:
            to_dt = dateutil.parser.parse(to_date)
        return search.filter('range', **{field_name: {'gte': from_dt, 'lte': to_dt}})

    def _get_documents(self, index_name, exclusions=(), match=(), sort_field=None, date_field=None,
                       start_at=0, rows_per_page=5000, **kwargs):
        """
        Get Elasticsearch documents

        :param index_name: Name of Elasticsearch Index to query
        :type index_name: str
        :param exclusions: Tuple of field names to exclude from results
        :type exclusions: tuple
        :param match: Tuple of elements to match instead of wildcard
        :type match: tuple
        :param date_field: Date field to use for date filter
        :type date_field: str
        :param sort_field: Sort field to use
        :type sort_field: str
        :param start_at: which entry to start on (for pagination)
        :type start_at: int
        :param rows_per_page: Number of documents to return
        :type rows_per_page: int
        :param kwargs: Keyword arguments
        :return: List of Elasticsearch documents
        :rtype: list
        """
        document_list = []
        s = Search(index=index_name, using=self.es)
        # Add field exclusions list
        s = s.source(excludes=exclusions)

        # Sort by field passed in or timestamp
        if sort_field:
            s = s.sort(sort_field)

        # Build date filter
        if date_field:
            s = self._build_date_filter(s, date_field, kwargs.get('from_date'), kwargs.get('to_date'))
            kwargs.pop('from_date', None)
            kwargs.pop('to_date', None)

        # Build src_ip filter (single IP or CIDR) - validated by API layer
        # Use prefix queries for /8-/24 (fast, avoids 65k-term query). Terms for /25-/31 only.
        # Reject prefix_len < 16 (too broad; causes negative shift in /17-/23 path).
        src_ip = kwargs.pop('src_ip', None)
        if src_ip:
            if '/' in src_ip:
                network = ipaddress.ip_network(src_ip, strict=False)
                prefix_len = network.prefixlen
                # Reject /0-/7 and /9-/15 (cause negative shift in /17-/23 path)
                if prefix_len <= 7 or (9 <= prefix_len <= 15):
                    raise ValueError(
                        f"CIDR prefix /{prefix_len} is not supported. Use /8, /16, or /24."
                    )
                if prefix_len <= 24:
                    # Prefix: "152." /8, "152.32." /16, "152.32.185." /24. Also /17-/23 via
                    # multiple prefixes (e.g. /20 = 16 prefixes). Much faster than 65k terms.
                    octets = str(network.network_address).split('.')
                    if prefix_len in (8, 16, 24):
                        n = prefix_len // 8
                        prefix = '.'.join(octets[:n]) + '.'
                        s = s.filter('prefix', **{'src_ip.keyword': prefix})
                    else:
                        # /17-/23: OR of prefix queries (2-128 clauses)
                        step = 256 >> (prefix_len - 16)  # /17:128, /18:64, /20:16, /23:2
                        prefixes = [
                            f"{octets[0]}.{octets[1]}.{i}."
                            for i in range(int(octets[2]), int(octets[2]) + step)
                        ]
                        q = Q('prefix', **{'src_ip.keyword': prefixes[0]})
                        for p in prefixes[1:]:
                            q = q | Q('prefix', **{'src_ip.keyword': p})
                        s = s.filter(q)
                elif prefix_len == 32:
                    s = s.filter('term', **{'src_ip.keyword': str(network.network_address)})
                else:
                    # /25-/31: terms (max 128), acceptable
                    ip_list = [str(ip) for ip in network]
                    if ip_list:
                        s = s.filter('terms', **{'src_ip.keyword': ip_list})
            else:
                s = s.filter('term', **{'src_ip.keyword': src_ip})

        # Build filters from kwargs
        for k, v in kwargs.items():
            if k in match:
                s = s.filter('match', **{k: v})
            else:
                s = s.filter('wildcard', **{k: v})

        try:
            # Get total number so we can provide that to the caller
            # so they can calculate how many pages of data will be needed.
            count = s.count()
            if int(start_at) < 1:
                start_at = 1

            end_at = int(start_at)-1 + int(rows_per_page)
            s = s[int(start_at)-1:end_at]

            response = s.execute()
        except elasticsearch.exceptions.NotFoundError:
            return {"count": 0, "documents": []}

        for hit in response:
            document = hit.to_dict()
            document.update(id=hit.meta.id)
            document_list.append(document)
        return {"count": count, "documents": document_list}

    def _get_document(self, index_name, ident):
        """
        Get Elasticsearch document by Id

        :param index_name: Name of Elasticsearch Index to query
        :type index_name: str
        :param ident: Document Id
        :type ident: str
        :return: Elasticsearch document
        :rtype: dict
        """
        s = Search(index=index_name, using=self.es)
        s = s.query("match", _id=ident)
        response = s.execute()
        if response:
            document_dict = response[0].to_dict()
            document_dict.update(id=response[0].meta.id)
            return document_dict
        else:
            return {}

    def _delete_document(self, document_type, ident):
        """
        Generic Elasticsearch document deletion.

        :param document_type: Type of document to delete in Elasticsearch
        :type document_type: class
        :param ident: Document Id
        :type ident: str
        :return: Deleted document
        :rtype: dict
        """
        try:
            document = document_type.get(using=self.es, id=ident)
            document.delete(using=self.es)
            document_dict = document.to_dict()
            document_dict.update(id=document.meta.id)
            return document_dict
        except elasticsearch.exceptions.NotFoundError:
            return {}

    def _delete_by_query(self, uuid):
        """
        Elasticsearch delete_by_query of all sessions for a specific sensor.uuid value

        :param uuid: UUID of sensor to delete all sessions from Elasticsearch
        :type uuid: str
        :return: number deleted session records
        :rtype: int 
        """
        s = Search(index="stingar-*", using=self.es)
        s = s.query("match", sensor__uuid=uuid)
        try:
            response = s.delete() 
        except elasticsearch.exceptions.NotFoundError:
            return 0

        return response

