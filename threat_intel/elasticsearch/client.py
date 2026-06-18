"""Lightweight Elasticsearch HTTP client (urllib, no elasticsearch-py dependency)."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Optional

log = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9200


def es_base_url() -> str:
    explicit = os.getenv("ELASTICSEARCH_URL")
    if explicit:
        return explicit.rstrip("/")
    host = os.getenv("ELASTICSEARCH_HOST", os.getenv("ES_HOST", DEFAULT_HOST))
    port = os.getenv("ELASTICSEARCH_PORT", os.getenv("ES_PORT", str(DEFAULT_PORT)))
    scheme = os.getenv("ELASTICSEARCH_SCHEME", "http")
    return f"{scheme}://{host}:{port}"


class ElasticsearchClient:
    def __init__(self, base_url: Optional[str] = None, timeout: int = 30):
        self.base_url = (base_url or es_base_url()).rstrip("/")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        *,
        allow_404: bool = False,
    ) -> dict:
        url = f"{self.base_url}/{path.lstrip('/')}"
        data = None
        headers = {"Content-Type": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:
                if allow_404 and exc.code == 404:
                    return {}
                if exc.code in (429, 502, 503, 504) and attempt < 4:
                    log.warning("ES %s on %s, retry %s", exc.code, path, attempt + 1)
                    continue
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", errors="replace")[:600]
                except Exception:
                    pass
                raise RuntimeError(f"Elasticsearch {exc.code} on {path}: {detail}") from exc
            except urllib.error.URLError as exc:
                if attempt < 4:
                    log.warning("ES unreachable (%s), retry %s", exc.reason, attempt + 1)
                    continue
                raise RuntimeError(f"Elasticsearch unreachable at {self.base_url}: {exc.reason}") from exc
        return {}

    def ping(self) -> bool:
        try:
            result = self.request("GET", "")
            return bool(result.get("version") or result.get("cluster_name"))
        except RuntimeError:
            return False

    def put_template(self, name: str, template: dict) -> None:
        self.request("PUT", f"_index_template/{name}", template)

    def put_ilm_policy(self, name: str, policy: dict) -> None:
        self.request("PUT", f"_ilm/policy/{name}", policy)

    def index_document(self, index: str, doc: dict, doc_id: Optional[str] = None) -> dict:
        path = f"{index}/_doc"
        if doc_id:
            path = f"{index}/_doc/{doc_id}"
        return self.request("PUT" if doc_id else "POST", path, doc)

    def get_document(self, index: str, doc_id: str) -> Optional[dict]:
        result = self.request("GET", f"{index}/_doc/{doc_id}", allow_404=True)
        if not result:
            return None
        return result.get("_source")

    def mget_documents(self, index: str, doc_ids: list[str]) -> dict[str, dict]:
        if not doc_ids:
            return {}
        body = {"ids": doc_ids}
        result = self.request("POST", f"{index}/_mget", body)
        found: dict[str, dict] = {}
        for item in result.get("docs", []):
            if item.get("found"):
                found[item["_id"]] = item["_source"]
        return found

    def search(self, index: str, body: dict) -> dict:
        return self.request("POST", f"{index}/_search", body)
