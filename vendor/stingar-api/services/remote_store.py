import json
import asyncio
import httpx
import time
import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)


def map_honeypot_fields_for_db(honeypot):
    """Map HP_AppStore field names to apiarist database field names."""
    
    field_mapping = {
        'id': 'remote_id',  # HP_AppStore 'id' -> apiarist 'remote_id'
        'created_at': 'created',  # HP_AppStore 'created_at' -> apiarist 'created'
        'local_created_at': 'local_created',  # HP_AppStore 'local_created_at' -> apiarist 'local_created'
        'local_updated_at': 'local_updated',  # HP_AppStore 'local_updated_at' -> apiarist 'local_updated'
        # Note: download_count stays as download_count for database storage
    }
    
    # Fields that should be stored as JSON strings in the database
    json_fields = ['tags', 'supported_protocols', 'default_ports', 'min_requirements', 'configuration_schema', 'default_configuration']
    
    mapped = {}
    for key, value in honeypot.items():
        # Use mapped field name if it exists, otherwise use original
        mapped_key = field_mapping.get(key, key)
        
        # Convert ISO datetime strings to Python datetime objects for SQLite
        if mapped_key in ['created', 'last_updated', 'local_created', 'local_updated'] and value:
            try:
                if isinstance(value, str):
                    # Parse ISO format datetime string
                    mapped[mapped_key] = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                else:
                    mapped[mapped_key] = value
            except (ValueError, TypeError):
                # If parsing fails, set to None
                mapped[mapped_key] = None
        # Convert list/dict fields to JSON strings for database storage
        elif mapped_key in json_fields and value is not None:
            try:
                mapped[mapped_key] = json.dumps(value)
            except (TypeError, ValueError):
                # If JSON serialization fails, store as empty string
                mapped[mapped_key] = ''
        else:
            mapped[mapped_key] = value
    
    return mapped


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class ExpiredAPIKeyError(AuthenticationError):
    """Raised when API key has expired."""
    pass


class RemoteHoneypotStore:
    """
    Client for communicating with HP_AppStore remote honeypot store.
    """

    def __init__(self, base_url: str, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize remote store client.
        
        :param base_url: Base URL of HP_AppStore API
        :param api_key: API key for authentication
        :param timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.session = None

    async def __aenter__(self):
        """Async context manager entry."""
        self.session = httpx.AsyncClient(
            timeout=self.timeout,
            headers=self._get_headers(),
            verify=True  # Enable SSL certificate verification for HTTPS
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.aclose()

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers."""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if self.api_key:
            # Use API-KEY header (preferred by HP_AppStore)
            headers['API-KEY'] = self.api_key
            # Also include Authorization header for compatibility
            headers['Authorization'] = f'Bearer {self.api_key}'
        return headers

    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make HTTP request to remote store.
        
        :param method: HTTP method
        :param endpoint: API endpoint
        :param kwargs: Additional request parameters
        :return: Response data
        """
        if not self.session:
            raise RuntimeError("Client not initialized. Use async context manager.")

        url = urljoin(self.base_url, endpoint)
        
        try:
            response = await self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                # Check if error indicates expired key
                error_text = ""
                try:
                    error_data = e.response.json()
                    error_text = str(error_data).lower()
                    # Also check detail field specifically
                    detail = error_data.get('detail', '')
                    if detail:
                        error_text += " " + detail.lower()
                except:
                    error_text = e.response.text.lower()
                
                is_expired = 'expired' in error_text or 'expiration' in error_text
                
                if is_expired:
                    logger.warning(f"API key expired: {e.response.text}")
                    # Trigger automatic refresh of expired key
                    try:
                        from services.auto_registration import refresh_expired_api_key
                        new_key = refresh_expired_api_key()
                        if new_key:
                            logger.info("API key refreshed successfully, retrying request...")
                            # Update API key and retry request
                            self.api_key = new_key
                            self.session.headers.update(self._get_headers())
                            # Retry the request with new key
                            response = await self.session.request(method, url, **kwargs)
                            response.raise_for_status()
                            return response.json()
                        else:
                            logger.warning("Failed to refresh expired API key, falling back to cached data")
                            raise ExpiredAPIKeyError("API key expired and refresh failed")
                    except ExpiredAPIKeyError:
                        raise
                    except Exception as refresh_error:
                        logger.error(f"Error refreshing expired API key: {refresh_error}")
                        raise ExpiredAPIKeyError("API key expired and refresh failed")
                else:
                    logger.warning(f"Authentication failed: {e.response.text}")
                    raise AuthenticationError("Invalid or missing API key")
            elif e.response.status_code == 403:
                logger.warning(f"Access forbidden: {e.response.text}")
                raise AuthenticationError("API key does not have required permissions")
            else:
                logger.error(f"HTTP error {e.response.status_code}: {e.response.text}")
                raise
        except httpx.RequestError as e:
            logger.error(f"Request error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise

    async def get_honeypots(self, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Get list of available honeypots.
        
        :param params: Query parameters
        :return: List of honeypot metadata
        """
        params = params or {}
        response = await self._make_request('GET', '/api/v2/store/honeypots', params=params)
        return response.get('data', [])

    async def get_honeypot(self, honeypot_id: str) -> Optional[Dict[str, Any]]:
        """
        Get specific honeypot details.
        
        :param honeypot_id: Honeypot ID
        :return: Honeypot metadata
        """
        try:
            response = await self._make_request('GET', f'/api/v2/store/honeypots/{honeypot_id}')
            return response.get('data')
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise

    async def search_honeypots(self, query: str, category: Optional[str] = None, 
                             hp_type: Optional[str] = None, page: int = 1, 
                             per_page: int = 50) -> List[Dict[str, Any]]:
        """
        Search honeypots by criteria.
        
        :param query: Search query
        :param category: Category filter
        :param hp_type: Honeypot type filter
        :param page: Page number for pagination
        :param per_page: Items per page
        :return: List of matching honeypots
        """
        params = {
            'page': page,
            'per_page': per_page
        }
        if query and query.strip():  # Only add query if it's not empty
            params['q'] = query
        if category:
            params['category'] = category
        if hp_type:
            params['hp_type'] = hp_type
            
        response = await self._make_request('GET', '/api/v2/store/search', params=params)
        return response.get('data', [])

    async def get_categories(self) -> List[str]:
        """
        Get available honeypot categories.
        
        :return: List of categories
        """
        response = await self._make_request('GET', '/api/v2/store/categories')
        return response.get('data', [])

    async def generate_template(self, honeypot_config: Dict[str, Any], deployment_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate template files from HP App Store.
        
        Args:
            honeypot_config: Honeypot configuration dictionary
            deployment_info: Optional deployment information
            
        Returns:
            Dictionary with template information and file paths
        """
        # Convert datetime objects to ISO strings for JSON serialization
        def convert_datetime_to_iso(obj):
            if isinstance(obj, datetime.datetime):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {key: convert_datetime_to_iso(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [convert_datetime_to_iso(item) for item in obj]
            else:
                return obj
        
        # Clean the payload to ensure JSON serialization
        clean_config = convert_datetime_to_iso(honeypot_config)
        clean_deployment_info = convert_datetime_to_iso(deployment_info or {})
        
        payload = {
            "config": clean_config,
            "deployment_info": clean_deployment_info,
            "output_dir": ""  # Let HP App Store use default
        }
        
        response = await self._make_request('POST', '/api/v2/store/templates/generate', json=payload)
        return response

    async def download_template_files(self, deployment_id: str) -> Dict[str, str]:
        """
        Download template files for a specific deployment.
        
        Args:
            deployment_id: Deployment ID from template generation
            
        Returns:
            Dictionary with docker-compose.yml and stingar-hp.env content
        """
        files = {}
        
        # Download docker-compose.yml
        try:
            compose_response = await self.session.get(
                urljoin(self.base_url, f'/api/v2/store/templates/{deployment_id}/docker-compose.yml'),
                headers=self._get_headers()
            )
            compose_response.raise_for_status()
            files['docker_compose'] = compose_response.text
        except Exception as e:
            logger.error(f"Failed to download docker-compose.yml for {deployment_id}: {e}")
            raise
        
        # Download stingar-hp.env
        try:
            env_response = await self.session.get(
                urljoin(self.base_url, f'/api/v2/store/templates/{deployment_id}/stingar-hp.env'),
                headers=self._get_headers()
            )
            env_response.raise_for_status()
            files['environment'] = env_response.text
        except Exception as e:
            logger.error(f"Failed to download stingar-hp.env for {deployment_id}: {e}")
            raise
        
        # Download honeypot_config.json
        try:
            config_response = await self.session.get(
                urljoin(self.base_url, f'/api/v2/store/templates/{deployment_id}/honeypot_config.json'),
                headers=self._get_headers()
            )
            config_response.raise_for_status()
            files['config'] = config_response.text
            logger.debug(f"Successfully downloaded honeypot_config.json for {deployment_id}")
        except Exception as e:
            logger.warning(f"Failed to download honeypot_config.json for {deployment_id}: {e}")
            # Don't fail the entire download if config file is missing
            files['config'] = None
        
        return files

    async def get_tags(self) -> List[str]:
        """
        Get available honeypot tags.
        
        :return: List of tags
        """
        response = await self._make_request('GET', '/api/v2/store/tags')
        return response.get('data', [])

    async def health_check(self) -> bool:
        """
        Check if remote store is healthy.
        Health endpoint does not require authentication.
        
        :return: True if healthy, False otherwise
        """
        try:
            # Health check doesn't require authentication
            url = urljoin(self.base_url, '/api/v2/health')
            response = await self.session.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get('status') == 'healthy'
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False


class StoreSyncManager:
    """
    Manager for synchronizing remote honeypot store data with local database.
    """

    def __init__(self, db, remote_store: RemoteHoneypotStore):
        """
        Initialize sync manager.
        
        :param db: Database interface
        :param remote_store: Remote store client
        """
        self.db = db
        self.remote_store = remote_store

    async def sync_honeypots(self) -> Dict[str, Any]:
        """
        Synchronize remote honeypots with local database.
        
        :return: Sync results
        """
        try:
            # Get remote honeypots
            remote_honeypots = await self.remote_store.get_honeypots()
            
            # Get existing local honeypots
            local_honeypots = self.db.get_remote_honeypots({})
            local_ids = {hp['remote_id'] for hp in local_honeypots}
            
            added = 0
            updated = 0
            errors = 0
            
            for remote_hp in remote_honeypots:
                try:
                    remote_id = remote_hp.get('id')
                    if not remote_id:
                        continue
                    
                    # Check if already exists locally
                    existing = next((hp for hp in local_honeypots if hp['remote_id'] == str(remote_id)), None)
                    
                    # Map fields for database storage
                    mapped_hp = map_honeypot_fields_for_db(remote_hp)
                    
                    if existing:
                        # Update existing record
                        self.db.update_remote_honeypot(existing['id'], **mapped_hp)
                        updated += 1
                    else:
                        # Add new record
                        self.db.create_remote_honeypot(**mapped_hp)
                        added += 1
                        
                except Exception as e:
                    logger.error(f"Error syncing honeypot {remote_hp.get('name', 'unknown')}: {e}")
                    errors += 1
            
            return {
                'added': added,
                'updated': updated,
                'errors': errors,
                'total_remote': len(remote_honeypots),
                'total_local': len(local_honeypots)
            }
            
        except Exception as e:
            logger.error(f"Sync failed: {e}")
            raise

    async def sync_categories(self) -> List[str]:
        """
        Synchronize categories from remote store.
        
        :return: List of categories
        """
        try:
            categories = await self.remote_store.get_categories()
            return categories
        except Exception as e:
            logger.error(f"Category sync failed: {e}")
            return []

    async def sync_tags(self) -> List[str]:
        """
        Synchronize tags from remote store.
        
        :return: List of tags
        """
        try:
            tags = await self.remote_store.get_tags()
            return tags
        except Exception as e:
            logger.error(f"Tag sync failed: {e}")
            return []


# Synchronous wrapper for non-async contexts
class SyncRemoteStore:
    """
    Synchronous wrapper for RemoteHoneypotStore.
    """

    def __init__(self, base_url: str, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize sync wrapper.
        
        :param base_url: Base URL of HP_AppStore API
        :param api_key: API key for authentication
        :param timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout

    def _run_async(self, coro):
        """Run async coroutine in sync context."""
        try:
            # Try to get the current event loop
            loop = asyncio.get_running_loop()
            # If we're already in an event loop, we need to create a new one
            # This is a common pattern when calling async code from sync context
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(self._run_in_new_loop, coro)
                return future.result()
        except RuntimeError:
            # No event loop is running, we can create a new one
            return self._run_in_new_loop(coro)
    
    def _run_in_new_loop(self, coro):
        """Run coroutine in a new event loop."""
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    async def _get_client(self):
        """Get async client."""
        async with RemoteHoneypotStore(self.base_url, self.api_key, self.timeout) as client:
            return client

    def get_honeypots(self, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Sync wrapper for get_honeypots."""
        async def _get():
            async with RemoteHoneypotStore(self.base_url, self.api_key, self.timeout) as client:
                try:
                    return await client.get_honeypots(params)
                except ExpiredAPIKeyError:
                    # Key expired - already handled in async client, but refresh failed
                    raise
                except AuthenticationError as e:
                    # Other auth errors - let them propagate
                    raise
        return self._run_async(_get())

    def get_honeypot(self, honeypot_id: str) -> Optional[Dict[str, Any]]:
        """Sync wrapper for get_honeypot."""
        async def _get():
            async with RemoteHoneypotStore(self.base_url, self.api_key, self.timeout) as client:
                return await client.get_honeypot(honeypot_id)
        return self._run_async(_get())

    def search_honeypots(self, query: str, category: Optional[str] = None, 
                        hp_type: Optional[str] = None, page: int = 1, 
                        per_page: int = 50) -> List[Dict[str, Any]]:
        """Sync wrapper for search_honeypots."""
        async def _search():
            async with RemoteHoneypotStore(self.base_url, self.api_key, self.timeout) as client:
                return await client.search_honeypots(query, category, hp_type, page, per_page)
        return self._run_async(_search())

    def get_categories(self) -> List[str]:
        """Sync wrapper for get_categories."""
        async def _get():
            async with RemoteHoneypotStore(self.base_url, self.api_key, self.timeout) as client:
                try:
                    return await client.get_categories()
                except ExpiredAPIKeyError:
                    # Key expired - already handled in async client, but refresh failed
                    raise
                except AuthenticationError as e:
                    # Other auth errors - let them propagate
                    raise
        return self._run_async(_get())

    def get_tags(self) -> List[str]:
        """Sync wrapper for get_tags."""
        async def _get():
            async with RemoteHoneypotStore(self.base_url, self.api_key, self.timeout) as client:
                try:
                    return await client.get_tags()
                except ExpiredAPIKeyError:
                    # Key expired - already handled in async client, but refresh failed
                    raise
                except AuthenticationError as e:
                    # Other auth errors - let them propagate
                    raise
        return self._run_async(_get())

    def health_check(self) -> bool:
        """Sync wrapper for health_check."""
        async def _check():
            async with RemoteHoneypotStore(self.base_url, self.api_key, self.timeout) as client:
                return await client.health_check()
        return self._run_async(_check())

    def generate_template(self, honeypot_config: Dict[str, Any], deployment_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Sync wrapper for generate_template."""
        async def _generate():
            async with RemoteHoneypotStore(self.base_url, self.api_key, self.timeout) as client:
                return await client.generate_template(honeypot_config, deployment_info)
        return self._run_async(_generate())

    def download_template_files(self, deployment_id: str) -> Dict[str, str]:
        """Sync wrapper for download_template_files."""
        async def _download():
            async with RemoteHoneypotStore(self.base_url, self.api_key, self.timeout) as client:
                return await client.download_template_files(deployment_id)
        return self._run_async(_download())