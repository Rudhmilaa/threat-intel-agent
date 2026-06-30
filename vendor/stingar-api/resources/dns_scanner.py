"""
Proxy resources for DNS vulnerability scanner endpoints.
Forwards requests to HP App Store.
"""

import falcon
import json
import httpx
import logging
from services.remote_store import SyncRemoteStore
from config.remote_store import remote_store_config
from resources.store import safe_log_config

logger = logging.getLogger(__name__)


class DNSScannerScanResource(object):
    """
    Proxy resource for DNS scanner scan endpoints.
    Forwards requests to HP App Store.
    """
    
    def _proxy_request(self, req, resp, method: str, endpoint_suffix: str = ''):
        """
        Proxy request to HP App Store.
        
        :param req: Falcon request
        :param resp: Falcon response
        :param method: HTTP method
        :param endpoint_suffix: Additional path after /dns-scanner
        """
        try:
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            remote_store = SyncRemoteStore(
                base_url=config['base_url'],
                api_key=config['api_key'] if config['api_key'] else None,
                timeout=config['timeout']
            )
            
            endpoint = f'/api/v2/dns-scanner{endpoint_suffix}'
            
            request_data = None
            if method in ['POST', 'PATCH', 'PUT']:
                try:
                    request_data = req.media
                except:
                    request_data = None
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            if config['api_key']:
                headers['API-KEY'] = config['api_key']
            
            params = dict(req.params) if req.params else {}
            
            url = f"{config['base_url'].rstrip('/')}{endpoint}"
            
            with httpx.Client(timeout=config['timeout']) as client:
                if method == 'GET':
                    response = client.get(url, headers=headers, params=params)
                elif method == 'POST':
                    response = client.post(url, headers=headers, json=request_data, params=params)
                elif method == 'PATCH':
                    response = client.patch(url, headers=headers, json=request_data, params=params)
                elif method == 'DELETE':
                    response = client.delete(url, headers=headers, params=params)
                else:
                    resp.status = falcon.HTTP_405
                    resp.text = json.dumps({"errors": [
                        {"title": "Method Not Allowed",
                         "description": f"Method {method} not supported."}]})
                    return
                
                resp.status = getattr(falcon, f'HTTP_{response.status_code}', falcon.HTTP_500)
                try:
                    resp.text = response.text
                    resp.content_type = 'application/json'
                except:
                    resp.text = json.dumps({"errors": [
                        {"title": "Proxy Error",
                         "description": "Failed to proxy request to remote store."}]})
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException, httpx.NetworkError) as e:
            # Connection errors indicate HP App Store is unavailable
            logger.warning(f"HP App Store unavailable for DNS scanner request: {e}")
            resp.status = falcon.HTTP_503
            resp.text = json.dumps({"errors": [
                {"title": "Service Unavailable",
                 "description": "HP App Store is currently unavailable."}]})
        except httpx.HTTPStatusError as e:
            # HTTP error responses from HP App Store - pass through the status code
            logger.error(f"HTTP error from HP App Store: {e}")
            resp.status = getattr(falcon, f'HTTP_{e.response.status_code}', falcon.HTTP_500)
            try:
                resp.text = e.response.text
                resp.content_type = 'application/json'
            except:
                resp.text = json.dumps({"errors": [
                    {"title": "Proxy Error",
                     "description": "Failed to proxy request to remote store."}]})
        except Exception as e:
            # Unexpected errors - log as error but return 500
            logger.error(f"Error proxying DNS scanner request to HP App Store: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Internal Server Error",
                 "description": str(e)}]})
    
    def on_post(self, req, resp, **kwargs):
        """Create a new DNS vulnerability scan."""
        endpoint_suffix = '/scan'
        self._proxy_request(req, resp, 'POST', endpoint_suffix)
    
    def on_get(self, req, resp, **kwargs):
        """List or get DNS vulnerability scans."""
        if 'ident' in kwargs:
            endpoint_suffix = f"/scans/{kwargs['ident']}"
        else:
            endpoint_suffix = '/scans'
        self._proxy_request(req, resp, 'GET', endpoint_suffix)


class DNSScannerResultResource(object):
    """Proxy resource for DNS scanner result endpoints."""
    
    def _proxy_request(self, req, resp, method: str, endpoint_suffix: str = ''):
        """Proxy request to HP App Store."""
        try:
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            if config['api_key']:
                headers['API-KEY'] = config['api_key']
            
            request_data = None
            if method in ['POST', 'PATCH', 'PUT']:
                try:
                    request_data = req.media
                except:
                    request_data = None
            
            params = dict(req.params) if req.params else {}
            
            endpoint = f'/api/v2/dns-scanner{endpoint_suffix}'
            url = f"{config['base_url'].rstrip('/')}{endpoint}"
            
            with httpx.Client(timeout=config['timeout']) as client:
                if method == 'GET':
                    response = client.get(url, headers=headers, params=params)
                elif method == 'PATCH':
                    response = client.patch(url, headers=headers, json=request_data, params=params)
                else:
                    resp.status = falcon.HTTP_405
                    resp.text = json.dumps({"errors": [
                        {"title": "Method Not Allowed",
                         "description": f"Method {method} not supported."}]})
                    return
                
                resp.status = getattr(falcon, f'HTTP_{response.status_code}', falcon.HTTP_500)
                resp.text = response.text
                resp.content_type = 'application/json'
                
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException, httpx.NetworkError) as e:
            # Connection errors indicate HP App Store is unavailable
            logger.warning(f"HP App Store unavailable for DNS scanner result request: {e}")
            resp.status = falcon.HTTP_503
            resp.text = json.dumps({"errors": [
                {"title": "Service Unavailable",
                 "description": "HP App Store is currently unavailable."}]})
        except httpx.HTTPStatusError as e:
            # HTTP error responses from HP App Store - pass through the status code
            logger.error(f"HTTP error from HP App Store: {e}")
            resp.status = getattr(falcon, f'HTTP_{e.response.status_code}', falcon.HTTP_500)
            try:
                resp.text = e.response.text
                resp.content_type = 'application/json'
            except:
                resp.text = json.dumps({"errors": [
                    {"title": "Proxy Error",
                     "description": "Failed to proxy request to remote store."}]})
        except Exception as e:
            # Unexpected errors - log as error but return 500
            logger.error(f"Error proxying DNS scanner result request: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Internal Server Error",
                 "description": str(e)}]})
    
    def on_get(self, req, resp, ident):
        """Get results for a scan."""
        endpoint_suffix = f"/scans/{ident}/results"
        self._proxy_request(req, resp, 'GET', endpoint_suffix)
    
    def on_patch(self, req, resp, ident):
        """Update a vulnerability result."""
        endpoint_suffix = f"/results/{ident}"
        self._proxy_request(req, resp, 'PATCH', endpoint_suffix)


class DNSScannerBulkUpdateResource(object):
    """Proxy resource for DNS scanner bulk update endpoint."""
    
    def _proxy_request(self, req, resp, method: str):
        """Proxy request to HP App Store."""
        try:
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            if config['api_key']:
                headers['API-KEY'] = config['api_key']
            
            request_data = None
            if method == 'PATCH':
                try:
                    request_data = req.media
                except:
                    request_data = None
            
            endpoint = '/api/v2/dns-scanner/results/bulk-update'
            url = f"{config['base_url'].rstrip('/')}{endpoint}"
            
            with httpx.Client(timeout=config['timeout']) as client:
                if method == 'PATCH':
                    response = client.patch(url, headers=headers, json=request_data)
                else:
                    resp.status = falcon.HTTP_405
                    resp.text = json.dumps({"errors": [
                        {"title": "Method Not Allowed",
                         "description": f"Method {method} not supported."}]})
                    return
                
                resp.status = getattr(falcon, f'HTTP_{response.status_code}', falcon.HTTP_500)
                resp.text = response.text
                resp.content_type = 'application/json'
                
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException, httpx.NetworkError) as e:
            # Connection errors indicate HP App Store is unavailable
            logger.warning(f"HP App Store unavailable for DNS scanner bulk update request: {e}")
            resp.status = falcon.HTTP_503
            resp.text = json.dumps({"errors": [
                {"title": "Service Unavailable",
                 "description": "HP App Store is currently unavailable."}]})
        except httpx.HTTPStatusError as e:
            # HTTP error responses from HP App Store - pass through the status code
            logger.error(f"HTTP error from HP App Store: {e}")
            resp.status = getattr(falcon, f'HTTP_{e.response.status_code}', falcon.HTTP_500)
            try:
                resp.text = e.response.text
                resp.content_type = 'application/json'
            except:
                resp.text = json.dumps({"errors": [
                    {"title": "Proxy Error",
                     "description": "Failed to proxy request to remote store."}]})
        except Exception as e:
            # Unexpected errors - log as error but return 500
            logger.error(f"Error proxying DNS scanner bulk update request: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Internal Server Error",
                 "description": str(e)}]})
    
    def on_patch(self, req, resp, **kwargs):
        """Bulk update vulnerability results."""
        self._proxy_request(req, resp, 'PATCH')


class DNSScannerConfigResource(object):
    """Proxy resource for DNS scanner configuration endpoints."""
    
    def _proxy_request(self, req, resp, method: str, endpoint_suffix: str = ''):
        """Proxy request to HP App Store."""
        try:
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            if config['api_key']:
                headers['API-KEY'] = config['api_key']
            
            request_data = None
            if method in ['POST', 'PATCH', 'PUT']:
                try:
                    request_data = req.media
                except:
                    request_data = None
            
            params = dict(req.params) if req.params else {}
            
            endpoint = f'/api/v2/dns-scanner{endpoint_suffix}'
            url = f"{config['base_url'].rstrip('/')}{endpoint}"
            
            with httpx.Client(timeout=config['timeout']) as client:
                if method == 'GET':
                    response = client.get(url, headers=headers, params=params)
                elif method == 'PATCH':
                    response = client.patch(url, headers=headers, json=request_data, params=params)
                else:
                    resp.status = falcon.HTTP_405
                    resp.text = json.dumps({"errors": [
                        {"title": "Method Not Allowed",
                         "description": f"Method {method} not supported."}]})
                    return
                
                resp.status = getattr(falcon, f'HTTP_{response.status_code}', falcon.HTTP_500)
                resp.text = response.text
                resp.content_type = 'application/json'
                
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException, httpx.NetworkError) as e:
            # Connection errors indicate HP App Store is unavailable
            logger.warning(f"HP App Store unavailable for DNS scanner config request: {e}")
            resp.status = falcon.HTTP_503
            resp.text = json.dumps({"errors": [
                {"title": "Service Unavailable",
                 "description": "HP App Store is currently unavailable."}]})
        except httpx.HTTPStatusError as e:
            # HTTP error responses from HP App Store - pass through the status code
            logger.error(f"HTTP error from HP App Store: {e}")
            resp.status = getattr(falcon, f'HTTP_{e.response.status_code}', falcon.HTTP_500)
            try:
                resp.text = e.response.text
                resp.content_type = 'application/json'
            except:
                resp.text = json.dumps({"errors": [
                    {"title": "Proxy Error",
                     "description": "Failed to proxy request to remote store."}]})
        except Exception as e:
            # Unexpected errors - log as error but return 500
            logger.error(f"Error proxying DNS scanner config request: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Internal Server Error",
                 "description": str(e)}]})
    
    def on_get(self, req, resp, **kwargs):
        """Get DNS scanner description."""
        endpoint_suffix = '/config/description'
        self._proxy_request(req, resp, 'GET', endpoint_suffix)
    
    def on_patch(self, req, resp, **kwargs):
        """Update DNS scanner description."""
        endpoint_suffix = '/config/description'
        self._proxy_request(req, resp, 'PATCH', endpoint_suffix)

