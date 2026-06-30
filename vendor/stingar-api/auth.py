import falcon
import logging
from storage.db import StingarDB

logger = logging.getLogger(__name__)
db = StingarDB()


class AuthMiddleware(object):

    """
    Authentication middleware for STINGAR API.
    """

    def __init__(self, exempt_routes=None, exempt_static_routes=None):
        """
        Initialize auth middleware and set exempted routes for authentication.

        :param exempt_routes: List of explicitly exempted routes. Exempts direct matches, but not subdirectories.
        :type exempt_routes: list
        :param exempt_static_routes: List of explicity exempted paths. Exempts any sub-url in the path as well.
                Used for exempting entire directories of static files.
        :type exempt_static_routes: list
        """
        self.exempt_routes = exempt_routes or []
        self.exempt_static_routes = exempt_static_routes or []

    def process_request(self, req, resp):
        """
        Process web request to STINGAR API and check authentication.

        Raises falcon.HTTPUnauthorized() error if authentication is not valid for path.

        :param req: Falcon request
        :param resp: Falcon response
        :return: None
        """
        token = req.get_header('api-key')
        
        # Normalize path: remove double slashes, query strings, trailing slashes
        # Handle cases like //api/v2/store/config -> /api/v2/store/config
        normalized_path = req.path.replace('//', '/').split('?')[0].rstrip('/')
        if normalized_path.startswith('//'):
            normalized_path = normalized_path[1:]  # Remove leading double slash

        # Explicitly exempt routes. Used for exempting specific files.
        # Check exact match first (both original and normalized)
        if req.path in self.exempt_routes or normalized_path in self.exempt_routes:
            return
        
        # Also check if normalized path matches any exempt route (handles trailing slashes, query params, double slashes, etc.)
        for exempt_route in self.exempt_routes:
            normalized_exempt = exempt_route.rstrip('/')
            if normalized_path == normalized_exempt:
                return

        # Fully exempted paths. Exempt auth for anything below this path. Used for static file directories.
        if any(substring in req.path for substring in self.exempt_static_routes):
            return

        if token is None:
            description = ('Please provide an auth token '
                         'as part of the request.')

            raise falcon.HTTPUnauthorized(
                title='Auth token required',
                description=description,
                href='http://docs.example.com/auth'
            )

        if not self._token_is_valid(token):
            description = ('The provided auth token is not valid. '
                         'Please request a new token and try again.')
            raise falcon.HTTPUnauthorized(
                title='Authentication required',
                description=description,
                href='http://docs.example.com/auth'
            )

    @staticmethod
    def _token_is_valid(token):
        """
        Check if API token is valid.

        :param token: STINGAR API token
        :type token: str
        :return: Is token valid or not?
        :rtype: bool
        """
        if db.check_token(token):
            return True
        return False
