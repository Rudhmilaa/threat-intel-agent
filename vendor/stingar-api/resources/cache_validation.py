"""
Cache validation API endpoints.

Provides endpoints for validating cache freshness and detecting stale data.
"""

import json
import datetime
import falcon
import logging
from falcon.media.validators import jsonschema
from resources import db
from util import json_converter
from services.cache_validator import CacheValidator

logger = logging.getLogger(__name__)


class CacheValidationResource(object):
    """
    Cache validation API endpoint for checking cache freshness.
    """
    
    def on_get(self, req, resp):
        """
        Validate cache freshness and return statistics.
        
        Query parameters:
        - max_age_hours: Maximum age in hours before data is considered stale (default: 24)
        
        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            # Get max_age_hours from query parameters
            max_age_hours = 24  # Default value
            if 'max_age_hours' in req.params:
                try:
                    max_age_hours = int(req.params['max_age_hours'])
                    if max_age_hours < 0:
                        max_age_hours = 24
                except (ValueError, TypeError):
                    max_age_hours = 24
            
            # Create cache validator and validate cache
            validator = CacheValidator(db)
            validation_result = validator.validate_cache_freshness(max_age_hours)
            
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({
                'success': True,
                'data': validation_result
            }, default=json_converter, ensure_ascii=False)
            
        except Exception as e:
            logger.error(f"Error validating cache: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({
                'success': False,
                'error': str(e)
            }, default=json_converter, ensure_ascii=False)


class CacheStatisticsResource(object):
    """
    Cache statistics API endpoint.
    """
    
    def on_get(self, req, resp):
        """
        Get general cache statistics.
        
        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            # Create cache validator and get statistics
            validator = CacheValidator(db)
            statistics = validator.get_cache_statistics()
            
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({
                'success': True,
                'data': statistics
            }, default=json_converter, ensure_ascii=False)
            
        except Exception as e:
            logger.error(f"Error getting cache statistics: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({
                'success': False,
                'error': str(e)
            }, default=json_converter, ensure_ascii=False)


class SpecificHoneypotValidationResource(object):
    """
    Specific honeypot cache validation API endpoint.
    """
    
    def on_get(self, req, resp, remote_id):
        """
        Validate freshness of a specific honeypot.
        
        Query parameters:
        - max_age_hours: Maximum age in hours before data is considered stale (default: 24)
        
        :param req: Falcon request
        :param resp: Falcon response
        :param remote_id: The remote ID of the honeypot to validate
        """
        try:
            # Get max_age_hours from query parameters
            max_age_hours = 24  # Default value
            if 'max_age_hours' in req.params:
                try:
                    max_age_hours = int(req.params['max_age_hours'])
                    if max_age_hours < 0:
                        max_age_hours = 24
                except (ValueError, TypeError):
                    max_age_hours = 24
            
            # Create cache validator and validate specific honeypot
            validator = CacheValidator(db)
            validation_result = validator.validate_specific_honeypot(remote_id, max_age_hours)
            
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({
                'success': True,
                'data': validation_result
            }, default=json_converter, ensure_ascii=False)
            
        except Exception as e:
            logger.error(f"Error validating specific honeypot {remote_id}: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({
                'success': False,
                'error': str(e)
            }, default=json_converter, ensure_ascii=False)


class StaleHoneypotsResource(object):
    """
    Get list of stale honeypots API endpoint.
    """
    
    def on_get(self, req, resp):
        """
        Get list of stale honeypots.
        
        Query parameters:
        - max_age_hours: Maximum age in hours before data is considered stale (default: 24)
        
        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            # Get max_age_hours from query parameters
            max_age_hours = 24  # Default value
            if 'max_age_hours' in req.params:
                try:
                    max_age_hours = int(req.params['max_age_hours'])
                    if max_age_hours < 0:
                        max_age_hours = 24
                except (ValueError, TypeError):
                    max_age_hours = 24
            
            # Create cache validator and get stale honeypots
            validator = CacheValidator(db)
            stale_honeypots = validator.get_stale_honeypots(max_age_hours)
            
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({
                'success': True,
                'data': {
                    'stale_honeypots': stale_honeypots,
                    'count': len(stale_honeypots),
                    'max_age_hours': max_age_hours,
                    'timestamp': datetime.datetime.utcnow().isoformat()
                }
            }, default=json_converter, ensure_ascii=False)
            
        except Exception as e:
            logger.error(f"Error getting stale honeypots: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({
                'success': False,
                'error': str(e)
            }, default=json_converter, ensure_ascii=False)
