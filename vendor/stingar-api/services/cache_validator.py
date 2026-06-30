"""
Cache validation service for remote honeypot data.

This module provides functionality to validate cache freshness and detect stale data.
"""

import datetime
import logging
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from storage.db import StingarDB
from storage.db.models import RemoteHoneypot

logger = logging.getLogger(__name__)


class CacheValidator:
    """
    Validates cache freshness and detects stale remote honeypot data.
    """
    
    def __init__(self, db: StingarDB):
        self.db = db
        
    def validate_cache_freshness(self, max_age_hours: int = 24) -> Dict[str, Any]:
        """
        Validate cache freshness and return statistics about stale data.
        
        :param max_age_hours: Maximum age in hours before data is considered stale
        :return: Dictionary with validation results
        """
        try:
            # Get all remote honeypots from cache
            all_honeypots = self.db.get_remote_honeypots({})
            
            if not all_honeypots:
                return {
                    'total_cached': 0,
                    'fresh_count': 0,
                    'stale_count': 0,
                    'stale_honeypots': [],
                    'validation_timestamp': datetime.datetime.utcnow().isoformat(),
                    'max_age_hours': max_age_hours
                }
            
            # Calculate cutoff time for stale data
            cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(hours=max_age_hours)
            
            fresh_count = 0
            stale_count = 0
            stale_honeypots = []
            
            for honeypot in all_honeypots:
                # Check if honeypot has local_updated timestamp
                if honeypot.get('local_updated'):
                    if isinstance(honeypot['local_updated'], str):
                        try:
                            updated_time = datetime.datetime.fromisoformat(honeypot['local_updated'].replace('Z', '+00:00'))
                        except (ValueError, TypeError):
                            # If we can't parse the timestamp, consider it stale
                            updated_time = None
                    else:
                        updated_time = honeypot['local_updated']
                    
                    if updated_time and updated_time >= cutoff_time:
                        fresh_count += 1
                    else:
                        stale_count += 1
                        # Convert datetime to ISO string for JSON serialization
                        last_updated = honeypot.get('local_updated')
                        if isinstance(last_updated, datetime.datetime):
                            last_updated = last_updated.isoformat()
                        
                        stale_honeypots.append({
                            'id': honeypot.get('id'),
                            'remote_id': honeypot.get('remote_id'),
                            'name': honeypot.get('name'),
                            'hp_type': honeypot.get('hp_type'),
                            'last_updated': last_updated,
                            'age_hours': self._calculate_age_hours(updated_time) if updated_time else None
                        })
                else:
                    # No timestamp means it's stale
                    stale_count += 1
                    stale_honeypots.append({
                        'id': honeypot.get('id'),
                        'remote_id': honeypot.get('remote_id'),
                        'name': honeypot.get('name'),
                        'hp_type': honeypot.get('hp_type'),
                        'last_updated': None,
                        'age_hours': None
                    })
            
            return {
                'total_cached': len(all_honeypots),
                'fresh_count': fresh_count,
                'stale_count': stale_count,
                'stale_honeypots': stale_honeypots,
                'validation_timestamp': datetime.datetime.utcnow().isoformat(),
                'max_age_hours': max_age_hours,
                'freshness_percentage': round((fresh_count / len(all_honeypots)) * 100, 2) if all_honeypots else 0
            }
            
        except Exception as e:
            logger.error(f"Error validating cache freshness: {e}")
            return {
                'error': str(e),
                'validation_timestamp': datetime.datetime.utcnow().isoformat(),
                'max_age_hours': max_age_hours
            }
    
    def _calculate_age_hours(self, timestamp: datetime.datetime) -> Optional[float]:
        """
        Calculate age of timestamp in hours.
        
        :param timestamp: The timestamp to calculate age for
        :return: Age in hours, or None if calculation fails
        """
        try:
            if not timestamp:
                return None
            
            now = datetime.datetime.utcnow()
            if timestamp.tzinfo:
                now = now.replace(tzinfo=timestamp.tzinfo)
            
            age_delta = now - timestamp
            return round(age_delta.total_seconds() / 3600, 2)
        except Exception as e:
            logger.error(f"Error calculating age for timestamp {timestamp}: {e}")
            return None
    
    def get_stale_honeypots(self, max_age_hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get list of stale honeypots.
        
        :param max_age_hours: Maximum age in hours before data is considered stale
        :return: List of stale honeypot records
        """
        validation_result = self.validate_cache_freshness(max_age_hours)
        return validation_result.get('stale_honeypots', [])
    
    def is_cache_stale(self, max_age_hours: int = 24) -> bool:
        """
        Check if cache contains stale data.
        
        :param max_age_hours: Maximum age in hours before data is considered stale
        :return: True if cache contains stale data, False otherwise
        """
        validation_result = self.validate_cache_freshness(max_age_hours)
        return validation_result.get('stale_count', 0) > 0
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """
        Get general cache statistics.
        
        :return: Dictionary with cache statistics
        """
        try:
            all_honeypots = self.db.get_remote_honeypots({})
            
            if not all_honeypots:
                return {
                    'total_cached': 0,
                    'oldest_cache_age_hours': None,
                    'newest_cache_age_hours': None,
                    'average_cache_age_hours': None,
                    'cache_timestamp': datetime.datetime.utcnow().isoformat()
                }
            
            ages = []
            for honeypot in all_honeypots:
                if honeypot.get('local_updated'):
                    age = self._calculate_age_hours(honeypot['local_updated'])
                    if age is not None:
                        ages.append(age)
            
            if not ages:
                return {
                    'total_cached': len(all_honeypots),
                    'oldest_cache_age_hours': None,
                    'newest_cache_age_hours': None,
                    'average_cache_age_hours': None,
                    'cache_timestamp': datetime.datetime.utcnow().isoformat()
                }
            
            return {
                'total_cached': len(all_honeypots),
                'oldest_cache_age_hours': max(ages),
                'newest_cache_age_hours': min(ages),
                'average_cache_age_hours': round(sum(ages) / len(ages), 2),
                'cache_timestamp': datetime.datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting cache statistics: {e}")
            return {
                'error': str(e),
                'cache_timestamp': datetime.datetime.utcnow().isoformat()
            }
    
    def get_honeypot_staleness_info(self, honeypot: Dict[str, Any], max_age_hours: int = 24) -> Dict[str, Any]:
        """
        Get staleness information for a specific honeypot.
        
        :param honeypot: The honeypot data to check
        :param max_age_hours: Maximum age in hours before data is considered stale
        :return: Dictionary with staleness information
        """
        try:
            last_updated = honeypot.get('local_updated')
            
            if not last_updated:
                return {
                    'is_stale': True,
                    'age_hours': None,
                    'last_updated': None,
                    'reason': 'No timestamp available'
                }
            
            # Parse timestamp if it's a string
            if isinstance(last_updated, str):
                try:
                    last_updated = datetime.datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    return {
                        'is_stale': True,
                        'age_hours': None,
                        'last_updated': honeypot.get('local_updated'),
                        'reason': 'Invalid timestamp format'
                    }
            
            age_hours = self._calculate_age_hours(last_updated)
            is_stale = age_hours is not None and age_hours > max_age_hours
            
            # Convert datetime to ISO string for JSON serialization
            last_updated = honeypot.get('local_updated')
            if isinstance(last_updated, datetime.datetime):
                last_updated = last_updated.isoformat()
            
            return {
                'is_stale': is_stale,
                'age_hours': age_hours,
                'last_updated': last_updated,
                'reason': None
            }
            
        except Exception as e:
            logger.error(f"Error getting staleness info for honeypot: {e}")
            return {
                'is_stale': True,
                'age_hours': None,
                'last_updated': None,
                'reason': f'Error: {str(e)}'
            }

    def validate_specific_honeypot(self, remote_id: str, max_age_hours: int = 24) -> Dict[str, Any]:
        """
        Validate freshness of a specific honeypot.
        
        :param remote_id: The remote ID of the honeypot to validate
        :param max_age_hours: Maximum age in hours before data is considered stale
        :return: Dictionary with validation results for the specific honeypot
        """
        try:
            honeypots = self.db.get_remote_honeypots({'remote_id': remote_id})
            
            if not honeypots:
                return {
                    'remote_id': remote_id,
                    'found': False,
                    'is_stale': None,
                    'age_hours': None,
                    'last_updated': None,
                    'validation_timestamp': datetime.datetime.utcnow().isoformat()
                }
            
            honeypot = honeypots[0]
            last_updated = honeypot.get('local_updated')
            
            if not last_updated:
                return {
                    'remote_id': remote_id,
                    'found': True,
                    'is_stale': True,
                    'age_hours': None,
                    'last_updated': None,
                    'validation_timestamp': datetime.datetime.utcnow().isoformat(),
                    'reason': 'No timestamp available'
                }
            
            # Parse timestamp if it's a string
            if isinstance(last_updated, str):
                try:
                    last_updated = datetime.datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    return {
                        'remote_id': remote_id,
                        'found': True,
                        'is_stale': True,
                        'age_hours': None,
                        'last_updated': honeypot.get('local_updated'),
                        'validation_timestamp': datetime.datetime.utcnow().isoformat(),
                        'reason': 'Invalid timestamp format'
                    }
            
            age_hours = self._calculate_age_hours(last_updated)
            is_stale = age_hours is not None and age_hours > max_age_hours
            
            # Convert datetime to ISO string for JSON serialization
            last_updated_str = honeypot.get('local_updated')
            if isinstance(last_updated_str, datetime.datetime):
                last_updated_str = last_updated_str.isoformat()
            
            return {
                'remote_id': remote_id,
                'found': True,
                'is_stale': is_stale,
                'age_hours': age_hours,
                'last_updated': last_updated_str,
                'validation_timestamp': datetime.datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error validating specific honeypot {remote_id}: {e}")
            return {
                'remote_id': remote_id,
                'error': str(e),
                'validation_timestamp': datetime.datetime.utcnow().isoformat()
            }
