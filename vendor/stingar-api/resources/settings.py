"""
Settings resource for managing stingar.env environment variables.

Provides endpoints to read and update environment variables from stingar.env file
with validation and action triggers.
"""

import os
import logging
import falcon
import json
from typing import Dict, Any, Optional
from resources.store_config import read_stingar_env, write_stingar_env, get_stingar_env_path

logger = logging.getLogger(__name__)


# Variable metadata definition
# Organized by the original stingar.env file order from configuration.md
VARIABLE_METADATA = {
    # Fluentd
    'FLUENTD_HOST': {
        'display_name': 'Fluentd Host',
        'description': 'The Fluentd host address. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': 'fluentd',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Fluentd',
    },
    'FLUENTD_PORT': {
        'display_name': 'Fluentd Port',
        'description': 'The port that Fluentd listens on. Automatically set when STINGAR is installed.',
        'type': 'number',
        'default': '24224',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Fluentd',
    },
    'FLUENTD_REMOTE_HOST': {
        'display_name': 'Fluentd Remote Host',
        'description': 'The address of the STINGAR server that hosts fluentd. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Fluentd',
    },
    'FLUENTD_LOCAL_PORT': {
        'display_name': 'Fluentd Local Port',
        'description': 'The port that STINGAR will use to access fluentd. Automatically set when STINGAR is installed.',
        'type': 'number',
        'default': '24225',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Fluentd',
    },
    'FLUENTD_KEY': {
        'display_name': 'Fluentd Key',
        'description': 'An access key that is automatically generated and saved to the stingar.env file when STINGAR is installed. It should not be changed.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': True,
        'editable': True,
        'group': 'Fluentd',
    },
    'FLUENTD_APP': {
        'display_name': 'Fluentd App',
        'description': 'The name of the fluentd application.',
        'type': 'string',
        'default': 'stingar',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Fluentd',
    },
    
    # Fluent Bit
    'FLUENTBIT_HOST': {
        'display_name': 'Fluent Bit Host',
        'description': 'The Fluent Bit host address. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': 'fluentbit',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Fluent Bit',
    },
    'FLUENTBIT_PORT': {
        'display_name': 'Fluent Bit Port',
        'description': 'The port that Fluent Bit listens on. Automatically set when STINGAR is installed.',
        'type': 'number',
        'default': '24284',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Fluent Bit',
    },
    'FLUENTBIT_APP': {
        'display_name': 'Fluent Bit App',
        'description': 'The name of the Fluent Bit application. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': 'stingar',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Fluent Bit',
    },
    'FLUENTBIT_HOSTNAME': {
        'display_name': 'Fluent Bit Hostname',
        'description': 'The hostname for Fluent Bit. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': 'flb.local',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Fluent Bit',
    },
    
    # Syslog output of attack logs
    'SYSLOG_ENABLED': {
        'display_name': 'Syslog Enabled',
        'description': 'Enable or disable syslog output of attack logs. Disabled by default, set to true to enable.',
        'type': 'boolean',
        'default': 'false',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Syslog Output',
    },
    'SYSLOG_HOST': {
        'display_name': 'Syslog Host',
        'description': 'If enabled, insert name/IP address of Syslog destination server.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Syslog Output',
    },
    'SYSLOG_PORT': {
        'display_name': 'Syslog Port',
        'description': 'The port for syslog output.',
        'type': 'number',
        'default': '514',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Syslog Output',
    },
    'SYSLOG_SEVERITY': {
        'display_name': 'Syslog Severity',
        'description': 'The severity level for syslog messages.',
        'type': 'string',
        'default': 'info',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Syslog Output',
    },
    'SYSLOG_HOSTNAME': {
        'display_name': 'Syslog Hostname',
        'description': 'If enabled, insert name/IP address of this STINGAR server.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Syslog Output',
    },
    'SYSLOG_PROTOCOL': {
        'display_name': 'Syslog Protocol',
        'description': 'The protocol for syslog output. UDP is the default, TCP is optional.',
        'type': 'string',
        'default': 'udp',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Syslog Output',
    },
    
    # Local file output of attack logs
    'FILE_ENABLED': {
        'display_name': 'File Output Enabled',
        'description': 'Enable or disable local file output of attack logs. Disabled by default, set to true to enable. If enabled, the output file location is mounted/mapped to the local file system in the docker-compose.yml file.',
        'type': 'boolean',
        'default': 'false',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Local File Output',
    },
    
    # CIF ENV variables
    'CIF_ENABLED': {
        'display_name': 'CIF Enabled',
        'description': 'Enable or disable CIF (Central Intelligence Framework) for remote sharing of attack data. Disabled by default, set to true to enable.',
        'type': 'boolean',
        'default': 'false',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'CIF Configuration',
    },
    'CIF_HOST': {
        'display_name': 'CIF Host',
        'description': 'The CIF broker host address. Provided by Forewarned (info@forewarned.io).',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'CIF Configuration',
    },
    'CIF_TOKEN': {
        'display_name': 'CIF Token',
        'description': 'The CIF authentication token. Provided by Forewarned (info@forewarned.io).',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': True,
        'editable': True,
        'group': 'CIF Configuration',
    },
    'CIF_PROVIDER': {
        'display_name': 'CIF Provider',
        'description': 'The CIF provider name. Provided by Forewarned (info@forewarned.io).',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'CIF Configuration',
    },
    'CIF_CONFIDENCE': {
        'display_name': 'CIF Confidence',
        'description': 'The confidence level for CIF indicators. Automatically set when STINGAR is installed.',
        'type': 'number',
        'default': '8',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'CIF Configuration',
    },
    'CIF_TAGS': {
        'display_name': 'CIF Tags',
        'description': 'Tags for CIF indicators. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': 'honeypots',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'CIF Configuration',
    },
    'CIF_GROUP': {
        'display_name': 'CIF Group',
        'description': 'The group for CIF indicators. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': 'everyone',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'CIF Configuration',
    },
    
    # HP App Store Configuration
    'REMOTE_STORE_ENABLED': {
        'display_name': 'HP App Store Enabled',
        'description': 'Enable or disable HP App Store integration. When enabled, STINGAR will automatically attempt to register your instance and fetch honeypot data from the store.',
        'type': 'boolean',
        'default': 'true',
        'required': False,
        'sensitive': False,
        'editable': True,
        'action_trigger': 'hp_store_enable_disable',
        'group': 'HP App Store Configuration',
        'validation': {
            'allowed_values': ['true', 'false', '1', '0', 'yes', 'no']
        }
    },
    'REMOTE_STORE_API_KEY': {
        'display_name': 'HP App Store API Key',
        'description': 'API key for authenticating with HP App Store. Automatically generated when you enable the store and register your instance.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': True,
        'editable': True,
        'action_trigger': 'api_key_change',
        'group': 'HP App Store Configuration',
        'validation': {
            'format': 'starts_with:hp_ak_',
            'min_length': 10
        }
    },
    'REMOTE_STORE_BASE_URL': {
        'display_name': 'HP App Store Base URL',
        'description': 'The base URL for the HP App Store API (default: https://store.4warned.io).',
        'type': 'url',
        'default': 'https://store.4warned.io',
        'required': False,
        'sensitive': False,
        'editable': True,
        'action_trigger': 'base_url_change',
        'group': 'HP App Store Configuration',
        'validation': {
            'format': 'url'
        }
    },
    
    # Local server settings
    'API_HOST': {
        'display_name': 'API Host',
        'description': 'The API host address. Automatically set when STINGAR is installed. Typically not modified.',
        'type': 'url',
        'default': 'http://stingarapi:8000/',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Local Server Settings',
    },
    'API_KEY': {
        'display_name': 'API Key',
        'description': 'The key that STINGAR uses to access the API. The API stores this token and confirms that the one provided by all API requests match before it responds. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': True,
        'editable': True,
        'group': 'Local Server Settings',
    },
    'PASSPHRASE': {
        'display_name': 'Passphrase',
        'description': 'Used by install script to create API key. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': True,
        'editable': True,
        'group': 'Local Server Settings',
    },
    'SALT': {
        'display_name': 'Salt',
        'description': 'Used by install script to create API key. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': True,
        'editable': True,
        'group': 'Local Server Settings',
    },
    'STINGAR_SERVICE_URL': {
        'display_name': 'STINGAR Service URL',
        'description': 'The service URL for STINGAR API. Automatically set when STINGAR is installed.',
        'type': 'url',
        'default': 'http://stingarapi:8000/api/v2',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Local Server Settings',
    },
    'UI_HOSTNAME': {
        'display_name': 'UI Hostname',
        'description': 'The hostname for the STINGAR UI. Automatically set when STINGAR is installed.',
        'type': 'string',
        'default': 'localhost',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Local Server Settings',
    },
    
    # Honeypot health check interval
    'HONEYPOT_HEALTHCHECK_INTERVAL': {
        'display_name': 'Honeypot Health Check Interval',
        'description': 'The interval for honeypot health checks. Default check every 01 hours 0 mins 0 secs. Format: PT01h0m0s (ISO 8601 duration).',
        'type': 'string',
        'default': 'PT01h0m0s',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Honeypot Configuration',
    },
    
    # Honeypot Tags
    'TAGS': {
        'display_name': 'Honeypot Tags',
        'description': 'List of tags to use for honeypots. List should be comma separated. Key value pairs should be colon delimited. Non-key value pairs will be added to "misc" tag.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Honeypot Configuration',
    },
    
    # LDAP
    'LDAP_ENABLED': {
        'display_name': 'LDAP Enabled',
        'description': 'Enable or disable LDAP authentication. If enabled, LDAP will be enabled, allowing you to use your organization\'s institutional identity management system to authenticate STINGAR users. Users will still need to be added to STINGAR via the User Management module.',
        'type': 'boolean',
        'default': 'false',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'LDAP Configuration',
    },
    'LDAP_HOST': {
        'display_name': 'LDAP Host',
        'description': 'Set to local LDAP server address.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'LDAP Configuration',
    },
    'LDAP_PORT': {
        'display_name': 'LDAP Port',
        'description': 'The port for LDAP server connection.',
        'type': 'number',
        'default': '636',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'LDAP Configuration',
    },
    'LDAP_BASE': {
        'display_name': 'LDAP Base',
        'description': 'Set to LDAP Base DN.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'LDAP Configuration',
    },
    
    # Miscellaneous UI settings
    'INSTITUTION_NAME': {
        'display_name': 'Institution Name',
        'description': 'The name of your organization. The value you enter will appear in the STINGAR header.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'action_trigger': 'institution_name_change',
        'group': 'UI Settings',
        'validation': {
            'max_length': 255
        }
    },
    'CONTACT_EMAIL': {
        'display_name': 'Contact Email',
        'description': 'Contact email for this STINGAR instance. Used for instance registration and communication.',
        'type': 'email',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'action_trigger': 'contact_email_change',
        'group': 'UI Settings',
        'validation': {
            'format': 'email'
        }
    },
    'THEME_DARK_BASE_COLOR': {
        'display_name': 'Theme Dark Base Color',
        'description': 'A dark color that is used throughout the application (including header & sidebar backgrounds).',
        'type': 'string',
        'default': '#363636',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'UI Settings',
    },
    'THEME_LIGHT_BASE_COLOR': {
        'display_name': 'Theme Light Base Color',
        'description': 'A light color that is used throughout the application (including header & sidebar text).',
        'type': 'string',
        'default': 'white',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'UI Settings',
    },
    'DEFAULT_ROWS_PER_PAGE': {
        'display_name': 'Default Rows Per Page',
        'description': 'When displaying attack events, STINGAR presents them page by page. You may use this env variable to define the number of rows that should appear per page, as the default. (The user may change this while viewing events).',
        'type': 'number',
        'default': '50',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'UI Settings',
    },
    'SESSIONS_DEFAULT_DATE_RANGE': {
        'display_name': 'Sessions Default Date Range',
        'description': 'Default time window for Attack Analysis when no date filter is specified. Use 24h, 7d, etc. (24h = 24 hours, 7d = 7 days). Long values (>30d) may cause slow response from Elasticsearch.',
        'type': 'string',
        'default': '24h',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'UI Settings',
    },
    
    # IDS Rules Feed
    'IDS_RULES_FEED_CACHE_TTL': {
        'display_name': 'IDS Rules Feed Cache TTL',
        'description': 'Cache TTL in seconds for the on-demand rules feed (default 300 = 5 minutes). Rules are generated when the feed is requested and the cache is stale or missing.',
        'type': 'number',
        'default': '300',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'IDS Rules Feed',
    },
    'IDS_RULES_AUTO_UPDATE_ENABLED': {
        'display_name': 'IDS Rules Auto-Update Enabled (DEPRECATED)',
        'description': 'DEPRECATED. Rules feed now uses on-demand generation. This setting is ignored.',
        'type': 'boolean',
        'default': 'true',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'IDS Rules Feed',
        'validation': {
            'allowed_values': ['true', 'false', '1', '0', 'yes', 'no']
        }
    },
    'IDS_RULES_AUTO_UPDATE_INTERVAL': {
        'display_name': 'IDS Rules Auto-Update Interval (DEPRECATED)',
        'description': 'DEPRECATED. Rules feed now uses on-demand generation. This setting is ignored.',
        'type': 'number',
        'default': '300',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'IDS Rules Feed',
    },
    'IDS_RULES_CACHE_PATH': {
        'display_name': 'IDS Rules Cache Path',
        'description': 'File path where the auto-generated rules feed is written. IDS devices pull from the feed endpoint which serves this file.',
        'type': 'string',
        'default': '/var/lib/stingar/ids-rules/stingar-honeypot.rules',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'IDS Rules Feed',
    },
    'IDS_RULES_FEED_DATE_RANGE': {
        'display_name': 'IDS Rules Feed Date Range',
        'description': 'Lookback window for the auto-generated feed: 30d, 7d, 24h, 12h, 3h, 1h. Configurable from the IDS Rules page.',
        'type': 'string',
        'default': '30d',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'IDS Rules Feed',
        'validation': {
            'allowed_values': ['30d', '7d', '24h', '12h', '3h', '1h']
        }
    },
    'IDS_RULES_FEED_STARTUP_DELAY': {
        'display_name': 'IDS Rules Feed Startup Delay (DEPRECATED)',
        'description': 'DEPRECATED. Rules feed now uses on-demand generation. This setting is ignored.',
        'type': 'number',
        'default': '90',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'IDS Rules Feed',
    },

    # Docker Code Repository (DEPRECATED)
    'DOCKER_USERNAME': {
        'display_name': 'Docker Username',
        'description': 'The name of the Docker user that Langstroth will use to access the repository of \'playbooks\' that tell STINGAR how to deploy each type of honeypot. The API stores information about this user in a sqlite database. DEPRECATED.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Docker Repository (Deprecated)',
    },
    'DOCKER_REPOSITORY': {
        'display_name': 'Docker Repository',
        'description': 'The address of the code repository STINGAR uses to install your implementation and keep it updated. Automatically set when STINGAR is installed and should not be modified. DEPRECATED.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': False,
        'editable': True,
        'group': 'Docker Repository (Deprecated)',
    },
    'DOCKER_PASSWORD': {
        'display_name': 'Docker Password',
        'description': 'The password STINGAR uses to retrieve code from the STINGAR code repository. Automatically set when STINGAR is installed and should not be modified. DEPRECATED.',
        'type': 'string',
        'default': '',
        'required': False,
        'sensitive': True,
        'editable': True,
        'group': 'Docker Repository (Deprecated)',
    },
}


def validate_variable_value(variable_name: str, value: str) -> tuple[bool, Optional[str]]:
    """
    Validate a variable value against its metadata.
    
    :param variable_name: Name of the variable
    :param value: Value to validate
    :return: Tuple of (is_valid, error_message)
    """
    if variable_name not in VARIABLE_METADATA:
        return False, f"Unknown variable: {variable_name}"
    
    metadata = VARIABLE_METADATA[variable_name]
    validation = metadata.get('validation', {})
    
    # Type-specific validation
    var_type = metadata.get('type', 'string')
    
    if var_type == 'boolean':
        allowed = validation.get('allowed_values', ['true', 'false', '1', '0', 'yes', 'no'])
        if value.lower() not in [v.lower() for v in allowed]:
            return False, f"Invalid boolean value. Allowed: {', '.join(allowed)}"
    elif 'allowed_values' in validation:
        allowed = validation['allowed_values']
        if value.lower() not in [str(v).lower() for v in allowed]:
            return False, f"Invalid value. Allowed: {', '.join(str(v) for v in allowed)}"
    
    elif var_type == 'email':
        if value and '@' not in value:
            return False, "Invalid email format"
    
    elif var_type == 'url':
        if value and not (value.startswith('http://') or value.startswith('https://')):
            return False, "Invalid URL format. Must start with http:// or https://"
    
    elif var_type == 'number':
        if value:
            try:
                float(value)  # Accept both int and float
            except ValueError:
                return False, "Invalid number format"
    
    # Format validation
    format_rule = validation.get('format', '')
    if format_rule.startswith('starts_with:'):
        prefix = format_rule.split(':', 1)[1]
        if value and not value.startswith(prefix):
            return False, f"Value must start with: {prefix}"
    
    # Length validation
    if 'min_length' in validation and len(value) < validation['min_length']:
        return False, f"Value must be at least {validation['min_length']} characters"
    
    if 'max_length' in validation and len(value) > validation['max_length']:
        return False, f"Value must be at most {validation['max_length']} characters"
    
    return True, None


def mask_sensitive_value(variable_name: str, value: str) -> str:
    """
    Mask sensitive variable values for display.
    
    :param variable_name: Name of the variable
    :param value: Value to mask
    :return: Masked value
    """
    if variable_name not in VARIABLE_METADATA:
        return value
    
    metadata = VARIABLE_METADATA[variable_name]
    if metadata.get('sensitive', False) and value:
        # Show first 4 and last 4 characters, mask the middle
        if len(value) > 8:
            return f"{value[:4]}...{value[-4:]}"
        else:
            return "****"
    return value


class SettingsEnvResource(object):
    """Resource for managing environment variables from stingar.env."""
    
    def on_get(self, req, resp):
        """Get all environment variables from stingar.env with metadata."""
        try:
            # Read current environment variables
            env_vars = read_stingar_env()
            
            # Build response with metadata
            variables = []
            for var_name, var_value in env_vars.items():
                metadata = VARIABLE_METADATA.get(var_name, {
                    'display_name': var_name,
                    'description': '',
                    'type': 'string',
                    'default': '',
                    'required': False,
                    'sensitive': False,
                    'editable': True,
                    'action_trigger': None,
                    'group': 'Other Configuration'
                })
                
                variables.append({
                    'name': var_name,
                    'display_name': metadata.get('display_name', var_name),
                    'value': mask_sensitive_value(var_name, var_value),  # Masked value for display
                    'raw_value': var_value,  # Always return raw value (frontend handles masking)
                    'description': metadata.get('description', ''),
                    'type': metadata.get('type', 'string'),
                    'default': metadata.get('default', ''),
                    'required': metadata.get('required', False),
                    'sensitive': metadata.get('sensitive', False),
                    'editable': metadata.get('editable', True),
                    'action_trigger': metadata.get('action_trigger'),
                    'group': metadata.get('group', 'Other Configuration'),
                    'validation': metadata.get('validation', {})
                })
            
            resp.status = falcon.HTTP_200
            resp.media = {
                'data': variables,
                'metadata': {
                    'total': len(variables),
                    'file_path': get_stingar_env_path()
                }
            }
            
        except Exception as e:
            logger.error(f"Error reading environment variables: {e}", exc_info=True)
            resp.status = falcon.HTTP_500
            resp.media = {
                'errors': [{
                    'title': 'Internal Server Error',
                    'description': f'Failed to read environment variables: {str(e)}'
                }]
            }
    
    def on_put(self, req, resp):
        """Update environment variables in stingar.env."""
        try:
            # Get updates from request
            updates = req.media.get('variables', {})
            
            if not updates:
                resp.status = falcon.HTTP_400
                resp.media = {
                    'errors': [{
                        'title': 'Bad Request',
                        'description': 'No variables provided for update'
                    }]
                }
                return
            
            # Read current values
            current_vars = read_stingar_env()
            old_values = {k: current_vars.get(k, '') for k in updates.keys()}
            
            # Validate all updates before applying
            validation_errors = []
            for var_name, new_value in updates.items():
                # Convert value to string if needed
                value_str = str(new_value) if new_value is not None else ''
                
                # Validate
                is_valid, error_msg = validate_variable_value(var_name, value_str)
                if not is_valid:
                    validation_errors.append({
                        'variable': var_name,
                        'error': error_msg
                    })
            
            if validation_errors:
                resp.status = falcon.HTTP_400
                resp.media = {
                    'errors': [{
                        'title': 'Validation Error',
                        'description': 'One or more variables failed validation',
                        'details': validation_errors
                    }]
                }
                return
            
            # Apply updates
            updated_vars = current_vars.copy()
            for var_name, new_value in updates.items():
                value_str = str(new_value) if new_value is not None else ''
                updated_vars[var_name] = value_str
            
            # Write to file
            write_stingar_env(updated_vars)
            
            # Trigger actions for changed variables
            action_results = []
            for var_name, new_value in updates.items():
                value_str = str(new_value) if new_value is not None else ''
                old_value = old_values.get(var_name, '')
                
                if old_value != value_str:
                    metadata = VARIABLE_METADATA.get(var_name, {})
                    action_trigger = metadata.get('action_trigger')
                    
                    if action_trigger:
                        result = self._trigger_action(action_trigger, var_name, old_value, value_str)
                        action_results.append(result)
            
            resp.status = falcon.HTTP_200
            resp.media = {
                'data': {
                    'updated': len(updates),
                    'variables': list(updates.keys()),
                    'actions': action_results
                }
            }
            
        except Exception as e:
            logger.error(f"Error updating environment variables: {e}", exc_info=True)
            resp.status = falcon.HTTP_500
            resp.media = {
                'errors': [{
                    'title': 'Internal Server Error',
                    'description': f'Failed to update environment variables: {str(e)}'
                }]
            }
    
    def _trigger_action(self, action_name: str, variable_name: str, old_value: str, new_value: str) -> Dict[str, Any]:
        """
        Trigger action based on variable change.
        
        :param action_name: Name of the action to trigger
        :param variable_name: Name of the variable that changed
        :param old_value: Previous value
        :param new_value: New value
        :return: Action result dictionary
        """
        result = {
            'action': action_name,
            'variable': variable_name,
            'status': 'pending'
        }
        
        try:
            if action_name == 'hp_store_enable_disable':
                # Trigger registration check if enabling
                if new_value.lower() in ['true', '1', 'yes']:
                    from services.auto_registration import ensure_registered
                    api_key = ensure_registered()
                    if api_key:
                        result['status'] = 'success'
                        result['message'] = 'HP App Store enabled and registration successful'
                    else:
                        result['status'] = 'warning'
                        result['message'] = 'HP App Store enabled but registration pending (HP App Store may be unavailable)'
                else:
                    result['status'] = 'success'
                    result['message'] = 'HP App Store disabled'
            
            elif action_name == 'api_key_change':
                # Reload remote store configuration
                from config.remote_store import remote_store_config
                remote_store_config._load_env_file()
                result['status'] = 'success'
                result['message'] = 'API key updated and configuration reloaded'
            
            elif action_name == 'base_url_change':
                # Update remote store configuration
                from config.remote_store import remote_store_config
                remote_store_config._load_env_file()
                result['status'] = 'success'
                result['message'] = 'Base URL updated and configuration reloaded'
            
            elif action_name in ['contact_email_change', 'institution_name_change']:
                # These may trigger re-registration, but for now just log
                result['status'] = 'success'
                result['message'] = f'{variable_name} updated'
            
            else:
                result['status'] = 'success'
                result['message'] = 'No action required'
                
        except Exception as e:
            logger.error(f"Error triggering action {action_name}: {e}", exc_info=True)
            result['status'] = 'error'
            result['message'] = f'Action failed: {str(e)}'
        
        return result


class SettingsEnvVariableResource(object):
    """Resource for getting a single environment variable."""
    
    def on_get(self, req, resp, variable_name: str):
        """Get a single environment variable by name."""
        try:
            # Read current environment variables
            env_vars = read_stingar_env()
            
            if variable_name not in env_vars:
                resp.status = falcon.HTTP_404
                resp.media = {
                    'errors': [{
                        'title': 'Not Found',
                        'description': f'Variable {variable_name} not found'
                    }]
                }
                return
            
            value = env_vars[variable_name]
            metadata = VARIABLE_METADATA.get(variable_name, {
                'display_name': variable_name,
                'description': '',
                'type': 'string',
                'default': '',
                'required': False,
                'sensitive': False,
                'editable': True,
                'action_trigger': None,
                'group': 'Other Configuration'
            })
            
            resp.status = falcon.HTTP_200
            resp.media = {
                'data': {
                    'name': variable_name,
                    'display_name': metadata.get('display_name', variable_name),
                    'value': mask_sensitive_value(variable_name, value),  # Masked value for display
                    'raw_value': value,  # Always return raw value (frontend handles masking)
                    'description': metadata.get('description', ''),
                    'type': metadata.get('type', 'string'),
                    'default': metadata.get('default', ''),
                    'required': metadata.get('required', False),
                    'sensitive': metadata.get('sensitive', False),
                    'editable': metadata.get('editable', True),
                    'action_trigger': metadata.get('action_trigger'),
                    'group': metadata.get('group', 'Other Configuration'),
                    'validation': metadata.get('validation', {})
                }
            }
            
        except Exception as e:
            logger.error(f"Error reading environment variable {variable_name}: {e}", exc_info=True)
            resp.status = falcon.HTTP_500
            resp.media = {
                'errors': [{
                    'title': 'Internal Server Error',
                    'description': f'Failed to read environment variable: {str(e)}'
                }]
            }

