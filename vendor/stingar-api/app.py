import os
import pathlib
import logging
import falcon
from falcon_swagger_ui import register_swaggerui_app

import auth

from resources import ansible as ansible_resource
from resources import authkeys as authkeys_resource
from resources import deployments as deployments_resource
from resources import honeypot_configs as configs_resource
from resources import hosts as hosts_resource
from resources import indicators as indicators_resource
from resources import kibana as kibana_resource
from resources import sensors as sensors_resource
from resources import sessions as sessions_resource
from resources import store as store_resource
from resources import store_config as store_config_resource
from resources import settings as settings_resource
from resources import dns_scanner as dns_scanner_resource
from resources import ids_rules as ids_rules_resource
from resources import tags as tags_resource
from resources import users as users_resource
from resources import cache_validation as cache_validation_resource
from resources import system as system_resource

# Version information
__version__ = "2.3.0"
APP_NAME = "Apiarist"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Reduce httpx logging verbosity - only show warnings and errors
httpx_logger = logging.getLogger("httpx")
httpx_logger.setLevel(logging.WARNING)

# Reduce elastic_transport logging verbosity - only show warnings and errors
elastic_transport_logger = logging.getLogger("elastic_transport")
elastic_transport_logger.setLevel(logging.WARNING)


exempt_routes = ["/api/v2",
                 "/api/v2/swagger-ui.css",
                 "/api/v2/swagger-ui-bundle.js",
                 "/api/v2/swagger-ui-standalone-preset.js",
                 "/api/v2/store/register-instance",  # Registration doesn't need auth (it's how you get an API key)
                 "/api/v2/store/config"]  # Config endpoint reads local stingar.env (non-sensitive data)

exempt_static_routes = ["/static/v2/"]


api = application = falcon.App(middleware=[auth.AuthMiddleware(exempt_routes=exempt_routes,
                                                               exempt_static_routes=exempt_static_routes)])

# Log startup message
logger.info(f"{APP_NAME} v{__version__} starting up")

# Auto-register with HP App Store if needed (runs in background, doesn't block startup)
# If HP App Store is unavailable, Apiarist continues to function normally
try:
    from services.auto_registration import ensure_registered, retry_registration_periodically
    import threading
    
    def register_in_background():
        """Register instance in background thread to avoid blocking startup."""
        try:
            # Initial registration attempt (non-blocking)
            ensure_registered()
            
            # Start periodic retry loop (in case HP App Store was unavailable initially)
            logger.info("Starting periodic registration retry loop")
            retry_registration_periodically()
        except Exception as e:
            logger.error(f"Background registration failed: {e}")
            # Don't crash - Apiarist should continue to work
    
    # Start registration in background thread (daemon thread - won't prevent shutdown)
    registration_thread = threading.Thread(target=register_in_background, daemon=True)
    registration_thread.start()
    logger.info("Started background auto-registration thread (non-blocking)")
except Exception as e:
    logger.warning(f"Could not start auto-registration: {e}")
    logger.info("Apiarist will continue to function normally without HP App Store integration")

# Start update service for automatic image pulling (runs in background, doesn't block startup)
try:
    from services.update_service import (
        ensure_update_service_started,
        reconcile_version_state_on_boot,
    )

    # Reconcile the legacy version state file with the actually-running
    # image version before starting any subsystem that reads it. Absorbs
    # out-of-band ``docker compose pull`` updates so the dashboard never
    # reports a stale "current version". Safe to call repeatedly.
    # See Roadmap/plans/VERSIONING_OVERHAUL_PLAN.md (phase 4 / P4).
    reconcile_version_state_on_boot()

    ensure_update_service_started()
except Exception as e:
    logger.warning(f"Could not start update service: {e}")
    logger.info("Apiarist will continue to function normally without update service")

# IDS rules feed: on-demand generation (no background scheduler)


SWAGGERUI_URL = '/api/v2'
SCHEMA_URL = '/static/v2/swagger.yaml'
STATIC_PATH = pathlib.Path(__file__).parent / 'static'
api.add_static_route('/static', str(STATIC_PATH))

page_title = 'STINGARv2 Swagger Doc'
favicon_url = 'https://falconframework.org/favicon-32x32.png'

register_swaggerui_app(
    api, SWAGGERUI_URL, SCHEMA_URL,
    page_title=page_title,
    favicon_url=favicon_url,
    config={'supportedSubmitMethods': ['get', 'put', 'post', 'delete'], }
)

passphrase = os.environ.get("PASSPHRASE")
salt = os.environ.get("SALT")


# FALCON API RESOURCES
session = sessions_resource.SessionResource()
sessions = sessions_resource.SessionsResource()

indicators = indicators_resource.IndicatorResource()

sensors = sensors_resource.SensorsResource()
sensor = sensors_resource.SensorResource()
stopsensor = sensors_resource.StopSensorResource()
startsensor = sensors_resource.StartSensorResource()
restartsensor = sensors_resource.RestartSensorResource()

users = users_resource.UsersResource()
user = users_resource.UserResource()
token = users_resource.TokenResource()
auth_user = users_resource.AuthenticationResource()

authkeys = authkeys_resource.AuthKeysResource(passphrase=passphrase, salt=salt)
authkey = authkeys_resource.AuthKeyResource()

hosts = hosts_resource.HostsResource()
host = hosts_resource.HostResource()

config = configs_resource.HoneypotConfigResource()
configs = configs_resource.HoneypotConfigsResource()
config_cleanup = configs_resource.ConfigCleanupResource()
store_cache_cleanup = configs_resource.StoreCacheCleanupResource()

deployments = deployments_resource.DeploymentsResource()
deployments_compose = deployments_resource.DeploymentsComposeResource()
deployments_env = deployments_resource.DeploymentsEnvResource()
deployment = deployments_resource.DeploymentResource()
deployment_compose = deployments_resource.DeploymentComposeResource()
deployment_env = deployments_resource.DeploymentEnvResource()
deployment_status = deployments_resource.DeploymentStatusResource()
deploy = deployments_resource.DeployResource()

tags = tags_resource.TagsResource()
tag = tags_resource.TagResource()

ansible_logs = ansible_resource.AnsibleLogsResource()

kibana_objects = kibana_resource.KibanaObjectsResource()
kibana_saved_objects = kibana_resource.KibanaSavedObjectsResource()
kibana_saved_object = kibana_resource.KibanaSavedObjectResource()
kibana_load_active = kibana_resource.KibanaObjectsLoadActiveResource()
kibana_load = kibana_resource.KibanaObjectsLoadResource()
kibana_save = kibana_resource.KibanaObjectsSaveResource()

# Store resources
store = store_resource.StoreResource()
store_honeypot = store_resource.StoreHoneypotResource()
store_search = store_resource.StoreSearchResource()
store_categories = store_resource.StoreCategoriesResource()
store_tags = store_resource.StoreTagsResource()
local_installations = store_resource.LocalInstallationsResource()
store_requests = store_resource.StoreRequestsResource()
store_request_vote = store_resource.StoreRequestVoteResource()
store_request_vote_status = store_resource.StoreRequestVoteStatusResource()
store_config = store_config_resource.StoreConfigResource()
store_config_api_key = store_config_resource.StoreConfigAPIKeyResource()
store_registration = store_config_resource.StoreRegistrationResource()

# Settings resources
settings_env = settings_resource.SettingsEnvResource()
settings_env_variable = settings_resource.SettingsEnvVariableResource()

# DNS Scanner resources
dns_scanner_scan = dns_scanner_resource.DNSScannerScanResource()
dns_scanner_result = dns_scanner_resource.DNSScannerResultResource()
dns_scanner_bulk_update = dns_scanner_resource.DNSScannerBulkUpdateResource()
dns_scanner_config = dns_scanner_resource.DNSScannerConfigResource()

# IDS Rules resources
ids_rules = ids_rules_resource.IDSRulesResource()
ids_rules_preview = ids_rules_resource.IDSRulesPreviewResource()
ids_rules_export = ids_rules_resource.IDSRulesExportResource()
ids_rules_feed = ids_rules_resource.IDSRulesFeedResource()
ids_rules_status = ids_rules_resource.IDSRulesStatusResource()


# FALCON API ROUTES
api.add_route('/api/v2/sessions', sessions)
api.add_route('/api/v2/sessions/{ident}', session)
#api.add_route('/api/v2/sessions/manage/{ident}', session)

api.add_route('/api/v2/indicators', indicators)

api.add_route('/api/v2/sensors', sensors)
api.add_route('/api/v2/sensors/{ident}', sensor)
api.add_route('/api/v2/sensors/stop/{ident}', stopsensor)
api.add_route('/api/v2/sensors/start/{ident}', startsensor)
api.add_route('/api/v2/sensors/restart/{ident}', restartsensor)

api.add_route('/api/v2/authenticate_user', auth_user)
api.add_route('/api/v2/users', users)
api.add_route('/api/v2/users/{ident}', user)
api.add_route('/api/v2/users/{ident}/token', token)

api.add_route('/api/v2/authkeys', authkeys)
api.add_route('/api/v2/authkeys/{ident}', authkey)

api.add_route('/api/v2/hosts', hosts)
api.add_route('/api/v2/hosts/{ident}', host)

api.add_route('/api/v2/configs', configs)
api.add_route('/api/v2/configs/{ident}', config)
api.add_route('/api/v2/configs/cleanup', config_cleanup)
api.add_route('/api/v2/store/cleanup-cache', store_cache_cleanup)

api.add_route('/api/v2/deployments', deployments)
api.add_route('/api/v2/deployments/compose', deployments_compose)
api.add_route('/api/v2/deployments/env', deployments_env)
api.add_route('/api/v2/deployments/{ident}', deployment)
api.add_route('/api/v2/deployments/{ident}/compose', deployment_compose)
api.add_route('/api/v2/deployments/{ident}/env', deployment_env)
api.add_route('/api/v2/deployments/{ident}/status', deployment_status)
api.add_route('/api/v2/deploymentlogs', ansible_logs)
api.add_route('/api/v2/deploy', deploy)

api.add_route('/api/v2/tags', tags)
api.add_route('/api/v2/tags/{ident}', tag)

api.add_route('/api/v2/kibana/objects', kibana_objects)
api.add_route('/api/v2/kibana/saved_objects', kibana_saved_objects)
api.add_route('/api/v2/kibana/saved_objects/{ident}', kibana_saved_object)
api.add_route('/api/v2/kibana/load', kibana_load_active)
api.add_route('/api/v2/kibana/load/{ident}', kibana_load)
api.add_route('/api/v2/kibana/save', kibana_save)

# Store routes
api.add_route('/api/v2/store/honeypots/count', store, suffix='count')
api.add_route('/api/v2/store/honeypots', store)
api.add_route('/api/v2/store/honeypots/{ident}', store_honeypot)
api.add_route('/api/v2/store/search', store_search)
api.add_route('/api/v2/store/categories', store_categories)
api.add_route('/api/v2/store/tags', store_tags)
api.add_route('/api/v2/store/installed', local_installations)
api.add_route('/api/v2/store/installed/{ident}', local_installations)
# Request routes (proxy to HP App Store)
api.add_route('/api/v2/store/requests', store_requests)
api.add_route('/api/v2/store/requests/{ident}', store_requests)
api.add_route('/api/v2/store/requests/{ident}/vote', store_request_vote)
api.add_route('/api/v2/store/requests/{ident}/vote-status', store_request_vote_status)
api.add_route('/api/v2/store/config', store_config)
api.add_route('/api/v2/store/config/api-key', store_config_api_key)
api.add_route('/api/v2/store/register-instance', store_registration)

# Settings routes
api.add_route('/api/v2/settings/env', settings_env)
api.add_route('/api/v2/settings/env/{variable_name}', settings_env_variable)

# System routes (version and update management)
system_version = system_resource.SystemVersionResource()
system_update_check = system_resource.SystemUpdateCheckResource()
system_update_status = system_resource.SystemUpdateStatusResource()
system_update_apply = system_resource.SystemUpdateApplyResource()
system_update_job_status = system_resource.SystemUpdateJobStatusResource()
system_update_settings = system_resource.SystemUpdateSettingsResource()

api.add_route('/api/v2/system/version', system_version)
api.add_route('/api/v2/system/update-check', system_update_check)
api.add_route('/api/v2/system/update-status', system_update_status)
api.add_route('/api/v2/system/update/apply', system_update_apply)
api.add_route('/api/v2/system/update/status/{job_id}', system_update_job_status)
api.add_route('/api/v2/settings/update', system_update_settings)

# DNS Scanner routes (proxy to HP App Store)
# Note: More specific routes (like bulk-update) must be registered before parameterized routes
api.add_route('/api/v2/dns-scanner/scan', dns_scanner_scan)
api.add_route('/api/v2/dns-scanner/scans', dns_scanner_scan)
api.add_route('/api/v2/dns-scanner/scans/{ident}', dns_scanner_scan)
api.add_route('/api/v2/dns-scanner/scans/{ident}/results', dns_scanner_result)
api.add_route('/api/v2/dns-scanner/results/bulk-update', dns_scanner_bulk_update)  # Must come before {ident} route
api.add_route('/api/v2/dns-scanner/results/{ident}', dns_scanner_result)
api.add_route('/api/v2/dns-scanner/config/description', dns_scanner_config)

# IDS Rules routes (more specific routes before base)
api.add_route('/api/v2/ids-rules/export', ids_rules_export)
api.add_route('/api/v2/ids-rules/feed', ids_rules_feed)
api.add_route('/api/v2/ids-rules/status', ids_rules_status)
api.add_route('/api/v2/ids-rules/preview', ids_rules_preview)
api.add_route('/api/v2/ids-rules', ids_rules)

# Cache validation routes
cache_validation = cache_validation_resource.CacheValidationResource()
cache_statistics = cache_validation_resource.CacheStatisticsResource()
specific_honeypot_validation = cache_validation_resource.SpecificHoneypotValidationResource()
stale_honeypots = cache_validation_resource.StaleHoneypotsResource()

api.add_route('/api/v2/cache/validate', cache_validation)
api.add_route('/api/v2/cache/statistics', cache_statistics)
api.add_route('/api/v2/cache/validate/{remote_id}', specific_honeypot_validation)
api.add_route('/api/v2/cache/stale', stale_honeypots)
