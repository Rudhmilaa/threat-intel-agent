# This file contains JSON schema definitions for API POST validation


# Schema definition for Session record
session_schema = {
    "type": "object",
    "properties": {
        "app": {"type": "string"},
        "start_time": {"type": "date"},
        "end_time": {"type": "date"},
        "sensor": {"type": "document"},
        "src_ip": {"type": "string"},
        "src_port": {"type": "number"},
        "dst_ip": {"type": "string"}
    }
}


# Schema definition for Tag record
tag_schema = {
    "type": "object",
    "properties": {
        "tag_name": {"type": "string"},
        "tag_value": {"type": "string"}
    }
}


authkey_schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"}
    }
}


# Schema definition for Host record
host_schema = {
    "type": "object",
    "properties": {
        "address": {"type": "string"},
        "ssh_port": {"type": "number"},
        "username": {"type": "string"},
        "host_id": {"type": "string"},
        "authkey_id": {"type": "integer"}
    }
}


# Schema definition for User record
user_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "email": {"type": "string"},
        "password": {"type": "string"}
    }
}


# Schema definition for username / password authentication
auth_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "password": {"type": "string"}
    }
}

# Schema definition for Cowrie configuration
cowrie_options_schema = {
    "type": "object",
    "properties": {
        "ssh_enabled": {"type": "boolean"},
        "ssh_port": {"type": "integer"},
        "telnet_enabled": {"type": "boolean"},
        "telnet_port": {"type": "integer"}
    }
}

cowrie_config_schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "hp_type": {"enum": ["cowrie"]},
        "hp_options": cowrie_options_schema
    },
    "required": ["hp_type"]
}


cowrie_deploy_schema = {
    "type": "object",
    "properties": {
        "address": {"type": "string"},
        "ssh_port": {"type": "integer"},
        "username": {"type": "string"},
        "authkey_id": {"type": "integer"},
        "hp_type": {"enum": ["cowrie"]},
        "hp_options": cowrie_options_schema
    },
    "required": ["hp_type", "hp_options"]
}


# Schema definition for Dionaea configuration
dionaea_options_schema = {
    "type": "object",
    "properties": {
        "ftp_enabled": {"type": "boolean"},
        "ftp_port": {"type": "integer"},
        "http_enabled": {"type": "boolean"},
        "http_port": {"type": "integer"},
        "https_enabled": {"type": "boolean"},
        "https_port": {"type": "integer"},
        "mqtt_enabled": {"type": "boolean"},
        "mqtt_port": {"type": "integer"},
        "mssql_enabled": {"type": "boolean"},
        "mssql_port": {"type": "integer"},
        "mysql_enabled": {"type": "boolean"},
        "mysql_port": {"type": "integer"},
        "pptp_enabled": {"type": "boolean"},
        "pptp_port": {"type": "integer"},
        "sip_enabled": {"type": "boolean"},
        "sip_port": {"type": "integer"},
        "smb_enabled": {"type": "boolean"},
        "smb_port": {"type": "integer"},
        "tftp_enabled": {"type": "boolean"},
        "tftp_port": {"type": "integer"},
        "upnp_enabled": {"type": "boolean"},
        "upnp_port": {"type": "integer"},
    }
}

dionaea_config_schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "hp_type": {"enum": ["dionaea"]},
        "hp_options": dionaea_options_schema
    },
    "required": ["hp_type"]
}


dionaea_deploy_schema = {
    "type": "object",
    "properties": {
        "address": {"type": "string"},
        "ssh_port": {"type": "integer"},
        "username": {"type": "string"},
        "authkey_id": {"type": "integer"},
        "hp_type": {"enum": ["dionaea"]},
        "hp_options": dionaea_options_schema
    },
    "required": ["hp_type", "hp_options"]
}


# Schema definition for Glastopf configuration
glastopf_options_schema = {
    "type": "object",
    "properties": {
        "web_port": {"type": "integer"}
    }
}

glastopf_config_schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "hp_type": {"enum": ["glastopf"]},
        "hp_options": glastopf_options_schema
    },
    "required": ["hp_type"]
}


glastopf_deploy_schema = {
    "type": "object",
    "properties": {
        "address": {"type": "string"},
        "ssh_port": {"type": "integer"},
        "username": {"type": "string"},
        "authkey_id": {"type": "integer"},
        "hp_type": {"enum": ["glastopf"]},
        "hp_options": glastopf_options_schema
    },
    "required": ["hp_type", "hp_options"]
}


# Schema definition for Conpot configuration
conpot_options_schema = {
    "type": "object",
    "properties": {
        "http_enabled": {"type": "boolean"},
        "http_port": {"type": "integer"},
        "s7_enabled": {"type": "boolean"},
        "s7_port": {"type": "integer"},
        "modbus_enabled": {"type": "boolean"},
        "modbus_port": {"type": "integer"},
        "snmp_enabled": {"type": "boolean"},
        "snmp_port": {"type": "integer"},
        "bacnet_enabled": {"type": "boolean"},
        "bacnet_port": {"type": "integer"},
        "ipmi_enabled": {"type": "boolean"},
        "ipmi_port": {"type": "integer"},
        "ftp_enabled": {"type": "boolean"},
        "ftp_port": {"type": "integer"},
        "tftp_enabled": {"type": "boolean"},
        "tftp_port": {"type": "integer"},
        "enip_enabled": {"type": "boolean"},
        "enip_port": {"type": "integer"}
    }
}

conpot_config_schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "hp_type": {"enum": ["conpot"]},
        "hp_options": conpot_options_schema
    },
    "required": ["hp_type"]
}


conpot_deploy_schema = {
    "type": "object",
    "properties": {
        "address": {"type": "string"},
        "ssh_port": {"type": "integer"},
        "username": {"type": "string"},
        "authkey_id": {"type": "integer"},
        "hp_type": {"enum": ["conpot"]},
        "hp_options": conpot_options_schema
    },
    "required": ["hp_type", "hp_options"]
}


# Schema definition for Amun configuration
amun_options_schema = {
    "type": "object",
    "properties": {
        "smb_enabled": {"type": "boolean"},
        "smb_port": {"type": "integer"},
        "rdp_enabled": {"type": "boolean"},
        "rdp_port": {"type": "integer"}
    }
}

amun_config_schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "hp_type": {"enum": ["amun"]},
        "hp_options": amun_options_schema
    },
    "required": ["hp_type"]
}

amun_deploy_schema = {
    "type": "object",
    "properties": {
        "address": {"type": "string"},
        "ssh_port": {"type": "integer"},
        "username": {"type": "string"},
        "authkey_id": {"type": "integer"},
        "hp_type": {"enum": ["amun"]},
        "hp_options": amun_options_schema
    },
    "required": ["hp_type", "hp_options"]
}

rdphoney_options_schema = {
    "type": "object",
    "properties": {
        "rdp_port": {"type": "integer"}
    }
}

rdphoney_config_schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "hp_type": {"enum": ["rdphoney"]},
        "hp_options": rdphoney_options_schema
    },
    "required": ["hp_type"]
}

rdphoney_deploy_schema = {
    "type": "object",
    "properties": {
        "address": {"type": "string"},
        "ssh_port": {"type": "integer"},
        "username": {"type": "string"},
        "authkey_id": {"type": "integer"},
        "hp_type": {"enum": ["rdphoney"]},
        "hp_options": rdphoney_options_schema
    },
    "required": ["hp_type", "hp_options"]
}

config_schema = {
    "oneOf": [
        cowrie_config_schema,
        dionaea_config_schema,
        glastopf_config_schema,
        conpot_config_schema,
        amun_config_schema,
        rdphoney_config_schema
    ]
}


# Schema definition for new Honeypot deployment records
deployment_schema = {
    "oneOf": [
        cowrie_deploy_schema,
        dionaea_deploy_schema,
        glastopf_deploy_schema,
        conpot_deploy_schema,
        amun_deploy_schema,
        rdphoney_deploy_schema,
        # Generic schema for unknown honeypot types
        # Exclude known honeypot types to prevent overlap with specific schemas
        {
            "allOf": [
                {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string"},
                        "ssh_port": {"type": "integer"},
                        "username": {"type": "string"},
                        "authkey_id": {"type": "integer"},
                        "hp_type": {"type": "string"},
                        "hp_options": {"type": "object"}
                    },
                    "required": ["hp_type", "hp_options"]
                },
                {
                    "properties": {
                        "hp_type": {
                            "not": {"enum": ["cowrie", "dionaea", "glastopf", "conpot", "amun", "rdphoney"]}
                        }
                    }
                }
            ]
        }
    ]
}


# Schema definition for Honeypot deployment status updates
deployment_status_schema = {
    "type": "object",
    "properties": {
        "status": {"type": "integer"}
    }
}


# Schema definition for Deployment push to Langstroth call
deploy_schema = {
    "type": "object",
    "properties": {
        "deployment_id": {"type": "string"},
        "update_status": {"type": "boolean"}
    },
    "required": ["deployment_id"]
}

# Dummy schema
default_schema = {}
