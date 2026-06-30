"""
Generic Foundation Class for Apiarist.

This module provides a generic builder class for honeypot types without specific builders.
Uses configuration data to dynamically determine ports and environment variables.
"""

import json
import logging
import io
import yaml
from .base import BaseFoundation
from .ports import apply_transport

logger = logging.getLogger(__name__)


def _explicit_transport(config, service_name=None):
    """Pull an explicit transport hint out of a store config fragment.

    Accepts either a per-service form (``{service}_transport`` /
    ``{service}_protocol`` / ``{service}_udp`` on the parent dict) or a
    per-port-dict form (``transport`` / ``protocol`` / ``udp`` keys). Returns
    "udp"/"tcp"/"both" or None; bogus values fall through to None so the
    name/port heuristic still applies.
    """
    if not isinstance(config, dict):
        return None
    if service_name is not None:
        if config.get(f"{service_name}_udp") is True:
            return "udp"
        return (config.get(f"{service_name}_transport")
                or config.get(f"{service_name}_protocol"))
    if config.get("udp") is True:
        return "udp"
    return config.get("transport")


class GenericFoundation(BaseFoundation):
    """
    Generic builder class for honeypot types without specific builders.
    Uses configuration data to dynamically determine ports and environment variables.
    """

    def get_docker_ports(self, hp_options):
        """
        Extract ports from configuration data.
        
        Args:
            hp_options: Honeypot options dictionary
            
        Returns:
            List of port mappings
        """
        ports = []
        
        # Handle different port configuration formats
        if isinstance(hp_options, str):
            try:
                hp_options = json.loads(hp_options)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse hp_options as JSON: {hp_options}")
                return ports
        
        # Default container ports per protocol, used when only a protocol name
        # is supplied. Includes UDP services (snmp/tftp/bacnet/...) so a store
        # honeypot declaring only supported_protocols still gets a mapping AND
        # the correct transport (apply_transport adds "/udp").
        protocol_default_ports = {
            'ssh': 22, 'telnet': 23, 'ftp': 21, 'http': 80, 'https': 443,
            'smtp': 25, 'pop3': 110, 'imap': 143, 'rdp': 3389, 'vnc': 5900,
            'mqtt': 1883, 'modbus': 502, 's7': 102, 'enip': 44818,
            'snmp': 161, 'snmptrap': 162, 'tftp': 69, 'bacnet': 47808,
            'ipmi': 623, 'ntp': 123, 'sip': 5060, 'syslog': 514, 'dns': 53,
            'netbios': 137, 'mdns': 5353, 'ssdp': 1900, 'upnp': 1900,
            'coap': 5683, 'radius': 1812,
        }
        
        # Extract ports from configuration
        if 'ports' in hp_options:
            for port_config in hp_options['ports']:
                if isinstance(port_config, dict):
                    external = port_config.get('external', '')
                    internal = port_config.get('internal', '')
                    if external and internal:
                        ports.extend(apply_transport(
                            f"{external}:{internal}",
                            protocol=port_config.get('protocol'),
                            port=internal,
                            transport=_explicit_transport(port_config)))
                elif isinstance(port_config, str):
                    # Handle "external:internal" format (a "/udp" or "/tcp"
                    # suffix already present is honored by apply_transport).
                    ports.extend(apply_transport(port_config))
        
        # Extract ports from default_configuration if available
        if 'default_configuration' in hp_options:
            default_config = hp_options['default_configuration']
            if isinstance(default_config, str):
                try:
                    default_config = json.loads(default_config)
                except json.JSONDecodeError:
                    pass
            
            if isinstance(default_config, dict) and 'ports' in default_config:
                for port_config in default_config['ports']:
                    if isinstance(port_config, dict):
                        external = port_config.get('external', '')
                        internal = port_config.get('internal', '')
                        if external and internal:
                            ports.extend(apply_transport(
                                f"{external}:{internal}",
                                protocol=port_config.get('protocol'),
                                port=internal,
                                transport=_explicit_transport(port_config)))
        
        # Extract ports from supported_protocols if available
        if 'supported_protocols' in hp_options:
            protocols = hp_options['supported_protocols']
            if isinstance(protocols, str):
                try:
                    protocols = json.loads(protocols)
                except json.JSONDecodeError:
                    protocols = [protocols]
            
            if isinstance(protocols, list):
                for protocol in protocols:
                    proto = str(protocol).lower()
                    if proto in protocol_default_ports:
                        p = protocol_default_ports[proto]
                        ports.extend(apply_transport(
                            f"{p}:{p}", protocol=proto, port=p))
        
        # Extract ports from _enabled and _port format (HP App Store format)
        for key, value in hp_options.items():
            if key.endswith('_enabled') and value:
                service_name = key.replace('_enabled', '')
                port_key = f"{service_name}_port"
                if port_key in hp_options:
                    internal_port = hp_options[port_key]
                    
                    # For honeypot services, use the port from hp_options for both external and internal
                    # The deployment sshPort is for Ansible deployment, not honeypot service ports
                    ports.extend(apply_transport(
                        f"{internal_port}:{internal_port}",
                        protocol=service_name,
                        port=internal_port,
                        transport=_explicit_transport(hp_options, service_name)))
        
        # Extract ports from custom port arrays
        if 'custom_ports' in hp_options:
            custom_ports = hp_options['custom_ports']
            if isinstance(custom_ports, list):
                for port in custom_ports:
                    if isinstance(port, (int, str)):
                        ports.extend(apply_transport(f"{port}:{port}", port=port))
                    elif isinstance(port, dict):
                        # Handle {"port": 5555} or {"external": 5555, "internal": 5555} format
                        if 'port' in port:
                            port_num = port['port']
                            ports.extend(apply_transport(
                                f"{port_num}:{port_num}",
                                protocol=port.get('protocol'),
                                port=port_num,
                                transport=_explicit_transport(port)))
                        elif 'external' in port and 'internal' in port:
                            ports.extend(apply_transport(
                                f"{port['external']}:{port['internal']}",
                                protocol=port.get('protocol'),
                                port=port['internal'],
                                transport=_explicit_transport(port)))
        
        # Extract ports from port ranges
        if 'port_ranges' in hp_options:
            port_ranges = hp_options['port_ranges']
            if isinstance(port_ranges, list):
                for port_range in port_ranges:
                    if isinstance(port_range, dict):
                        start = port_range.get('start')
                        end = port_range.get('end')
                        transport = _explicit_transport(port_range)
                        if start and end and isinstance(start, (int, str)) and isinstance(end, (int, str)):
                            try:
                                start_int = int(start)
                                end_int = int(end)
                                for port in range(start_int, end_int + 1):
                                    ports.extend(apply_transport(
                                        f"{port}:{port}", port=port, transport=transport))
                            except (ValueError, TypeError):
                                logger.warning(f"Invalid port range: {start}-{end}")
        
        # Extract ports from game_ports or similar custom port configurations
        for key, value in hp_options.items():
            if key.endswith('_ports') and key != 'custom_ports' and key != 'port_ranges':
                if isinstance(value, list):
                    for port in value:
                        if isinstance(port, (int, str)):
                            ports.extend(apply_transport(f"{port}:{port}", port=port))
                        elif isinstance(port, dict):
                            if 'port' in port:
                                ports.extend(apply_transport(
                                    f"{port['port']}:{port['port']}",
                                    protocol=port.get('protocol'),
                                    port=port['port'],
                                    transport=_explicit_transport(port)))
                            elif 'external' in port and 'internal' in port:
                                ports.extend(apply_transport(
                                    f"{port['external']}:{port['internal']}",
                                    protocol=port.get('protocol'),
                                    port=port['internal'],
                                    transport=_explicit_transport(port)))
                elif isinstance(value, dict):
                    # Handle {"start": 5555, "end": 5600} format
                    start = value.get('start')
                    end = value.get('end')
                    transport = _explicit_transport(value)
                    if start and end and isinstance(start, (int, str)) and isinstance(end, (int, str)):
                        try:
                            start_int = int(start)
                            end_int = int(end)
                            for port in range(start_int, end_int + 1):
                                ports.extend(apply_transport(
                                    f"{port}:{port}", port=port, transport=transport))
                        except (ValueError, TypeError):
                            logger.warning(f"Invalid port range in {key}: {start}-{end}")
        
        # Extract ports from any numeric keys that look like port numbers
        for key, value in hp_options.items():
            if key.endswith('_port') and not key.endswith('_enabled'):
                # Skip if we already processed this in the _enabled/_port section
                continue
            
            # Look for keys that might be direct port specifications
            if key.endswith('_port_num') or key.endswith('_port_number'):
                if isinstance(value, (int, str)):
                    try:
                        port_num = int(value)
                        if 1 <= port_num <= 65535:  # Valid port range
                            ports.extend(apply_transport(f"{port_num}:{port_num}", port=port_num))
                    except (ValueError, TypeError):
                        pass
        
        logger.debug(f"Extracted ports for generic honeypot: {ports}")
        return ports
    
    def get_docker_image(self, hp_options):
        """
        Extract docker image from hp_options.
        
        Args:
            hp_options: Honeypot options dictionary
            
        Returns:
            Docker image string
        """
        try:
            if isinstance(hp_options, str):
                hp_options = json.loads(hp_options)
            
            # Check for docker image in hp_options (HP App Store format)
            if 'docker_image' in hp_options:
                return hp_options['docker_image']
            
            # Check for docker image name and tag separately
            if 'docker_image_name' in hp_options and 'docker_tag' in hp_options:
                return f"{hp_options['docker_image_name']}:{hp_options['docker_tag']}"
            
            # Fallback to default
            return '4warned/unknown:latest'
            
        except Exception as e:
            logger.warning(f"Error extracting docker image from hp_options: {e}")
            return '4warned/unknown:latest'

    def get_reported_port_envs(self, hp_options):
        """
        Extract port environment variables from configuration.
        
        Args:
            hp_options: Honeypot options dictionary
            
        Returns:
            Dictionary of port environment variables
        """
        port_envs = {}
        
        if isinstance(hp_options, str):
            try:
                hp_options = json.loads(hp_options)
            except json.JSONDecodeError:
                return port_envs
        
        # Extract port information for environment variables
        if 'ports' in hp_options:
            for i, port_config in enumerate(hp_options['ports']):
                if isinstance(port_config, dict):
                    external = port_config.get('external', '')
                    if external:
                        port_envs[f"REPORTED_PORT_{i+1}"] = str(external)
        
        # Extract from default_configuration
        if 'default_configuration' in hp_options:
            default_config = hp_options['default_configuration']
            if isinstance(default_config, str):
                try:
                    default_config = json.loads(default_config)
                except json.JSONDecodeError:
                    pass
            
            if isinstance(default_config, dict) and 'ports' in default_config:
                for i, port_config in enumerate(default_config['ports']):
                    if isinstance(port_config, dict):
                        external = port_config.get('external', '')
                        if external:
                            port_envs[f"REPORTED_PORT_{i+1}"] = str(external)
        
        # Extract from supported_protocols
        if 'supported_protocols' in hp_options:
            protocols = hp_options['supported_protocols']
            if isinstance(protocols, str):
                try:
                    protocols = json.loads(protocols)
                except json.JSONDecodeError:
                    protocols = [protocols]
            
            if isinstance(protocols, list):
                for i, protocol in enumerate(protocols):
                    protocol_ports = {
                        'ssh': '22',
                        'telnet': '23',
                        'ftp': '21',
                        'http': '80',
                        'https': '443',
                        'smtp': '25',
                        'pop3': '110',
                        'imap': '143',
                        'rdp': '3389',
                        'vnc': '5900'
                    }
                    
                    if protocol.lower() in protocol_ports:
                        port_envs[f"REPORTED_{protocol.upper()}_PORT"] = protocol_ports[protocol.lower()]
        
        logger.debug(f"Extracted port environment variables: {port_envs}")
        return port_envs

    def get_environment_variables(self, hp_options):
        """
        Extract additional environment variables from configuration.
        
        Args:
            hp_options: Honeypot options dictionary
            
        Returns:
            Dictionary of environment variables
        """
        env_vars = {}
        
        if isinstance(hp_options, str):
            try:
                hp_options = json.loads(hp_options)
            except json.JSONDecodeError:
                return env_vars
        
        # Extract environment variables from configuration
        if 'environment' in hp_options:
            env_config = hp_options['environment']
            if isinstance(env_config, dict):
                for key, value in env_config.items():
                    env_vars[key.upper()] = str(value)
        
        # Extract from default_configuration
        if 'default_configuration' in hp_options:
            default_config = hp_options['default_configuration']
            if isinstance(default_config, str):
                try:
                    default_config = json.loads(default_config)
                except json.JSONDecodeError:
                    pass
            
            if isinstance(default_config, dict) and 'environment' in default_config:
                env_config = default_config['environment']
                if isinstance(env_config, dict):
                    for key, value in env_config.items():
                        env_vars[key.upper()] = str(value)
        
        # Extract honeypot-specific configuration
        if 'honeypot_config' in hp_options:
            hp_config = hp_options['honeypot_config']
            if isinstance(hp_config, str):
                try:
                    hp_config = json.loads(hp_config)
                except json.JSONDecodeError:
                    pass
            
            if isinstance(hp_config, dict):
                for key, value in hp_config.items():
                    env_vars[f"HP_{key.upper()}"] = str(value)
        
        logger.debug(f"Extracted environment variables: {env_vars}")
        return env_vars

    def get_volume_mounts(self, hp_options):
        """
        Extract volume mount information from configuration.
        
        Args:
            hp_options: Honeypot options dictionary
            
        Returns:
            List of volume mount strings
        """
        volumes = []
        
        if isinstance(hp_options, str):
            try:
                hp_options = json.loads(hp_options)
            except json.JSONDecodeError:
                return volumes
        
        # Extract volumes from configuration
        if 'volumes' in hp_options:
            vol_config = hp_options['volumes']
            if isinstance(vol_config, list):
                for vol in vol_config:
                    if isinstance(vol, dict):
                        host_path = vol.get('host', '')
                        container_path = vol.get('container', '')
                        if host_path and container_path:
                            volumes.append(f"{host_path}:{container_path}")
                    elif isinstance(vol, str):
                        volumes.append(vol)
        
        # Extract from default_configuration
        if 'default_configuration' in hp_options:
            default_config = hp_options['default_configuration']
            if isinstance(default_config, str):
                try:
                    default_config = json.loads(default_config)
                except json.JSONDecodeError:
                    pass
            
            if isinstance(default_config, dict) and 'volumes' in default_config:
                vol_config = default_config['volumes']
                if isinstance(vol_config, list):
                    for vol in vol_config:
                        if isinstance(vol, dict):
                            host_path = vol.get('host', '')
                            container_path = vol.get('container', '')
                            if host_path and container_path:
                                volumes.append(f"{host_path}:{container_path}")
                        elif isinstance(vol, str):
                            volumes.append(vol)
        
        logger.debug(f"Extracted volume mounts: {volumes}")
        return volumes

    def build_docker_compose(self, compose_template, deployment, docker_repository="", env_filename="stingar-hp.env"):
        """
        Enhanced docker-compose builder that uses HP App Store configuration values.
        
        Args:
            compose_template: docker-compose.yml template file
            deployment: Honeypot Deployment object
            docker_repository: Docker repository prefix
            env_filename: Environment file name
            
        Returns:
            Enhanced docker-compose.yml content
        """
        # Check if this is a Jinja2 template (contains {{ }} variables or {% %} control structures)
        try:
            with open(compose_template, 'r') as f:
                template_content = f.read()
            
            # Detect Jinja2 templates by checking for both variable syntax and control structures
            is_jinja2_template = (
                ('{{' in template_content and '}}' in template_content) or
                ('{%' in template_content and '%}' in template_content) or
                ('%' in template_content and ('if' in template_content or 'for' in template_content or 'set' in template_content))
            )
            
            if is_jinja2_template:
                # This is a Jinja2 template - render it
                try:
                    # Try importing Environment first (newer Jinja2 versions)
                    try:
                        from jinja2 import Environment
                        env = Environment()
                    except ImportError:
                        # Fallback to SandboxedEnvironment (older versions)
                        from jinja2 import SandboxedEnvironment
                        env = SandboxedEnvironment()
                    
                    template = env.from_string(template_content)
                    
                    # Extract docker_image from hp_options if not directly in deployment
                    docker_image = deployment.get('docker_image')
                    if not docker_image:
                        # Try to extract from hp_options (HP App Store format)
                        hp_options = deployment.get('hp_options', '{}')
                        if isinstance(hp_options, str):
                            try:
                                hp_options_dict = json.loads(hp_options)
                            except (json.JSONDecodeError, TypeError):
                                hp_options_dict = {}
                        else:
                            hp_options_dict = hp_options
                        
                        # Use get_docker_image method to extract docker_image
                        docker_image = self.get_docker_image(hp_options_dict)
                        if docker_image == '4warned/unknown:latest':
                            # Fallback: construct from hp_type
                            hp_type = deployment.get('hp_type', 'unknown')
                            docker_tag = hp_options_dict.get('docker_tag', 'latest')
                            docker_image = f'4warned/{hp_type}:{docker_tag}'
                            logger.debug(f"docker_image not found in deployment or hp_options, constructed from hp_type: {docker_image}")
                    
                    # Prepare template context - sanitize data to prevent code execution
                    context = {
                        'honeypot_name': str(deployment.get('hp_type', 'honeypot')),
                        'honeypot_type': str(deployment.get('hp_type', 'unknown')),
                        'docker_image': str(docker_image),
                        'ports': self._get_ports_for_template(deployment),
                        'volumes': list(deployment.get('volumes', [])) if isinstance(deployment.get('volumes'), list) else [],
                        'environment': dict(deployment.get('environment', {})) if isinstance(deployment.get('environment'), dict) else {}
                    }
                    
                    # Render template
                    rendered_content = template.render(**context)
                    
                    # Parse the rendered content as YAML
                    data = yaml.safe_load(io.StringIO(rendered_content))
                    
                except ImportError as import_err:
                    error_msg = (
                        f"Jinja2 template detected but Jinja2 is not available. "
                        f"Template file '{compose_template}' contains Jinja2 syntax that cannot be parsed as static YAML. "
                        f"Please install Jinja2: pip install jinja2"
                    )
                    logging.error(error_msg)
                    raise ValueError(error_msg) from import_err
                except Exception as e:
                    logging.warning(f"Failed to render Jinja2 template: {e}, attempting fallback")
                    # Try to parse as YAML anyway (might work if template is mostly static)
                    try:
                        data = yaml.safe_load(io.StringIO(template_content))
                        logging.warning("Successfully parsed template as static YAML despite Jinja2 syntax")
                    except yaml.YAMLError as yaml_err:
                        error_msg = (
                            f"Template file '{compose_template}' contains Jinja2 syntax but cannot be parsed. "
                            f"Original error: {e}. YAML parse error: {yaml_err}"
                        )
                        logging.error(error_msg)
                        raise ValueError(error_msg) from yaml_err
            else:
                # This is a static YAML file
                data = yaml.safe_load(io.StringIO(template_content))
                
        except Exception as e:
            logging.error(f"Error reading template file {compose_template}: {e}")
            raise

        hp_type = deployment.get('hp_type')
        hp_options = deployment.get('hp_options', '{}')
        
        if isinstance(hp_options, str):
            try:
                hp_options = json.loads(hp_options)
            except json.JSONDecodeError:
                hp_options = {}
        
        # Update docker image from HP App Store configuration BEFORE repository prefixing
        logger.debug(f"hp_options for {hp_type}: {hp_options}")
        docker_image = self.get_docker_image(hp_options)
        logger.debug(f"Extracted docker image for {hp_type}: {docker_image}")
        if docker_image and docker_image != '4warned/unknown:latest' and hp_type in data.get('services', {}):
            data['services'][hp_type]['image'] = docker_image
            logger.debug(f"Updated docker image for {hp_type} to: {docker_image}")
        else:
            logger.debug(f"Keeping original docker image for {hp_type}: {data['services'][hp_type].get('image', 'not set')}")
        
        # Apply standard BaseFoundation logic
        try:
            data['services']['fluentbit']['env_file'] = env_filename
        except KeyError:
            logging.error("No fluentbit definition found in template file %s.", compose_template)

        try:
            data['services'][hp_type]['env_file'] = env_filename
        except KeyError:
            logging.error("No honeypot definition found in template file %s for honeypot type %s", (compose_template,
                                                                                                    hp_type))
        
        # Apply docker repository prefixing (standard BaseFoundation logic)
        if docker_repository:
            fluentbit_image = data['services']['fluentbit']['image']
            data['services']['fluentbit']['image'] = docker_repository + "/" + fluentbit_image
            try:
                # Use the updated image name (which may have been set from hp_options)
                hp_image = data['services'][hp_type]['image']
                # Only add repository prefix if the image doesn't already have one
                if not hp_image.startswith(docker_repository + "/"):
                    data['services'][hp_type]['image'] = docker_repository + "/" + hp_image
            except KeyError:
                logging.error("No honeypot definition found in template file %s for honeypot type %s",
                              (compose_template,
                               hp_type))

        # Add ports from hp_options
        ports = self.get_docker_ports(hp_options)
        data['services'][hp_type]['ports'] = ports
        
        # Add environment variables from HP App Store configuration
        env_vars = self.get_environment_variables(hp_options)
        if env_vars and hp_type in data.get('services', {}):
            if 'environment' not in data['services'][hp_type]:
                data['services'][hp_type]['environment'] = []
            
            for key, value in env_vars.items():
                data['services'][hp_type]['environment'].append(f"{key}={value}")
        
        # Add volume mounts from HP App Store configuration
        volumes = self.get_volume_mounts(hp_options)
        if volumes and hp_type in data.get('services', {}):
            if 'volumes' not in data['services'][hp_type]:
                data['services'][hp_type]['volumes'] = []
            
            data['services'][hp_type]['volumes'].extend(volumes)
        
        # Add reported port environment variables
        port_envs = self.get_reported_port_envs(hp_options)
        if port_envs and hp_type in data.get('services', {}):
            if 'environment' not in data['services'][hp_type]:
                data['services'][hp_type]['environment'] = []
            
            for key, value in port_envs.items():
                data['services'][hp_type]['environment'].append(f"{key}={value}")
        
        logger.debug(f"Enhanced docker-compose with HP App Store configuration for {hp_type}")
        return yaml.dump(data, default_flow_style=False)

    def build_honeypot_env(self, env_template, deployment, fluent_host, fluent_port, fluent_key):
        """
        Enhanced environment file builder that uses HP App Store configuration values.
        
        Args:
            env_template: Environment template file
            deployment: Honeypot Deployment object
            fluent_host: Fluentd host
            fluent_port: Fluentd port
            fluent_key: Fluentd key
            
        Returns:
            Enhanced environment file content
        """
        # Call parent method first
        env_content = super().build_honeypot_env(env_template, deployment, fluent_host, fluent_port, fluent_key)
        
        # Parse existing environment variables
        env_lines = env_content.split('\n')
        env_dict = {}
        
        for line in env_lines:
            if '=' in line:
                key, value = line.split('=', 1)
                env_dict[key] = value
        
        # Add HP App Store configuration values
        hp_options = deployment.get('hp_options', '{}')
        if isinstance(hp_options, str):
            try:
                hp_options = json.loads(hp_options)
            except json.JSONDecodeError:
                hp_options = {}
        
        # Add environment variables from configuration
        env_vars = self.get_environment_variables(hp_options)
        for key, value in env_vars.items():
            env_dict[key] = value
        
        # Add reported port environment variables
        port_envs = self.get_reported_port_envs(hp_options)
        for key, value in port_envs.items():
            env_dict[key] = value
        
        # Add honeypot-specific metadata
        if 'default_configuration' in hp_options:
            default_config = hp_options['default_configuration']
            if isinstance(default_config, str):
                try:
                    default_config = json.loads(default_config)
                except json.JSONDecodeError:
                    default_config = {}
            
            if isinstance(default_config, dict):
                # Add honeypot type and version
                if 'honeypot_type' in default_config:
                    env_dict['HONEYPOT_TYPE'] = default_config['honeypot_type']
                if 'version' in default_config:
                    env_dict['HONEYPOT_VERSION'] = default_config['version']
                if 'description' in default_config:
                    env_dict['HONEYPOT_DESCRIPTION'] = default_config['description']
        
        # Add supported protocols
        if 'supported_protocols' in hp_options:
            protocols = hp_options['supported_protocols']
            if isinstance(protocols, str):
                try:
                    protocols = json.loads(protocols)
                except json.JSONDecodeError:
                    protocols = [protocols]
            
            if isinstance(protocols, list):
                env_dict['SUPPORTED_PROTOCOLS'] = ','.join(protocols)
        
        logger.debug(f"Enhanced environment file with HP App Store configuration")
        return "\n".join([f"{key}={value}" for key, value in env_dict.items()])
