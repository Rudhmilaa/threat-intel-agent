from .base import BaseFoundation


SSH_DEFAULT = "22"
TELNET_DEFAULT = "23"


class CowrieFoundation(BaseFoundation):

    def get_docker_ports(self, hp_options):
        """
        Get service ports for Cowrie for use in docker-compose.yml file

        :param hp_options: Honeypot options as returned by Deployment class
        :type hp_options: dict
        :return: Honeypot ports in docker-compose.yml format
        :rtype: str
        """
        ports = []
        if hp_options['ssh_enabled']:
            if "ssh_port" in hp_options.keys() and hp_options["ssh_port"]:
                ssh_port = str(hp_options['ssh_port']) + ":2222"
            else:
                ssh_port = SSH_DEFAULT + ":2222"
            ports.append(ssh_port)
        if hp_options['telnet_enabled']:
            if "telnet_port" in hp_options.keys() and hp_options["telnet_port"]:
                telnet_port = str(hp_options['telnet_port']) + ":2223"
            else:
                telnet_port = TELNET_DEFAULT + ":2223"
            ports.append(telnet_port)
        return ports

    def get_reported_port_envs(self, hp_options):
        """
        Get reported port numbers for Cowrie for use in .env file

        :param hp_options: Honeypot options as returned by Deployment class
        :type hp_options: dict
        :return: Honeypot ports in .env format
        :rtype: str
        """
        port_envs = dict()
        if hp_options['ssh_enabled']:
            if "ssh_port" in hp_options.keys() and hp_options["ssh_port"]:
                port_envs["REPORTED_SSH_PORT"] = str(hp_options['ssh_port'])
        if hp_options['telnet_enabled']:
            if "telnet_port" in hp_options.keys() and hp_options["telnet_port"]:
                port_envs["REPORTED_TELNET_PORT"] = str(hp_options['telnet_port'])
        return port_envs
