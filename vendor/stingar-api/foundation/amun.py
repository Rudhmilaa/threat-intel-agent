from .base import BaseFoundation


SMB_DEFAULT = "445"
RDP_DEFAULT = "3389"


class AmunFoundation(BaseFoundation):

    def get_docker_ports(self, hp_options):
        """
        Get service ports for Amun for use in docker-compose.yml file

        :param hp_options: Honeypot options as returned by Deployment class
        :type hp_options: dict
        :return: Honeypot ports in docker-compose.yml format
        :rtype: str
        """
        ports = []
        if hp_options['smb_enabled']:
            if "smb_port" in hp_options.keys() and hp_options["smb_port"]:
                smb_port = str(hp_options['smb_port']) + ":445"
            else:
                smb_port = SMB_DEFAULT + ":445"
            ports.append(smb_port)
        if hp_options['rdp_enabled']:
            if "rdp_port" in hp_options.keys() and hp_options["rdp_port"]:
                rdp_port = str(hp_options['rdp_port']) + ":3389"
            else:
                rdp_port = RDP_DEFAULT + ":3389"
            ports.append(rdp_port)
        return ports
