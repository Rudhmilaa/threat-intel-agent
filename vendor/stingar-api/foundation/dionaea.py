from .base import BaseFoundation

FTP_DEFAULT = "21"
HTTP_DEFAULT = "80"
HTTPS_DEFAULT = "443"
MQTT_DEFAULT = "1883"
MSSQL_DEFAULT = "1433"
MYSQL_DEFAULT = "3306"
PPTP_DEFAULT = "1723"
SIP_DEFAULT = "5060"
SMB_DEFAULT = "445"
TFTP_DEFAULT = "69"
UPNP_DEFAULT = "1900"


class DionaeaFoundation(BaseFoundation):

    def get_docker_ports(self, hp_options):
        """
        Get service ports for Dionaea for use in docker-compose.yml file

        :param hp_options: Honeypot options as returned by Deployment class
        :type hp_options: dict
        :return: Honeypot ports in docker-compose.yml format
        :rtype: str
        """
        ports = []
        if hp_options['ftp_enabled']:
            if "ftp_port" in hp_options.keys() and hp_options["ftp_port"]:
                ftp_port = str(hp_options['ftp_port']) + ":21"
            else:
                ftp_port = FTP_DEFAULT + ":21"
            ports.append(ftp_port)
        if hp_options['http_enabled']:
            if "http_port" in hp_options.keys() and hp_options["http_port"]:
                http_port = str(hp_options['http_port']) + ":80"
            else:
                http_port = HTTP_DEFAULT + ":80"
            ports.append(http_port)

        # HTTPS: TLS listener on the http module (JA3/JA4 client fingerprints).
        # Dionaea binds 443 in-container; publish as host 443. Defaults to enabled
        # when http is on so redeploys stay JA4-compatible even if https_enabled
        # is absent from older stored hp_options.
        if hp_options.get('http_enabled') and hp_options.get('https_enabled', True):
            if "https_port" in hp_options.keys() and hp_options["https_port"]:
                https_port = str(hp_options['https_port']) + ":443"
            else:
                https_port = HTTPS_DEFAULT + ":443"
            ports.append(https_port)

        if hp_options['mqtt_enabled']:
            if "mqtt_port" in hp_options.keys() and hp_options["mqtt_port"]:
                mqtt_port = str(hp_options['mqtt_port']) + ":1883"
            else:
                mqtt_port = MQTT_DEFAULT + ":1883"
            ports.append(mqtt_port)
        if hp_options['mssql_enabled']:
            if "mssql_port" in hp_options.keys() and hp_options["mssql_port"]:
                mssql_port = str(hp_options['mssql_port']) + ":1433"
            else:
                mssql_port = MSSQL_DEFAULT + ":1433"
            ports.append(mssql_port)
        if hp_options['mysql_enabled']:
            if "mysql_port" in hp_options.keys() and hp_options["mysql_port"]:
                mysql_port = str(hp_options['mysql_port']) + ":3306"
            else:
                mysql_port = MYSQL_DEFAULT + ":3306"
            ports.append(mysql_port)
        if hp_options['pptp_enabled']:
            if "pptp_port" in hp_options.keys() and hp_options["pptp_port"]:
                pptp_port = str(hp_options['pptp_port']) + ":1723"
            else:
                pptp_port = PPTP_DEFAULT + ":1723"
            ports.append(pptp_port)
        # SIP, TFTP and UPnP/SSDP are UDP services in dionaea -- the mapping
        # needs a "/udp" suffix or Docker only forwards TCP and the listener
        # stays dark (same class of bug as the conpot UDP protocols).
        if hp_options['sip_enabled']:
            if "sip_port" in hp_options.keys() and hp_options["sip_port"]:
                sip_port = str(hp_options['sip_port']) + ":5060/udp"
            else:
                sip_port = SIP_DEFAULT + ":5060/udp"
            ports.append(sip_port)
        if hp_options['smb_enabled']:
            if "smb_port" in hp_options.keys() and hp_options["smb_port"]:
                smb_port = str(hp_options['smb_port']) + ":445"
            else:
                smb_port = SMB_DEFAULT + ":445"
            ports.append(smb_port)
        if hp_options['tftp_enabled']:
            if "tftp_port" in hp_options.keys() and hp_options["tftp_port"]:
                tftp_port = str(hp_options['tftp_port']) + ":69/udp"
            else:
                tftp_port = TFTP_DEFAULT + ":69/udp"
            ports.append(tftp_port)
        if hp_options['upnp_enabled']:
            if "upnp_port" in hp_options.keys() and hp_options["upnp_port"]:
                upnp_port = str(hp_options['upnp_port']) + ":1900/udp"
            else:
                upnp_port = UPNP_DEFAULT + ":1900/udp"
            ports.append(upnp_port)
        return ports
