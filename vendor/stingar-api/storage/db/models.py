from sqlalchemy import ForeignKey, Column, Integer, String, DateTime, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship


Base = declarative_base()


class User(Base):
    """
    STINGAR API / UI user records.
    """

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String)
    email = Column(String)
    password = Column(String)
    token = Column(String)
    created = Column(DateTime)
    updated = Column(DateTime)

    def __repr__(self):
        return "<User(id='%s', username='%s', email='%s', token='%s', created='%s', updated='%s')>" % (
            self.id, self.username, self.email, self.token, self.created, self.updated
        )

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def to_dict(self):
        # Don't provide the actual password, but do indicate whether or not it exists
        has_password = False
        if self.password:
            has_password = True
        return {"id": self.id, "username": self.username, "email": self.email,
                "has_password": has_password, "token": self.token, "created": self.created, "updated": self.updated}


class DeploymentTag(Base):
    """
    Many-to-many relationships between Deployment records and Tag records.
    """
    __tablename__ = 'deployment_tags'

    deployment_id = Column(Integer, ForeignKey('deployments.id'), primary_key=True)
    tag_id = Column(Integer, ForeignKey('tags.id'), primary_key=True)


class Deployment(Base):
    """
    Deployment records for honeypot configuration options.
    """
    __tablename__ = 'deployments'

    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(String)
    status = Column(Integer)
    address = Column(String)
    ssh_port = Column(Integer)
    username = Column(String)
    authkey_id = Column(Integer, ForeignKey('authkey.id'))
    hp_type = Column(String)
    hp_options = Column(String)
    created = Column(DateTime)
    updated = Column(DateTime)

    authkey = relationship('AuthKey')
    tags = relationship('Tag', secondary='deployment_tags', viewonly=True)

    def __repr__(self):
        return ("<Deployment(id='%s', uuid='%s', status='%s', address='%s', ssh_port='%s', username='%s',"
                " authkey_id='%s', hp_type='%s', hp_options='%s', created='%s', updated='%s')>") % (
            self.id, self.uuid, self.status, self.address, self.ssh_port, self.username,
            self.authkey_id, self.hp_type, self.hp_options,self.created, self.updated)

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def to_dict(self):
        tag_dicts = []
        for tag in self.tags:
            tag_dicts.append(tag.to_dict())
        return {"id": self.id, "uuid": self.uuid, "status": self.status,
                "address": self.address, "ssh_port": self.ssh_port, "username": self.username,
                "authkey_id": self.authkey_id, "hp_type": self.hp_type, "hp_options": self.hp_options,
                "created": self.created, "updated": self.updated, "tags": tag_dicts}

    def to_dict_with_authkey(self):
        tag_dicts = []
        for tag in self.tags:
            tag_dicts.append(tag.to_dict())
        authkey_dict = {}
        if self.authkey:
            authkey_dict = self.authkey.to_dict()
        return {"id": self.id, "uuid": self.uuid, "status": self.status,
                "address": self.address, "ssh_port": self.ssh_port, "username": self.username,
                "authkey_id": self.authkey_id, "authkey": authkey_dict,
                "hp_type": self.hp_type, "hp_options": self.hp_options,
                "created": self.created, "updated": self.updated, "tags": tag_dicts}


class Tag(Base):
    """
    Tag records for tagging honeypot deployments.
    """
    __tablename__ = 'tags'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)
    value = Column(String)
    description = Column(String)

    deployments = relationship(Deployment, secondary='deployment_tags')

    def __repr__(self):
        return "<Tag(id='%s', name='%s', value='%s', description='%s')>" % (self.id, self.name,
                                                                            self.value, self.description)

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def to_dict(self):
        return {"id": self.id, "name": self.name, "value": self.value, "description": self.description}


class Config(Base):
    """
    Configuration templates for honeypot deployments.
    """
    __tablename__ = 'config_templates'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)
    hp_type = Column(String)
    hp_options = Column(String)
    created = Column(DateTime)
    updated = Column(DateTime)

    def __repr__(self):
        return "<Config(id='%s', name='%s', hp_type='%s', hp_options='%s', created='%s', updated='%s')>" % (
            self.id, self.name, self.hp_type, self.hp_options, self.created, self.updated
        )

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def to_dict(self):
        return {"id": self.id, "name": self.name, "hp_type": self.hp_type, "hp_options": self.hp_options,
                "created": self.created, "updated": self.updated}


class Host(Base):
    """
    Defined honeypot hosts for deploying honeypots to.
    """
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    authkey_id = Column(Integer, ForeignKey('authkey.id'))
    uuid = Column(String)
    address = Column(String)
    ssh_port = Column(Integer)
    username = Column(String)
    created = Column(DateTime)
    updated = Column(DateTime)

    authkey = relationship("AuthKey")

    def __repr__(self):
        return ("<Host(id='%s', authkey_id='%s', uuid='%s', address='%s', ssh_port='%s',"
                " username='%s', created='%s', updated='%s')>") % (
            self.id, self.authkey_id, self.uuid, self.address, self.ssh_port, self.username, self.created, self.updated
        )

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def to_dict(self):
        return {"id": self.id, "authkey_id": self.authkey_id, "uuid": self.uuid, "address": self.address,
                "ssh_port": self.ssh_port, "username": self.username, "created": self.created, "updated": self.updated}


class AuthKey(Base):
    """
    SSH authentication keys for authenticating and deploying to defined honeypot Hosts.
    """
    __tablename__ = 'authkey'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)
    public_key = Column(String)
    private_key = Column(String)
    created = Column(DateTime)

    def __repr__(self):
        return "<AuthKey(id='%s', name='%s', public_key='%s')>" % (
            self.id, self.name, self.public_key
        )

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def to_dict(self):
        return {"id": self.id, "name": self.name, "public_key": self.public_key, "private_key": self.private_key}


class KibanaObject(Base):
    """
    Saved Kibana objects for presenting dashboards and visualizations.
    'objects' column should be generated by the output of the Kibana API.
    """
    __tablename__ = "kibana_objects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    description = Column(String)
    active = Column(Integer)
    created = Column(DateTime)
    objects = Column(Text)

    def __repr__(self):
        return "<KibanaObject(id='%s', description='%s', active='%s', created='%s')>" % (
            self.id, self.description, self.active, self.created
        )

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def to_dict(self):
        return {"id": self.id, "description": self.description, "active": self.active,
                "created": self.created, "objects": self.objects}


class RemoteHoneypot(Base):
    """
    Remote honeypot store metadata from HP_AppStore.
    """
    __tablename__ = 'remote_honeypots'

    id = Column(Integer, primary_key=True, autoincrement=True)
    remote_id = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    display_name = Column(String)
    description = Column(Text)
    version = Column(String)
    author = Column(String)
    maintainer = Column(String)
    license = Column(String)
    category = Column(String)
    tags = Column(Text)  # JSON array
    hp_type = Column(String)
    supported_protocols = Column(Text)  # JSON array
    default_ports = Column(Text)  # JSON array
    min_requirements = Column(Text)  # JSON object
    configuration_schema = Column(Text)  # JSON schema
    default_configuration = Column(Text)  # JSON
    docker_image = Column(String)
    docker_tag = Column(String)
    documentation_url = Column(String)
    source_url = Column(String)
    rating = Column(Float, default=0.0)
    download_count = Column(Integer, default=0)
    last_updated = Column(DateTime)
    created = Column(DateTime)
    status = Column(String, default='active')
    local_created = Column(DateTime)
    local_updated = Column(DateTime)

    # Relationships
    installations = relationship('LocalInstallation', back_populates='remote_honeypot')

    def __repr__(self):
        return f"<RemoteHoneypot(id='{self.id}', name='{self.name}', hp_type='{self.hp_type}')>"

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "remote_id": self.remote_id,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "maintainer": self.maintainer,
            "license": self.license,
            "category": self.category,
            "tags": json.loads(self.tags) if self.tags else [],
            "hp_type": self.hp_type,
            "supported_protocols": json.loads(self.supported_protocols) if self.supported_protocols else [],
            "default_ports": json.loads(self.default_ports) if self.default_ports else [],
            "min_requirements": json.loads(self.min_requirements) if self.min_requirements else {},
            "configuration_schema": json.loads(self.configuration_schema) if self.configuration_schema else {},
            "default_configuration": json.loads(self.default_configuration) if self.default_configuration else {},
            "docker_image": self.docker_image,
            "docker_tag": self.docker_tag,
            "documentation_url": self.documentation_url,
            "source_url": self.source_url,
            "rating": self.rating,
            "download_count": self.download_count,
            "last_updated": self.last_updated,
            "created": self.created,
            "status": self.status,
            "local_created": self.local_created,
            "local_updated": self.local_updated
        }


class LocalInstallation(Base):
    """
    Local installations of remote honeypots.
    """
    __tablename__ = 'local_installations'

    id = Column(Integer, primary_key=True, autoincrement=True)
    remote_honeypot_id = Column(Integer, ForeignKey('remote_honeypots.id'))
    local_config_id = Column(Integer, ForeignKey('config_templates.id'))
    installation_date = Column(DateTime)
    version_installed = Column(String)
    status = Column(String, default='installing')
    deployment_status = Column(Integer, default=0)

    # Relationships
    remote_honeypot = relationship('RemoteHoneypot', back_populates='installations')
    local_config = relationship('Config')

    def __repr__(self):
        return f"<LocalInstallation(id='{self.id}', remote_hp_id='{self.remote_honeypot_id}', status='{self.status}')>"

    def to_dict(self):
        return {
            "id": self.id,
            "remote_honeypot_id": self.remote_honeypot_id,
            "local_config_id": self.local_config_id,
            "installation_date": self.installation_date,
            "version_installed": self.version_installed,
            "status": self.status,
            "deployment_status": self.deployment_status,
            "remote_honeypot": self.remote_honeypot.to_dict() if self.remote_honeypot else None,
            "local_config": self.local_config.to_dict() if self.local_config else None
        }