import os
import uuid
import datetime
import hashlib
import secrets
import base64
from sqlalchemy import create_engine, exc
from sqlalchemy.orm import sessionmaker
from storage.db.models import Base, Host, Config, Deployment, AuthKey, Tag, User, KibanaObject, RemoteHoneypot, LocalInstallation


class StingarDB:
    """
    STINGAR API connector for SQL databases.
    """

    def __init__(self, db_path=None):
        """
        :param db_path: Database connection path
        :type db_path: str
        """
        if db_path is None:
            db_path = os.environ.get(
                'STINGAR_DATABASE_URL', 'sqlite:////srv/db/stingar.db'
            )
        if db_path.startswith('sqlite'):
            # SQLAlchemy 2.x: QueuePool sizing is invalid for SQLite (incl. :memory: tests).
            engine = create_engine(
                db_path, connect_args={'check_same_thread': False}
            )
        else:
            engine = create_engine(
                db_path,
                pool_size=10,
                max_overflow=20,
                pool_timeout=60,
                pool_recycle=1800,
            )
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(engine) 
        #self.Session.configure(bind=engine)
        
    def get_users(self, params):
        """
        Get list of Users from SQL database.

        :return: User record
        :rtype: dict
        """
        return self._get_records(model=User, filter_params=params)

    def get_user(self, ident):
        return self._get_record(model=User, ident=ident)

    def get_user_by_username(self, username):
        """
        Get User from SQL database by username.

        :param username: username of user to retrieve
        :type username: str
        :return: User record
        :rtype: dict
        """
        """ ORIG before WITH BLOCK update to force close session once complete:
        session = self.Session(expire_on_commit=False)
        user = session.query(User).filter(User.username == username).first()
        session.expunge_all()
        if user:
            return user.to_dict()
        else:
            return {}
        """
        with self.Session(expire_on_commit=False) as session:
            user = session.query(User).filter(User.username == username).first()
            session.expunge_all()  # Still necessary if you want objects to be detached
            if user:
                return user.to_dict()
            else:
                return {}


    def get_user_password(self, username, password):
        """
        Get User from SQL database by username / password combination.

        :param username: Username of user to retrieve
        :type username: str
        :param password: Password of user to retrieve
        :type password: str
        :return: User record
        :rtype: dict
        """
        session = self.Session(expire_on_commit=False)
        pass_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        user = session.query(User).filter(User.username == username,
                                          User.password == pass_hash).first()
        session.expunge_all()
        session.close()
        if user:
            return user.to_dict()
        else:
            return {}

    def check_token(self, token):
        """
        Validate API token in SQL database.

        :param token: API token to validate.
        :type token: str
        :return: User record
        :rtype: dict
        """
        """ WITH BLOCK REPLACEMENT
        session = self.Session()
        user = session.query(User).filter(User.token == token).first()
        session.close()
        if user:
            return user.to_dict()
        else:
            return {}
        """
        with self.Session() as session:
            user = session.query(User).filter(User.token == token).first()
            if user:
                return user.to_dict()
            else:
                return {}


    def create_user(self, username, password="", email=None, token=None):
        """
        Create User record in SQL database.

        :param username: Username of user to create
        :type username: str
        :param password: Password of user to create
        :type password: str
        :param email: Email address of user to create
        :type email: str
        :param token: API token of user to create
        :type token: str
        :return: User record
        :rtype: dict
        """
        session = self.Session(expire_on_commit=False)
        if not token:
            token = secrets.token_urlsafe(16)
        created = datetime.datetime.utcnow()
        user = session.query(User).filter(User.username == username).first()
        if user:
            session.close()
            return {}
        else:
            pw_hash = ""
            if password:
                pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            user = User(username=username, password=pw_hash, token=token, email=email,
                        created=created, updated=created)
            session.add(user)
            session.commit()
            session.expunge_all()
            session.close()
            if user:
                return user.to_dict()
            else:
                return {}

    def update_user(self, ident, email=None, password=None, update_token=False):
        """
        Update User record in SQL database.

        :param ident: Id of user to update
        :type ident: str
        :param email: Updated email address for user
        :type email: str
        :param password: Updated password for user
        :type password: str
        :param update_token: True to update API token, False to keep old token value
        :type update_token: bool
        :return: User record
        :rtype: dict
        """
        session = self.Session()
        user_dict = {}
        user = session.query(User).get(int(ident))
        if user:
            user.updated = datetime.datetime.utcnow()
            if update_token:
                user.token = secrets.token_urlsafe(16)
            if email:
                user.email = email
            if password:
                user.password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            session.commit()
            user_dict = user.to_dict()
        session.close()
        return user_dict

    def delete_user(self, ident):
        """
        Delete User record in SQL database.

        :param ident: Id of user to delete
        :type ident: str
        :return: User record
        :rtype: dict
        """
        return self._delete_record(ident=ident, model=User)

    def get_configs(self, params):
        """
        Get Config records in SQL database.

        :return: List of Config records
        :rtype: list
        """
        return self._get_records(model=Config, filter_params=params)

    def get_config(self, ident):
        """
        Get single Config record in SQL database.

        :param ident: Id of Config record
        :type ident: str
        :return: Config record
        :rtype: dict
        """
        return self._get_record(model=Config, ident=ident)

    def create_config(self, **kwargs):
        """
        Create new Config record in SQL database.

        :return: Config record
        :rtype: dict
        """
        created = datetime.datetime.utcnow()
        return self._create_record(model=Config, created=created, **kwargs)

    def update_config(self, ident, **kwargs):
        """
        Update existing Config record in SQL database.

        :param ident: Id of Config record
        :type ident: str
        :return: Config record
        :rtype: dict
        """
        updated = datetime.datetime.utcnow()
        return self._update_record(model=Config, ident=ident, updated=updated, **kwargs)

    def delete_config(self, ident):
        """
        Delete Config record in SQL database.

        :param ident: Id of Config record
        :type ident: str
        :return: Config record
        :rtype: dict
        """
        return self._delete_record(model=Config, ident=ident)

    def get_hosts(self, params):
        """
        Get Host records in SQL database.

        :return: List of Host records
        :rtype: list
        """
        return self._get_records(model=Host, filter_params=params)

    def get_host(self, ident):
        """
        Get single Host record in SQL database.
        """
        return self._get_record(model=Host, ident=ident)

    def create_host(self, **kwargs):
        """
        Create new Host record in SQL database.

        :return: Host record
        :rtype: dict
        """
        created = datetime.datetime.utcnow()
        uid = uuid.uuid4().hex
        return self._create_record(model=Host, created=created, uuid=uid, **kwargs)

    def update_host(self, ident, **kwargs):
        """
        Update existing Host record in SQL database.

        :param ident: Id of Host record
        :type ident: str
        :return: Host record
        :rtype: dict
        """
        updated = datetime.datetime.utcnow()
        return self._update_record(model=Host, ident=ident, updated=updated, **kwargs)

    def delete_host(self, ident):
        """
        Delete Host record in SQL database.

        :param ident: Id of Host record
        :type ident: str
        :return: Host record
        :rtype: dict
        """
        return self._delete_record(model=Host, ident=ident)

    def get_deployments(self, params):
        """
        Get Deployment records in SQL database.
        """
        if 'status' in params.keys():
            del params['status']
        return self._get_records(model=Deployment, filter_params=params)

    def get_deployment(self, ident):
        """
        Get single Deployment record in SQL database.
        """
        return self._get_record(model=Deployment, ident=ident)

    def create_deployment(self, **kwargs):
        """
        Create Deployment record in SQL database.
        """
        created = datetime.datetime.utcnow()
        if 'status' in kwargs.keys():
            status = kwargs['status']
            del kwargs['status']
        else:
            status = 0

        uid = uuid.uuid4().hex
        return self._create_record(model=Deployment, created=created, status=status, uuid=uid, **kwargs)

    def create_deployment_no_save(self, **kwargs):
        """
        Create Deployment record without saving to SQL database.
        """
        created = datetime.datetime.utcnow()
        status = 0
        uid = uuid.uuid4().hex
        record = Deployment(created=created, status=status, uuid=uid, **kwargs)
        record_dict = record.to_dict()
        return record_dict

    def update_deployment(self, ident, **kwargs):
        """
        Update existing Deployment record in SQL database.
        """
        return self._update_record(model=Deployment, ident=ident, **kwargs)

    def delete_deployment(self, ident):
        """
        Delete Deployment record in SQL database.
        """
        return self._delete_record(ident=ident, model=Deployment)

    def next_deployment(self):
        """
        Get next undeployed Deployment record in SQL database.
        """
        session = self.Session()
        deployment = session.query(Deployment).filter(Deployment.status == 0).first()
        if not deployment:
            session.close()
            return {}
        deployment.status = 1
        session.commit()
        deployment_dict = deployment.to_dict_with_authkey()
        session.close()
        return deployment_dict

    def add_tag_to_deployment(self, ident, tag_id):
        """
        Add Tag record to Deployment record in SQL database.
        """
        deployment_dict = {}
        added = False
        session = self.Session()
        tag = session.query(Tag).get(int(tag_id))
        deployment = session.query(Deployment).get(int(ident))
        if deployment and tag:
            deployment.tags.append(tag)
            added = True
        if deployment:
            deployment_dict = deployment.to_dict()
        session.add(deployment)
        session.commit()
        session.close()
        return deployment_dict, added

    def get_authkeys(self, params, include_private_key=False):
        """
        Get Authkey records in SQL database.
        """
        if include_private_key:
            return self._get_records(model=AuthKey, filter_params=params)
        records = []
        for authkey in self._get_records(model=AuthKey, filter_params=params):
            authkey.pop("private_key")
            records.append(authkey)
        return records

    def get_authkey(self, ident, include_private_key=False):
        """
        Get single Authkey record in SQL database.
        """
        record = self._get_record(model=AuthKey, ident=ident)
        if not include_private_key:
            record.pop("private_key")
        return record

    def create_authkey(self, include_private_key=False, **kwargs):
        """
        Create new Authkey record in SQL database.
        """
        created = datetime.datetime.utcnow()
        record = self._create_record(model=AuthKey, created=created, **kwargs)
        if not include_private_key:
            record.pop("private_key")
        return record

    def delete_authkey(self, ident):
        """
        Delete Authkey record in SQL database.
        """
        record = self._delete_record(model=AuthKey, ident=ident)
        record.pop("private_key")
        return record

    def get_tags(self, params):
        """
        Get Tag records in SQL database.
        """
        return self._get_records(model=Tag, filter_params=params)

    def get_tag(self, ident):
        """
        Get single Tag record in SQL database.
        """
        return self._get_record(model=Tag, ident=ident)

    def create_tag(self, **kwargs):
        """
        Create new Tag record in SQL database.
        """
        return self._create_record(model=Tag, **kwargs)

    def delete_tag(self, ident):
        """
        Delete Tag record in SQL database.
        """
        return self._delete_record(model=Tag, ident=ident)

    def get_kibana_objects(self, params):
        """
        Get saved KibanaObject records in SQL database.
        """
        return self._get_records(model=KibanaObject, filter_params=params)

    def get_kibana_object(self, ident):
        """
        Get single saved KibanaObject record in SQL database.
        """
        return self._get_record(model=KibanaObject, ident=ident)

    def create_kibana_object(self, **kwargs):
        """
        Create new saved KibanaObject record in SQL database.
        """
        objects = kwargs.pop('objects')
        kwargs['objects'] = base64.b64encode(objects.encode("utf-8"))
        active = kwargs.get("active", 0)
        record = self._create_record(model=KibanaObject, **kwargs)
        if active:
            self._update_all_records(model=KibanaObject, active=0)
            self._update_record(model=KibanaObject, ident=record['id'], active=1)
        return record

    def set_kibana_objects_active(self, ident):
        """
        Set saved KibanaObject in SQL database to active.
        """
        record = self._get_record(model=KibanaObject, ident=ident)
        if record:
            self._update_all_records(model=KibanaObject, active=0)
            self._update_record(model=KibanaObject, ident=record['id'], active=1)
        return record

    def delete_kibana_object(self, ident):
        """
        Delete saved KibanaObject in SQL database.
        """
        return self._delete_record(model=KibanaObject, ident=ident)

    def _get_records(self, model, filter_params):
        """
        Generic get records in SQL database of given type.
        """
        record_list = []
        session = self.Session()
        query = session.query(model)
        try:
            for k, v in filter_params.items():
                query = query.filter_by(**{k: v})
        except exc.InvalidRequestError:
            return []
        for record in query.all():
            record_list.append(record.to_dict())
        session.close()
        return record_list

    def _get_record(self, model, ident):
        """
        Generic get single record in SQL database of given type.
        """
        session = self.Session()
        record = session.query(model).get(int(ident))
        record_dict = {}
        if record:
            record_dict = record.to_dict()
        session.close()
        return record_dict

    def _create_record(self, model, **kwargs):
        """
        Generic create new record in SQL database of given type.
        """
        session = self.Session()
        record = model(**kwargs)
        session.add(record)
        session.commit()
        record_dict = record.to_dict()
        session.close()
        return record_dict

    def _update_record(self, model, ident, **kwargs):
        """
        Generic update existing record in SQL database of given type.
        """
        session = self.Session()
        record_dict = {}
        record = session.query(model).get(int(ident))
        if record:
            for k, v in kwargs.items():
                if v is not None:
                    record[k] = v
            session.commit()
            record_dict = record.to_dict()
        session.close()
        return record_dict

    def _update_all_records(self, model, **kwargs):
        """
        Generic update all records in SQL database of given type.
        """
        session = self.Session()
        session.query(model).update(kwargs)
        session.commit()
        session.close()

    def _delete_record(self, model, ident):
        """
        Generic delete record in SQL database of given type.
        """
        session = self.Session()
        record_dict = {}
        record = session.query(model).filter(model.id == ident).first()
        if record:
            session.delete(record)
            session.commit()
            record_dict = record.to_dict()
        session.close()
        return record_dict

    # Store-related methods for remote honeypot integration
    def get_remote_honeypots(self, params):
        """
        Get list of remote honeypots from database.
        
        :param params: Filter parameters
        :type params: dict
        :return: List of remote honeypot records
        :rtype: list
        """
        return self._get_records(model=RemoteHoneypot, filter_params=params)

    def get_remote_honeypot(self, ident):
        """
        Get specific remote honeypot by ID.
        
        :param ident: Remote honeypot ID
        :type ident: int
        :return: Remote honeypot record
        :rtype: dict
        """
        return self._get_record(model=RemoteHoneypot, ident=ident)

    def create_remote_honeypot(self, **kwargs):
        """
        Create new remote honeypot record.
        
        :param kwargs: Remote honeypot data
        :return: Created remote honeypot record
        :rtype: dict
        """
        # Set default timestamps
        if 'local_created' not in kwargs:
            kwargs['local_created'] = datetime.datetime.utcnow()
        if 'local_updated' not in kwargs:
            kwargs['local_updated'] = datetime.datetime.utcnow()
        
        return self._create_record(model=RemoteHoneypot, **kwargs)

    def update_remote_honeypot(self, ident, **kwargs):
        """
        Update remote honeypot record.
        
        :param ident: Remote honeypot ID
        :type ident: int
        :param kwargs: Update data
        :return: Updated remote honeypot record
        :rtype: dict
        """
        kwargs['local_updated'] = datetime.datetime.utcnow()
        return self._update_record(model=RemoteHoneypot, ident=ident, **kwargs)

    def delete_remote_honeypot(self, ident):
        """
        Delete remote honeypot record.
        
        :param ident: Remote honeypot ID
        :type ident: int
        :return: Deleted remote honeypot record
        :rtype: dict
        """
        return self._delete_record(model=RemoteHoneypot, ident=ident)

    def get_local_installations(self, params):
        """
        Get list of local installations.
        
        :param params: Filter parameters
        :type params: dict
        :return: List of local installation records
        :rtype: list
        """
        return self._get_records(model=LocalInstallation, filter_params=params)

    def get_local_installation(self, ident):
        """
        Get specific local installation by ID.
        
        :param ident: Local installation ID
        :type ident: int
        :return: Local installation record
        :rtype: dict
        """
        return self._get_record(model=LocalInstallation, ident=ident)

    def create_local_installation(self, **kwargs):
        """
        Create new local installation record.
        
        :param kwargs: Local installation data
        :return: Created local installation record
        :rtype: dict
        """
        if 'installation_date' not in kwargs:
            kwargs['installation_date'] = datetime.datetime.utcnow()
        
        return self._create_record(model=LocalInstallation, **kwargs)

    def update_local_installation(self, ident, **kwargs):
        """
        Update local installation record.
        
        :param ident: Local installation ID
        :type ident: int
        :param kwargs: Update data
        :return: Updated local installation record
        :rtype: dict
        """
        return self._update_record(model=LocalInstallation, ident=ident, **kwargs)

    def delete_local_installation(self, ident):
        """
        Delete local installation record.
        
        :param ident: Local installation ID
        :type ident: int
        :return: Deletion result
        :rtype: dict
        """
        return self._delete_record(model=LocalInstallation, ident=ident)

    def install_remote_honeypot(self, remote_id, installation_data):
        """
        Install remote honeypot locally.
        
        :param remote_id: Remote honeypot ID
        :type remote_id: int
        :param installation_data: Installation configuration
        :type installation_data: dict
        :return: Installation result
        :rtype: dict
        """
        # Get remote honeypot details
        remote_hp = self.get_remote_honeypot(remote_id)
        if not remote_hp:
            raise ValueError(f"Remote honeypot {remote_id} not found")
        
        # Check if already installed
        existing_installation = self.get_local_installations({
            'remote_honeypot_id': remote_id
        })
        if existing_installation:
            raise ValueError(f"Remote honeypot {remote_id} already installed")
        
        # Create local config from remote metadata
        config_data = {
            'name': f"{remote_hp['name']} (from store)",
            'hp_type': remote_hp['hp_type'],
            'hp_options': remote_hp['default_configuration']
        }
        
        local_config = self.create_config(**config_data)
        
        # Create installation record
        installation_data = {
            'remote_honeypot_id': remote_id,
            'local_config_id': local_config['id'],
            'version_installed': remote_hp['version'],
            'status': 'installed'
        }
        
        installation = self.create_local_installation(**installation_data)
        
        return {
            'installation': installation,
            'local_config': local_config,
            'remote_honeypot': remote_hp
        }
