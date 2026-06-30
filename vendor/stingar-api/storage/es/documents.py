from elasticsearch_dsl import analyzer, Date, Document, Text, Keyword, Integer


token_analyzer = analyzer('token_analyzer',
                          tokenizer="standard",
                          filter=["standard"],
                          )


whitespace_analyzer = analyzer('whitespace_analyzer',
                               tokenizer='whitespace',
                               filter=["standard"],
                               )


class Session(Document):
    """
    Honeypot session record definition in Elasticsearch.
    """
    app = Keyword()
    start_time = Date()
    end_time = Date()
    sensor = Document()
    src_ip = Keyword()
    src_port = Integer()
    dst_ip = Keyword()
    dst_port = Integer()
    protocol = Keyword()
    hp_data = Document()
    fluentd_tag = Keyword()

    class Index:
        name = "stingar-*"


class Sensor(Document):
    """
    Sensor record definition in Elasticsearch.
    """
    uuid = Keyword()
    honeypot = Keyword()
    hostname = Keyword()
    ip = Keyword()
    asn = Keyword()
    created = Date()
    updated = Date()
    tags = Document()

    class Index:
        name = "sensors"


class DeploymentLog(Document):
    """
    Ansible deployment log record definition in Elasticsearch.
    """
    ts = Date()
    deployment_id = Keyword()
    event = Text()
    host = Keyword()
    msg = Text()
    error_msg = Text()
    fluentd_tag = Keyword()

    class Index:
        name = "ansible-*"
