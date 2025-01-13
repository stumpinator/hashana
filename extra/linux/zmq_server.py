from os import getenv
from hashana.mq import HashanaZMQServer

hashana_home = getenv('HASHANA_HOME', '/hashana')
hashana_db = getenv('HASHANA_DB', f"{hashana_home}/hashana.db")
hashana_port = getenv('HASHANA_PORT', '5557')
hashana_ip = getenv('HASHANA_IP', '*')

server_endpoint = f"tcp://{hashana_ip}:{hashana_port}"

server = HashanaZMQServer(server_endpoint, hashana_db)
server.serve()