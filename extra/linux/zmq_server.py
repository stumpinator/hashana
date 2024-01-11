import os
from hashana.adapted import *
from hashana.mq import *

hashana_home = os.getenv('HASHANA_HOME', '/hashana')
hashana_db = os.getenv('HASHANA_DB', f"{hashana_home}/hashana.db")
hashana_port = os.getenv('HASHANA_PORT', '5557')

server_endpoint = f"tcp://*:{hashana_port}"

server = HashanaZMQServer(server_endpoint, hashana_db)
server.serve()