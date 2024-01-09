import json
import threading

from hashana.db import HashanaReplier
from hashana.adapted import *

try:
    import zmq
except ImportError:
    _has_zmq = False
else:
    _has_zmq = True


class HashanaZMQServer:
    _msg_size: int
    _rcv_timeo: int
    _listen_url: str
    _db_path: str
    
    def __init__(self, listen_url: str, 
                 db_path: str, 
                 recv_timeout: int = 1000, 
                 message_size: int = 1024):
        if not _has_zmq:
            raise ImportError("zmq package is required for the zeromq features")
        self._msg_size = message_size
        self._rcv_timeo = recv_timeout
        self._listen_url = listen_url
        self._db_path = db_path
    
    def serve(self):
        context = zmq.Context()
        socket = context.socket(zmq.REP)
        socket.setsockopt(zmq.RCVTIMEO, self._rcv_timeo)
        socket.setsockopt(zmq.MAXMSGSIZE, self._msg_size)
        socket.bind(self._listen_url)
        
        replier = HashanaReplier(self._db_path)
        replier.connect()
        while True:
            try:
                msg = socket.recv()
            except zmq.error.Again:
                continue
            except:
                break
            
            try:
                js = json.loads(msg)
            except json.JSONDecodeError:
                socket.send_json(dict(error="ERROR_JSON"))
                continue
            
            if not isinstance(js, list):
                js = [js]
            
            try:
                reply = replier.process_requests(js)
            except:
                socket.send_json(dict(error="ERROR_DBREPLIER"))
            else:
                socket.send_json(reply)
        
        replier.close()
        socket.close()
        context.term()

    @staticmethod
    def serve_static(listen_url: str, 
                    db_path: str,
                    stop_event: threading.Event = None,
                    recv_timeout: int = 1000, 
                    message_size: int = 1024):
        context = zmq.Context()
        socket = context.socket(zmq.REP)
        socket.setsockopt(zmq.RCVTIMEO, recv_timeout)
        socket.setsockopt(zmq.MAXMSGSIZE, message_size)
        socket.bind(listen_url)
        
        stop = stop_event or threading.Event()
        replier = HashanaReplier(db_path)
        replier.connect()
        while not stop.is_set():
            try:
                msg = socket.recv()
            except zmq.error.Again:
                continue
            except Exception:
                break
            
            try:
                js = json.loads(msg)
            except json.JSONDecodeError:
                socket.send_json(dict(error="ERROR_JSON"))
                continue
            
            if not isinstance(js, list):
                js = [js]
            
            try:
                reply = replier.process_requests(js)
            except:
                socket.send_json(dict(error="ERROR_DBREPLIER"))
            else:
                socket.send_json(reply)
        
        replier.close()
        socket.close()
        context.term()

class HashanaZMQClient:
    _server: str
    _rcv_timeo: int
    _context: zmq.Context
    _client: zmq.Socket
    _tracking: int
    
    def __init__(self, server: str, recv_timeout: int = 10000):
        if not _has_zmq:
            raise ImportError("zmq package is required for the zeromq features")
        self._server = server
        self._rcv_timeo = recv_timeout
        self._tracking = 0
        self._context = zmq.Context()
        self._client = None
    
    def __del__(self):
        self._context.term()
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def connect(self):
        self._tracking += 1
        if self._client is None:
            self._client = self._context.socket(zmq.REQ)
            self._client.connect(self._server)
    
    def close(self):
        if self._client is not None:
            self._tracking = max(0, self._tracking - 1)
            if self._tracking == 0:
                self._client.close()
                self._client = None
    
    def request(self, message) -> (list | dict):
        self._client.send(message)
        reply = None
        if (self._client.poll(self._rcv_timeo) & zmq.POLLIN) != 0:
            reply = self._client.recv_json()
        return reply
