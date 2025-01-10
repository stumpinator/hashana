import json
#from threading import Event, Thread as Process
from multiprocessing import Process
from multiprocessing.synchronize import Event
from abc import abstractmethod, ABCMeta

from hashana.db import HashanaReplier

try:
    import zmq
except ImportError:
    _has_zmq = False
else:
    _has_zmq = True


class ZMQService(metaclass=ABCMeta):
    """Abstract class for creating zeromq services"""
    _svc_thread: Process
    _stop_evt: Event
    
    def __init__(self):
        if not _has_zmq:
            raise ImportError("zmq package is required for the zeromq features")
        self._svc_thread = None
        self._stop_evt = Event()
        
    @abstractmethod
    def thread_args(self) -> tuple:
        """positional arguments for the service method"""
        raise NotImplementedError
    
    @abstractmethod
    def thread_kwargs(self) -> dict:
        """keyword arguments for the service method"""
        raise NotImplementedError
    
    @staticmethod
    @abstractmethod
    def service(): 
        """static method to run zmq service. used as target for multiprocessing/threading.
        """
        raise NotImplementedError
    
    def start(self) -> bool:
        """star the service in another process

        Returns:
            bool: True if process is alive
        """
        if self._svc_thread is None:    
            self._stop_evt.clear()
            args = self.thread_args()
            kwargs = self.thread_kwargs()
            self._svc_thread = Process(target=type(self).service, args=args, kwargs=kwargs)
            self._svc_thread.daemon = True
            self._svc_thread.start()
        return self._svc_thread.is_alive()
    
    def stop(self):
        """stop the service running in another process
        """
        self._stop_evt.set()
        if self._svc_thread is not None:
            self._svc_thread.join()
            self._svc_thread = None
    
    def running(self) -> bool:
        """
        Returns:
            bool: True if process is running. Otherwise False
        """
        if self._svc_thread is not None:
            return self._svc_thread.is_alive()
        return False

class HashanaZMQBroker(ZMQService):
    """ZMQ Broker for connecting multiple worker processes"""
    _msg_size: int
    _poll_timeo: int
    _router_url: str
    _dealer_url: str
    
    def __init__(self, router_url: str, dealer_url: str, poll_timeout: int = 1000, message_size: int = 1024):
        super().__init__()
        self._router_url = router_url
        self._dealer_url = dealer_url
        self._msg_size = message_size
        self._poll_timeo = poll_timeout
        
    def serve(self, zmq_context: zmq.Context = None):
        type(self).service(self._router_url,
                            self._dealer_url, 
                            poll_timeout=self._poll_timeo, 
                            message_size=self._msg_size, 
                            zmq_context=zmq_context)
    
    @staticmethod
    def service(router_url: str, 
                dealer_url: str, 
                poll_timeout: int = 2000, 
                message_size: int = 1024, 
                zmq_context: zmq.Context = None,
                stop_event: Event = None):
        context = zmq_context or zmq.Context()
        stop = stop_event or Event()
        frontend = context.socket(zmq.ROUTER)
        backend = context.socket(zmq.DEALER)
        frontend.setsockopt(zmq.MAXMSGSIZE, message_size)
        frontend.setsockopt(zmq.LINGER, poll_timeout)
        backend.setsockopt(zmq.LINGER, poll_timeout)
        frontend.bind(router_url)
        backend.bind(dealer_url)
        
        poller = zmq.Poller()
        poller.register(frontend, zmq.POLLIN)
        poller.register(backend, zmq.POLLIN)
        
        while not stop.is_set():
            try:
                poll_results = poller.poll(poll_timeout)
            except zmq.error.Again:
                continue
            except KeyboardInterrupt:
                stop.set()
                break
            except Exception:
                stop.set()
                raise
            else:
                socks = dict(poll_results)
                
            if socks.get(frontend) == zmq.POLLIN:
                message = frontend.recv_multipart()
                backend.send_multipart(message)
            
            if socks.get(backend) == zmq.POLLIN:
                message = backend.recv_multipart()
                frontend.send_multipart(message)
        
        frontend.close()
        backend.close()
    
    def thread_args(self) -> tuple:
        return (self._router_url, self._dealer_url)
    
    def thread_kwargs(self) -> dict:
        return {"poll_timeout": self._poll_timeo, 
                "message_size": self._msg_size, 
                "zmq_context": None, 
                "stop_event": self._stop_evt}
    
class HashanaZMQReplier(ZMQService):
    """ZMQ interface for HashanaReplier"""
    _msg_size: int
    _rcv_timeo: int
    _zmq_url: str
    _db_path: str
    _worker: bool
    
    def __init__(self, 
                 zmq_url: str, 
                 db_path: str, 
                 recv_timeout: int = 1000, 
                 message_size: int = 1024,
                 worker: bool = False):
        super().__init__()
        self._msg_size = message_size
        self._rcv_timeo = recv_timeout
        self._zmq_url = zmq_url
        self._db_path = db_path
        self._worker = worker
        
    @staticmethod
    def service(zmq_url: str, 
                db_path: str, 
                recv_timeout: int = 2000, 
                message_size: int = 1024,
                zmq_context: zmq.Context = None,
                stop_event: Event = None,
                worker: bool = False,
                db_replier = None):
        context = zmq_context or zmq.Context()
        stop = stop_event or Event()
        socket = context.socket(zmq.REP)
        socket.setsockopt(zmq.RCVTIMEO, recv_timeout)
        socket.setsockopt(zmq.LINGER, recv_timeout)
        socket.setsockopt(zmq.MAXMSGSIZE, message_size)
        if worker:
            socket.connect(zmq_url)
        else:
            socket.bind(zmq_url)
        
        replier = db_replier or HashanaReplier(db_path)
        replier.connect()
        while not stop.is_set():
            try:
                msg = socket.recv()
            except zmq.error.Again:
                continue
            except zmq.error.ContextTerminated:
                break
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
    
    def serve(self, zmq_context: zmq.Context = None):
        type(self).service(self._zmq_url,
                            self._db_path,
                            recv_timeout=self._rcv_timeo,
                            message_size=self._msg_size,
                            zmq_context=zmq_context,
                            worker=self._worker)

    def thread_args(self) -> tuple:
        return (self._zmq_url, self._db_path)
    
    def thread_kwargs(self) -> dict:
        return {"recv_timeout": self._rcv_timeo, 
                "message_size": self._msg_size, 
                "zmq_context": None, 
                "stop_event": self._stop_evt,
                "worker": self._worker,
                "db_replier": None}

class HashanaZMQServer(HashanaZMQReplier):
    """Standalone replier. Will listen on url and accept REQ connections directly"""
    def __init__(self, 
                 listen_url: str, 
                 db_path: str, 
                 recv_timeout: int = 1000, 
                 message_size: int = 1024,
                 db_replier = None):
        super().__init__(listen_url, 
                         db_path, 
                         recv_timeout=recv_timeout, 
                         message_size=message_size, 
                         worker=False,
                         db_replier=db_replier)

class HashanaZMQWorker(HashanaZMQReplier):
    """Replier which connects to dealer (broker). Requires broker to service REQ messages"""
    def __init__(self, 
                 dealer_url: str, 
                 db_path: str, 
                 recv_timeout: int = 1000, 
                 message_size: int = 1024,
                 db_replier = None):
        super().__init__(dealer_url, 
                         db_path, 
                         recv_timeout=recv_timeout, 
                         message_size=message_size, 
                         worker=True,
                         db_replier=db_replier)

class HashanaZMQClient:
    _server: str
    _rcv_timeo: int
    _context: zmq.Context
    _client: zmq.Socket
    _tracking: int
    
    def __init__(self, server_url: str, recv_timeout: int = 10000):
        if not _has_zmq:
            raise ImportError("zmq package is required for the zeromq features")
        self._server = server_url
        self._rcv_timeo = recv_timeout
        self._tracking = 0
        self._context = zmq.Context()
        self._client = None
    
    def __del__(self):
        if self._tracking > 1:
            self._tracking = 1
        self.close()
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

    def get(self, hash_type: str, hex: str) -> (list| dict):
        return self.request(json.dumps([{hash_type: hex}]).encode())
    