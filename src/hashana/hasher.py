from hashlib import md5, sha1, sha224, sha256, sha384, sha512
from collections.abc import Iterable, Iterator
from concurrent import futures


class Hasher:
    """Hashes data using hashlib. Can perform multiple hashing ops simultaneously.
    """
    all_hash: dict
    buff_size: int
    _hasher_map: dict
    _byte_count: int
    
    _defaults: dict = None
    
    def __init__(self, **kwargs):
        
        # add default values not passed as keyword
        cfg = self.default_config() | kwargs
        
        classmap = self.hashes()
        self.all_hash = dict()
        self._hasher_map = dict()
        for k in classmap.keys():
            if cfg[k] == True:
                self.all_hash[k] = classmap[k]
                self._hasher_map[k] = classmap[k]()
        self.buff_size = cfg['buff_size']
        self._byte_count = 0
        
    def clear(self):
        """reset all hashing and byte counter
        """
        self._hasher_map.clear()
        self._byte_count = 0
        for k,v in self.all_hash.items():
            self._hasher_map[k] = v()
    
    def update(self, buffer: bytes|bytearray|memoryview):
        """updates all hashing objects
        """
        self._byte_count += len(buffer)
        for v in self._hasher_map.values():
            v.update(buffer)
    
    def report(self) -> dict:
        """create a dict report of total bytes and hex digests
        """
        report = dict(size=self._byte_count)
        for k,v in self._hasher_map.items():
            report[k] = v.hexdigest()
        return report
    
    def hash_file(self, file_path: str) -> dict:
        """Hashes and generates report using configured hash algorithms.
            call clear() first unless you want to start from a dirty state

        Args:
            file_path (str): file to hash

        Returns:
            dict: dictionary report of hash information / metadata for file
        """
        
        ba = bytearray(self.buff_size)
        mv = memoryview(ba)
        with open(file_path, 'rb', buffering=0) as f:
            while n := f.readinto(mv):
                self.update(mv[:n])
        
        report = self.report()            
        report['path'] = file_path
        return report
    
    def add_hash_type(self, hash_label: str) -> bool:
        """Add hash type to configuration. Must be a hash in .hashes()

        Args:
            hash_label (str): hash label to add

        Returns:
            bool: True if hash label is valid. Otherwise False.
        """
        classmap = self.hashes()
        if hash_label in classmap.keys():
            self.all_hash[hash_label] = classmap[hash_label]
            self._hasher_map[hash_label] = classmap[hash_label]()
            return True
        else:
            return False
    
    def del_hash_type(self, hash_label: str) -> bool:
        """Removes hash type from configuration.

        Args:
            hash_label (str): hash label to remove

        Returns:
            bool: True if hash was in config. Otherwise False.
        """
        if hash_label in self.all_hash.keys():
            self.all_hash.pop(hash_label)
            self._hasher_map.pop(hash_label)
            return True
        else:
            return False
    
    @staticmethod
    def hash_file_worker(file_path: str, cfg: dict | None = None) -> dict:
        """Hashes file and returns report. Used by threading/multiprocessing as target.

        Args:
            file_path (str): file to hash
            cfg (dict): hasher configuration

        Returns:
            dict: hash report
        """
        report = dict(path=file_path, success=False, size=-1)
        if not isinstance(cfg, dict):
            cfg = {}
        hshr = Hasher(**cfg)
        
        try:
            hshr.hash_file(file_path=file_path)
        except Exception as e:
            report['exception'] = str(e)
            return report
        
        report.update(hshr.report())
        report['success'] = True
        return report
    
    @property
    def config(self) -> dict:
        """Generate copy of current config

        Returns:
            dict: key/value pairs with all hasher class configuration
        """
        d = dict(buff_size=self.buff_size)
        hashtypes = self.hashes().keys()
        for k in hashtypes:
            if k in self.all_hash:
                d[k] = True
            else:
                d[k] = False
        return d
    
    @classmethod
    def default_config(cls) -> dict:
        """Default values for all configuration variables.

        Returns:
            dict: key/value pairs with default hasher class configuration
        """
        if cls._defaults is None:
            cls._defaults = dict(md5=True, sha1=True, sha256=True, sha224=False, 
                                 sha384=False, sha512=False, buff_size=131072)
        return cls._defaults
    
    @classmethod
    def hashes(cls) -> dict[str,callable]:
        """Available hashes

        Returns:
            dict: key = hash name, value = class for instancing
        """
        return dict(md5=md5,
                    sha1=sha1,
                    sha256=sha256,
                    sha224=sha224,
                    sha384=sha384,
                    sha512=sha512)


class HashConcurrent:
    max_threads: int
    use_mp: bool
    
    def __init__(self, max_threads: int = 2, use_mp: bool = False):
        """Can hash multiple files at the same time. May be faster, depending on resources, than hashing individually.
        
        Args:
            max_threads (int): number of available threads or process in the pool. default 2
            use_mp (bool): use multiprocessing instead of threads. default False
        """
        self.max_threads = max_threads
        self.use_mp = use_mp

    def hash_files(self, file_list: Iterable[str], cfg: dict | None = None)-> Iterator[dict]:
        """hash multiple files using concurrency
        
        Args:
            file_list (Iterable[str]): file paths to hash
            cfg (dict|None): Hasher config. If None (default) then use the Hasher class default config
            
        yields:
            Iterator[dict]: report for each file as completed
        """
        if self.use_mp:
            executor = futures.ProcessPoolExecutor(max_workers=self.max_threads)
        else:
            executor = futures.ThreadPoolExecutor(max_workers=self.max_threads)
            
        flist = list()
        for f in file_list:
            flist.append(executor.submit(Hasher.hash_file_worker, f, cfg))
        for fr in futures.as_completed(flist):
            yield fr.result()

        executor.shutdown(True)
        