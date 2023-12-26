from hashlib import md5, sha1, sha224, sha256, sha384, sha512
from collections.abc import Iterable, Iterator
from concurrent import futures


class Hasher:
    """Hashes data using hashlib. Can perform multiple hashing ops simultaneously per file.
    """
    all_hash: dict
    buff_size: int
    _defaults: dict = None
    
    def __init__(self, **kwargs):
        
        # add default values not passed as keyword
        cfg = self.default_config() | kwargs
        
        classmap = self.hashes()
        self.all_hash = dict()
        for k in classmap.keys():
            if cfg[k] == True:
                self.all_hash[k] = classmap[k]
        self.buff_size = cfg['buff_size']
    
    def hash_file(self, file_path: str) -> dict:
        """Hashes and generates report using configured hash algorithms.

        Args:
            file_path (str): file to hash

        Returns:
            dict: dictionary report of hash information / metadata for file
        """
        file_hashes = dict()
        for k,v in self.all_hash.items():
            file_hashes[k] = v()
        
        size = 0
        ba = bytearray(self.buff_size)
        mv = memoryview(ba)
        with open(file_path, 'rb', buffering=0) as f:
            while n := f.readinto(mv):
                size += n
                for v in file_hashes.values():
                    v.update(mv[:n])
                    
        report = dict(size=size,path=file_path)
        for k,v in file_hashes.items():
            report[k] = v.hexdigest()
        return report
    
    def hash_byte_chunks(self, chunks: Iterable) -> dict:
        """Hashes and generates report using configured hash algorithms.

        Args:
            chunks (Iterable): bytes to hash

        Returns:
            dict: dictionary report of hash information / metadata for all bytes combined
        """
        file_hashes = dict()
        for k,v in self.all_hash.items():
            file_hashes[k] = v()
            
        size = 0
        for data in chunks:
            size += len(data)
            for v in file_hashes.values():
                v.update(data)
                    
        report = dict(size=size)
        for k,v in file_hashes.items():
            report[k] = v.hexdigest()
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
            return True
        else:
            return False
    
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

class HasherThreaded(Hasher):
    """Use threads to hash multiple files at a time.
        This could be faster depending on disk/cpu performance.
    """
    max_threads: int
    
    def __init__(self, max_threads:int = 2, **kwargs):
        self.max_threads = max(max_threads, 1)
        super().__init__(**kwargs)

    def hash_files(self, file_list: Iterable[str]) -> Iterator[dict]:
        """Hash files and generate dictionary report as they finish.

        Args:
            file_list (Iterable[str]): Iterable of file paths

        Yields:
            dict: dictionary report of hash information / metadata for each file in list
        """
        cfg = self.config
        with futures.ThreadPoolExecutor(self.max_threads) as executor:
            flist = list()
            for f in file_list:
                flist.append(executor.submit(HasherThreaded.hash_worker, f, cfg))
            for fr in futures.as_completed(flist):
                yield fr.result()
    
    @staticmethod
    def hash_worker(file_path: str, cfg: dict) -> dict:
        """Hashes file and returns report. Used by threading/multiprocessing as target.

        Args:
            file_path (str): file to hash
            cfg (dict): hasher configuration

        Returns:
            dict: hash report
        """
        report = dict(path=file_path, success=False, size=-1)
        size = 0
        ba = bytearray(cfg['buff_size'])
        mv = memoryview(ba)
        
        classmap = HasherMP.hashes()
        file_hashes = dict()
        
        # instance all requested hashes
        for k in classmap.keys() & cfg.keys():
            if cfg[k] == True:
                file_hashes[k] = classmap[k]()
                    
        try:
            with open(file_path, 'rb', buffering=0) as f:
                while n := f.readinto(mv):
                    size += n
                    for v in file_hashes.values():
                        v.update(mv[:n])
        except Exception as e:
            report['exception'] = str(e)
            return report
                    
        report['size'] = size
        for k,v in file_hashes.items():
            report[k] = v.hexdigest()
        report['success'] = True
        return report

class HasherMP(HasherThreaded):
    """Use multiprocessing to hash multiple files at a time.
        This could be faster depending on disk/cpu performance.
    """
    def __init__(self, max_threads:int = 2, **kwargs):
        super().__init__(max_threads, **kwargs)

    def hash_files(self, file_list: Iterable[str]) -> Iterator[dict]:
        """Hash files and generate dictionary report as they finish.

        Args:
            file_list (Iterable[str]): Iterable of file paths

        Yields:
            dict: dictionary report of hash information / metadata for each file in list
        """
        cfg = self.config
        with futures.ProcessPoolExecutor(self.max_threads) as executor:
            flist = list()
            for f in file_list:
                flist.append(executor.submit(HasherThreaded.hash_worker, f, cfg))
            for fr in futures.as_completed(flist):
                yield fr.result()
