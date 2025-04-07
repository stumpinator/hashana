from multiprocessing import Process, Queue
from hashana.adapters import BLOBAdapterB, HexAdapter, ByteAdapter, SQLAdapter
from hashana.adapted import FileSizeB, MD5B, SHA1B, SHA256B, SHMBufferB
from collections.abc import Iterable, Iterator
from typing import List, Dict, Tuple
from struct import pack
from hashana.db import HashanaDataB, HashanaDBWriter, RDSReader
from datetime import datetime
from queue import Empty, Full
from argparse import ArgumentParser
from pathlib import Path

class HashanaCreatorMP:
    
    _empty_q: Queue
    _full_q: Queue
    _rds_list: list[str]
    _buff_count: int
    _buff_sz: int
    _adapter: ByteAdapter|SQLAdapter
    _select_sql: str = "SELECT file_size,upper(md5),upper(sha1),upper(sha256) FROM FILE;"
    
    def __init__(self,
                 rds_list: list[str],
                 buffer_count: int = None,
                 buffer_size: int = 8192):
        self._rds_list = rds_list
        self._full_q = Queue()
        self._empty_q = Queue()
        self._buff_count = buffer_count or (len(rds_list) * 2)
        self._buff_sz = buffer_size
        self._adapter = HashanaDataB

    def write_db(self, output_db: str, reader_count: int = 4) -> int:
        uniqueset = set()
        shmems: Dict[str, SHMBufferB] = dict()
        hashana_db = HashanaDBWriter(output_db)
        hashana_db.connect()
        total_written = 0
        hdbsqlins = self._adapter.sql_insert()
        readers_finished = 0
        while True:
            try:
                shm_name = self._full_q.get(True)
            except Empty:
                print("Timeout waiting for item in full_queue")
                break
            
            if shm_name is None:
                readers_finished += 1
                if readers_finished >= reader_count:
                    break
                else:
                    continue
            
            shmem = shmems.get(shm_name, None)
            if shmem is None:
                shmem = SHMBufferB(self._adapter, name=shm_name, create=False)
                shmems[shm_name] = shmem
            
            shmem.load_index()
            if len(shmem) == 0:
                print("Got a zero length buffer")
                break
            
            for i in shmem.as_tuples():
                hashid = hash(i)
                if hashid in uniqueset:
                    continue
                uniqueset.add(hashid)
                hashana_db._conn.execute(hdbsqlins, i)
                total_written += 1
            
            shmem.clear()
            self._empty_q.put_nowait(shm_name)
        
        self._empty_q.put_nowait(None)
        hashana_db.commit()
        hashana_db.close(hashana_db.autocommit)
        shml = list(shmems.values())
        del shmems
        while len(shml) > 0:
            s = shml.pop()
            s.close()
            del s
            
        return total_written

    def reader(self, input):
        shmems: Dict[str, SHMBufferB] = dict()
        records = RDSReader.enum_tuples_multi([input],
                                              self._select_sql,
                                              uniqueset=set())
        read = 0
        fsbstruct = FileSizeB.structure('!')
        while True:
            try:
                shm_name = self._empty_q.get(True, 30)
            except Empty:
                print("Timeout waiting for item in cleared_queue")
                break
            
            if shm_name is None:
                print("Received stop signal from cleared_queue")
                self._empty_q.put_nowait(None)
                break
            
            shmem = shmems.get(shm_name, None)
            if shmem is None:
                shmem = SHMBufferB(self._adapter, name=shm_name, create=False)
                shmems[shm_name] = shmem
                
            shmem.clear()
            while ds := next(records, None):
                shmem.add_bytes(pack(fsbstruct, int((ds[0]))))
                shmem.add_bytes(bytes.fromhex(ds[1]))
                shmem.add_bytes(bytes.fromhex(ds[2]))
                shmem.add_bytes(bytes.fromhex(ds[3]))
                read += 1
                if shmem.full:
                    break
            
            shmem.save_index()
            self._full_q.put_nowait(shm_name)
            
            if ds is None:
                break
        
        self._full_q.put_nowait(None)
        shml = list(shmems.values())
        del shmems
        while len(shml) > 0:
            s = shml.pop()
            s.close()
            del s

        return read

    def create(self, output_db: str):
        shml = list()
        for _ in range(0, self._buff_count):
            b = SHMBufferB(self._adapter, size=self._buff_sz, create=True)
            shml.append(b)
            self._empty_q.put_nowait(b.name)
        hreaders = list()
        for rfile in self._rds_list:
            p = Process(target=self.reader, args=(rfile,))
            p.start()
            hreaders.append(p)
        
        with HashanaDBWriter(output_db) as hdbw:
            hdbw.create_tables([self._adapter])
        
        written = self.write_db(output_db, reader_count=len(self._rds_list))
        
        with HashanaDBWriter(output_db) as hdbw:
            hdbw.create_indexes([self._adapter])
        
        for p in hreaders:
            p.join()
        
        return written
    

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('db', help='output database file')
    parser.add_argument('--rds', required=True, action='append', help='path to RDS dataset. can be used multiple times.')
    parsed = parser.parse_args()
    
    for rds in parsed.rds:
        rdsp = Path(rds)
        if not rdsp.exists() and not rdsp.is_file():
            print(f"{str(rdsp.absolute())} is not a valid file")
            exit(1)
            
    hmpw = HashanaCreatorMP(parsed.rds)
    hmpw.create(parsed.db)