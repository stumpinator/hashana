import sqlite3
from collections.abc import Iterable, Iterator
from typing import cast
from struct import pack
from pathlib import Path

from .adapters import SQLAdapter, TableAdapter, HexAdapter, GroupAdapter
from .adapted import HBuffer, FileSize, MD5, SHA1, SHA256
from .wrapped import RDSReader
from .hasher import Hasher

HASH_ZERO_LENGTH = {'file_size': 0, 
                    'md5': 'd41d8cd98f00b204e9800998ecf8427e', 
                    'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                    'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}


class HashanaData(GroupAdapter):
    """combines multiple metadata for use in hashana database/csv
    """
    def __init__(self, hexed: str):
        super().__init__(hexed)

    @classmethod
    def data_types(cls) -> Iterator[SQLAdapter]:
        # guarantees order when iterating
        yield FileSize
        yield MD5
        yield SHA1
        yield SHA256
    
    @classmethod
    def label(cls) -> str:
        return "hashana"
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"
    
    @classmethod
    def from_keywords(cls, **kwds):
        """create instance of class from keywords or dictionary.
        expected_keywords = set('file_size', 'md5', 'sha1', 'sha256')

        Returns:
            HashanaData
        """
        key = FileSize.label()
        # convert easier to read integer to FileSize hex
        kwds[key] = FileSize.from_ints(kwds[key]).hexed
        return super().from_keywords(**kwds)

    def as_dict(self) -> dict:
        key = FileSize.label()
        d = super().as_dict()
        # convert FileSize hex to easier to read integer
        d[key] = FileSize(d[key]).as_ints()[0]
        return d
    
    def as_csv_line(self) -> str:
        offset = 0
        itms = list()
        for dt in self.data_types():
            end = offset + (cast(HexAdapter, dt).struct_size() * 2)
            if dt == FileSize:
                # write FileSize as integer instead of hex
                itms.append(str(FileSize(self._hexed[offset:end]).as_ints()[0]))
            else:
                itms.append(self._hexed[offset:end])
            offset = end
        return ','.join(itms) + '\n'
    
    @classmethod
    def from_csv_line(cls, line: str):
        values = line.strip().split(',')
        d = dict(zip(cls.valid_keys(), values))
        key = FileSize.label()
        # FileSize is written as an integer instead of hex. coverted in from_keywords
        d[key] = int(d[key])
        return cls.from_keywords(**d)

class HashanaDBReader:
    """Interface to read hashana sqlite database.
    """
    _path: str
    _pathobj: Path
    _conn: object
    _tracking: int
    
    def __init__(self, path: str):
        """
        Args:
            path (str): path to sqlite database
        """
        self._path = path
        self._conn = None
        self._tracking = 0
        self._pathobj = Path(self._path)
        if not self._pathobj.exists():
            raise ValueError("Path is not a valid file")
        
    def __enter__(self):
        self.connect()
        return self
    
    def connect(self) -> bool:
        self._tracking += 1
        if self._conn is None:
            file_uri = f"{self._pathobj.as_uri()}?mode=ro"
            self._conn = sqlite3.connect(file_uri, uri=True)
            return True
        return None
            
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def __del__(self):
        if self._conn is not None:
            self._tracking = 1
            self.close()
    
    def close(self) -> bool:
        if self._conn is not None:
            self._tracking = max(0, self._tracking - 1)
            if self._tracking == 0:
                self._conn.close()
                self._conn = None
                return True
        return None

    def commit(self):
        raise NotImplementedError("DB interface is read only")
    
    @property
    def path(self):
        return self._path
    
    @property
    def connection(self):
        return self._conn
    
    @property
    def connected(self) -> bool:
        return self._conn is not None
    
    def calculate_signature(self, hex_sql_class, hasher: Hasher) -> dict:
        """hack clone of the dbhash program. determines if *contents* of database have changed.
        it is not reading the database file itself.
        it produces consistent results but it is slow if the database has many rows and/or no index.
        wrapper for calculate_signature_hex_sql

        Args:
            hex_sql_class (_type_): the entries you want to check for consistency.
                must be both HexAdapter and SQLAdapter
            hasher (Hasher): hasher instance used to hash the bytes and produce report

        Raises:
            ValueError: hex_sql_class is not both HexAdapter and SQLAdapter

        Returns:
            dict: report of hashed bytestream
        """
        return self.calculate_signature_hex_sql(hex_class=hex_sql_class, sql_class=hex_sql_class, hasher=hasher)
    
    def calculate_signature_hex_sql(self, hex_class: HexAdapter, sql_class: SQLAdapter, hasher: Hasher) -> dict:
        """hack clone of the dbhash program. determines if *contents* of database have changed.
        it is not reading the database file itself.
        it produces consistent results but it is slow if the database has many rows and/or no index.

        Args:
            hex_class (HexAdapter): adapter used to pack entries into bytes. typically same as sql_class
            sql_class (SQLAdapter): adapter used to select items from database. typically same as hex_class
            hasher (Hasher): hasher instance used to hash the bytes and produce report

        Raises:
            ValueError: Hex or SQL adapter class is not correct type

        Returns:
            dict: report of hashed bytestream
        """
        assert self._conn is not None, "Not connected"
        if not issubclass(sql_class, SQLAdapter):
            raise ValueError("Adapter must support SQLAdapter interface")
        if not issubclass(hex_class, HexAdapter):
            raise ValueError("Adapter must support HexAdapter interface")
        sql_adapter = cast(SQLAdapter, sql_class)
        hex_adapter = cast(HexAdapter, hex_class)
        # get all items, ordered, and convert to bytes to hash
        bytestream = map(lambda tpl: pack(hex_adapter.structure(), *tpl), 
                        self._conn.execute(sql_adapter.sql_select_all_ordered()))
        d = hasher.hash_byte_chunks(bytestream)
        return d
    
    def has_entry(self, sql_item: SQLAdapter) -> bool:
        """check if entry exists in database. Ignores how many times entry appears.

        Args:
            sql_item (SQLAdapter): item to check. this is an instance of the item not the class itself.

        Raises:
            ValueError: sql_item is not instance of SQLAdapter
            
        Returns:
            bool: True if exists at least once in database. otherwise False
        """
        assert self._conn is not None, "Not connected"
        if not isinstance(sql_item, SQLAdapter):
            raise ValueError("Item instance does not support SQLAdapter interface")
        db_entries = self._conn.execute(sql_item.sql_has_entry(), sql_item.as_sql_values()).fetchone()[0]
        return db_entries >= 1
    
    def item_count(self, sql_class: SQLAdapter) -> int:
        """Count number of rows/items in database for the specified data class.

        Args:
            sql_class (SQLAdapter): Data class to count. Must be a subclass of SQLAdapter

        Raises:
            ValueError: sql_class is not subclass of SQLAdapter
            
        Returns:
            int: Number of entries for sql_class in database
        """
        assert self._conn is not None, "Not connected"
        if not issubclass(sql_class, SQLAdapter):
            raise ValueError("Class must support SQLAdapter interface")
        sql_class = cast(SQLAdapter, sql_class)
        db_entries = self._conn.execute(sql_class.sql_item_count()).fetchone()[0]
        return db_entries
    
    def items(self, sql_class: SQLAdapter, ordered: bool = False) -> Iterator:
        """Enumerates items of sql class. optionally sorted.

        Args:
            sql_class (SQLAdapter): Data class to count. Must be a subclass of SQLAdapter
            ordered (bool, optional): Should the sql statement add ORDER BY. Defaults to False.

        Raises:
            ValueError: sql_class is not subclass of SQLAdapter

        Yields:
            Iterator: Instances of sql_class type with database values
        """
        assert self._conn is not None, "Not connected"
        if not issubclass(sql_class, SQLAdapter):
            raise ValueError("Class must support SQLAdapter interface")
        sql_class = cast(SQLAdapter, sql_class)
        if ordered:
            sql = sql_class.sql_select_all_ordered()
        else:
            sql = sql_class.sql_select_all()
        for row in self._conn.execute(sql):
            yield sql_class.from_sql_values(*row)
    
    def row_id(self, sql_item: SQLAdapter) -> int:
        """Retrieves rowid (primary key) of item in database.

        Args:
            sql_item (SQLAdapter): Item to retrieve. this is an instance of the item not the class itself.

        Raises:
            ValueError: sql_item is not instance of SQLAdapter

        Returns:
            int: rowid if exists, otherwise None
        """
        assert self._conn is not None, "Not connected"
        if not isinstance(sql_item, SQLAdapter):
            raise ValueError("Item instance does not support SQLAdapter interface")
        try:
            sql_val = sql_item.as_sql_values()
        except:
            raise ValueError("Invalid hex string")
        row = self._conn.execute(sql_item.sql_select(), sql_val).fetchone()
        if row is not None:
            return row[0]
        else:
            return None
    
    def item_by_id(self, rowid: int, sql_class: SQLAdapter) -> SQLAdapter:
        """Retrieve item by rowid (primary key)

        Args:
            rowid (int): rowid (primary key) of item to retrieve
            sql_class (SQLAdapter): Data class to return. Must be a subclass of SQLAdapter

        Raises:
            ValueError: sql_class is not subclass of SQLAdapter

        Returns:
            SQLAdapter: Data class of specified type if item exists, otherwise None
        """
        assert self._conn is not None, "Not connected"
        if not issubclass(sql_class, SQLAdapter):
            raise ValueError("Class must support SQLAdapter interface")
        sql_class = cast(SQLAdapter, sql_class)
        row = self._conn.execute(sql_class.sql_select_by_id(), (rowid,)).fetchone()
        if row is not None:
            return sql_class.from_sql_values(*row)
        else:
            return None

class HashanaDBWriter:
    """Interface to create/modify hashana sqlite database.
    """
    _path: str
    _conn: object
    _autocommit: bool
    _tracking: int
    _synchronous: str
    _journal_mode: str
    
    def __init__(self, path: str, autocommit: bool = True, journal_mode: str = 'WAL', synchronous: str = None):
        """
        Args:
            path (str): path to sqlite database
            autocommit (bool, optional): perform commit automatically on close. Defaults to True.
            journal_mode (str, optional): sqlite journal mode. Supports: None/WAL/MEMORY. Defaults to 'WAL'.
            synchronous (str, optional): sqlite synchronous pragma option. Supprots: None/EXTRA/OFF. Defaults to None.
        """
        self._synchronous = synchronous # EXTRA, OFF
        self._journal_mode = journal_mode # WAL, MEMORY
        self._path = path
        self._conn = None
        self._autocommit = autocommit
        self._tracking = 0
        
    def __enter__(self):
        self.connect()
        return self
    
    def connect(self) -> bool:
        self._tracking += 1
        if self._conn is None:
            self._conn = sqlite3.connect(self._path)
            # automagic pragma statements
            if self._synchronous in ['EXTRA', 'OFF']:
                self._conn.execute(f"PRAGMA synchronous = {self._synchronous}")
            if self._journal_mode in ['WAL', 'MEMORY']:
                self._conn.execute(f"PRAGMA journal_mode = {self._journal_mode}")
            return True
        return None
            
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close(self._autocommit)
    
    def __del__(self):
        self._tracking = 1
        self.close(False)
    
    @property
    def path(self):
        return self._path
    
    @property
    def connection(self):
        return self._conn
    
    @property
    def connected(self) -> bool:
        return self._conn is not None
    
    @property
    def autocommit(self):
        return self._autocommit
    
    def close(self, commit: bool = False):
        if self._conn is not None:
            if commit:
                self.commit()
            self._tracking = max(0, self._tracking - 1)
            if self._tracking == 0:
                self._conn.close()
                self._conn = None
                return True
        return None

    def commit(self):
        assert self._conn is not None, "Not connected"
        self._conn.commit()
    
    def create_tables(self, tables:Iterable[TableAdapter]) -> set[TableAdapter]:
        """create tables in database. does not create indexes (see create_indexes)

        Args:
            tables (Iterable[TableAdapter]): all tables to create in database

        Returns:
            set[TableAdapter]: _description_
        """
        assert self._conn is not None, "Not connected"
        created = set()
        for tbl in tables:
            if tbl not in created:
                created.add(tbl)
                self._conn.execute(tbl.sql_table_create())
        return created
    
    def create_indexes(self, indexes:Iterable[TableAdapter]) -> set[TableAdapter]:
        """creates indexes on the tables. fails if tables do not exist (see create_tables)

        Args:
            indexes (Iterable[TableAdapter]): all indexes to add to respective tables

        Returns:
            set[TableAdapter]: number of CREATE INDEX statements executed. does not determine if previously created.
        """
        assert self._conn is not None, "Not connected"
        created = set()
        for tbl in indexes:
            if tbl not in created:
                created.add(tbl)
                for idx in tbl.sql_table_create_indexes():
                    self._conn.execute(idx)
        return created

    def insert_buffer(self, buffer: HBuffer, clear: bool = False) -> int:
        """inserts multiple items to the database using a buffer. single transaction.
        wrapper for insert_buffer_class
        
        Args:
            buffer (HBuffer): buffer item to be inserted. 
            clear (bool, optional): automatically call clear on buffer when finished. Defaults to False.
        
        Raises:
            ValueError: buffer adapter is not subclass of SQLAdapter
            
        Returns:
            int: number of new items added to database
        """
        return self.insert_buffer_class(buffer=buffer, sql_class=buffer.hex_adapter, clear=clear)
    
    def insert_buffer_class(self, buffer: HBuffer, sql_class: SQLAdapter, clear: bool = False):
        """inserts multiple items to the database using a buffer. single transaction.

        Args:
            buffer (HBuffer): buffer item to be inserted.
            sql_class (SQLAdapter): data class to insert into database
            clear (bool, optional): automatically call clear on buffer when finished. Defaults to False.
        
        Raises:
            ValueError: sql_class is not subclass of SQLAdapter
            
        Returns:
            int: number of new items added to database
        """
        assert self._conn is not None, "Not connected"
        if len(buffer) <= 0:
            return 0
        if not issubclass(sql_class, SQLAdapter):
            raise ValueError("Adapter must support SQLAdapter interface")
        sql_class = cast(SQLAdapter, sql_class)
        inserted = self._conn.executemany(sql_class.sql_insert(), buffer.as_tuples()).rowcount
        
        if clear:
            buffer.clear()
        
        return inserted
    
    def insert_hashes(self, hash_items: Iterable[SQLAdapter]) -> int:
        """inserts items one at a time. does not require homogenous items.
        this is slow for mass inserts. if speed is required use hashbuffers.

        Args:
            hash_items (Iterable[SQLAdapter]): items to be inserted

        Returns:
            int: number of new items added to database
        """
        assert self._conn is not None, "Not connected"
        inserted = 0
        for itm in hash_items:
            inserted += self._conn.execute(itm.sql_insert(), itm.as_sql_values()).rowcount
        return inserted

    def backup_to(self, db_path: str):
        """WARNING: this will clobber target database contents!
        copy contents of database to another.
        useful for creating databases in memory and then copying to disk.

        Args:
            db_path (str): file path to new database
        """
        self.commit()
        outdb = sqlite3.connect(db_path)
        self._conn.backup(outdb)
        outdb.commit()
        outdb.close()
    
    def _merge_to(self, db_path: str):
        """attempts to insert items from current database into other database.
        testing/experimental. use at your own risk.

        Args:
            db_path (str): file path to other database
        """
        self.commit()
        
        self._conn.execute("ATTACH '" + db_path + "' as dba")
        self._conn.execute("BEGIN")
        for row in self._conn.execute("SELECT * FROM sqlite_master WHERE type='table'"):
            combine = "INSERT OR IGNORE INTO dba."+ row[1] + " SELECT * FROM " + row[1]
            self._conn.execute(combine)
        
        self.commit()
        self._conn.execute("detach database dba")

class HashanaRDSReader(RDSReader):
    """Reads NSRL RDS sqlite database and converts data to HashanaData
    """
    def __init__(self, path):
        super().__init__(path)

    def enum_hashana_data(self, distinct: bool = False) -> Iterator[HashanaData]:
        """Create HashanaData object for every entry in the RDS Database

        Args:
            distinct (bool, optional): True will get only unique items but is slower. Defaults to False.

        Yields:
            Iterator[HashanaData]: converted rds metadata
        """
        for d in self.enum_all(distinct=distinct):
            yield HashanaData.from_keywords(**d)
    
    def enum_blobs(self, buff_size: int = 4096, distinct: bool = False) -> Iterator[memoryview]:
        """Enumerates RDS data into chunks (blobs)

        Args:
            buff_size (int, optional): Number of items in buffer. total size will be buff_size * struct_size. Defaults to 4096.
            distinct (bool, optional): True will get only unique items but is slower. Defaults to False.. Defaults to False.

        Yields:
            Iterator[memoryview]: converted rds metadata in binary form. read only.
        """
        hb = HBuffer(HashanaData, buff_size)
        for i in self.enum_hashana_data(distinct=distinct):
            hb.add_hex(i)
            if hb.full:
                yield hb.snapshot()
                hb.clear()
        if len(hb) > 0:
            yield hb.snapshot()

    def enum_buffers(self, buff_size: int = 4096, distinct: bool = False) -> Iterator[HBuffer]:
        """Enumerates RDS data into buffers. Similar to enum_blobs but each item in iterator is separate HBuffer instance

        Args:
            buff_size (int, optional): Number of items in buffer. total size will be buff_size * struct_size. Defaults to 4096.
            distinct (bool, optional): True will get only unique items but is slower. Defaults to False.. Defaults to False.

        Yields:
            Iterator[HBuffer]: converted rds metadata as buffers
        """
        for mv in self.enum_blobs(buff_size=buff_size, distinct=distinct):
            hb = HBuffer(HashanaData, buff_size)
            hb.add_bytes(mv)
            yield hb

    @classmethod
    def make_hashana_db(cls, rds_list: Iterable[str], output_db: str) -> int:
        """creates a hashana sqlite database from the NSRL RDS. it is recommended to use the "minimal" set.
            This is very slow and requires a lot of memory (20GB+ for all sets) due to tracking duplicates.
            The duplicate tracking in python was faster than letting sqlite3 get unique values (in testing).
            Of course, all these recommendations depend heavily on hardware.

        Args:
            rds_list (Iterable[str]): an iterable list of fiel paths to the NSRL RDS sqlite databases.
            output_db (str): path to newly created hashana sqlite database

        Returns:
            int: number of unique items inserted into database
        """
        tracking = set()
        buffr = HBuffer(HashanaData, 32 * 1024)
        with HashanaDBWriter(output_db) as hashana_db:
            hashana_db.create_tables([HashanaData])
            for rds in rds_list:
                for ds in HashanaRDSReader(rds).enum_all():
                    hashid = hash((ds['file_size'],ds['md5'],ds['sha1'],ds['sha256']))
                    #hashid = hash(ds['sha256'])
                    if hashid in tracking:
                        continue
                    tracking.add(hashid)
                    buffr.add_bytes(HashanaData.from_keywords(**ds).as_bytes())
                    if buffr.full:
                        hashana_db.insert_buffer(buffr, True)
            if len(buffr) > 0:
                hashana_db.insert_buffer(buffr, True)
            inserted = len(tracking)
            tracking.clear()
            hashana_db.commit()
            hashana_db.create_indexes([HashanaData])
        return inserted

    @classmethod
    def make_hashana_csv(cls, rds_list: Iterable[str], output_csv: str) -> int:
        """creates a hashana csv file from the NSRL RDS. it is recommended to use the "minimal" set.
            This is very slow and requires a lot of memory (20GB+ for all sets) due to tracking duplicates.
            The duplicate tracking in python was faster than letting sqlite3 get unique values (in testing).
            Of course, all these recommendations depend heavily on hardware.

        Args:
            rds_list (Iterable[str]): an iterable list of fiel paths to the NSRL RDS sqlite databases.
            output_csv (str): path to newly created hashana csv

        Returns:
            int: number of unique items inserted into file
        """
        tracking = set()
        with open(output_csv, 'wt', newline='') as csvfile:
            csvfile.write(HashanaData.csv_header())
            for rds in rds_list:
                for ds in HashanaRDSReader(rds).enum_all():
                    hashid = hash((ds['file_size'],ds['md5'],ds['sha1'],ds['sha256']))
                    #hashid = hash(ds['sha256'])
                    if hashid in tracking:
                        continue
                    tracking.add(hashid)
                    csvfile.write(HashanaData.from_keywords(**ds).as_csv_line())
        return len(tracking)

class HashanaReplier(HashanaDBReader):
    """Basic query handler.
    """
    _default_reqs: list[HexAdapter] = [MD5, SHA1, SHA256]
    _valid_reqs: dict[str,HexAdapter]
    
    def __init__(self, db_path: str, valid_requests: Iterable[HexAdapter] = None):
        """
        Args:
            db_path (str): path to sqlite database
            valid_requests (Iterable[HexAdapter], optional): Which type of queries are valid for this handler. 
                Defaults to None which uses defaults (MD5, SHA1, and SHA256).

        Raises:
            ValueError: invalid request type
        """
        if valid_requests:
            self._valid_reqs = dict()
            for req in valid_requests:
                if not callable(req) or not issubclass(req, HexAdapter):
                    raise ValueError("Hash request must be HexAdapter, callable, and have associated hash algorithm in Hasher")
                req = cast(HexAdapter, req)
                self._valid_reqs[req.label()] = req
        else:
            self._valid_reqs = {hx.label():hx for hx in self._default_reqs}
        super().__init__(db_path)
    
    def parse_requests(self, requests: Iterable[dict[str,str]]) -> set[HexAdapter]:
        """Filters requests for valid items. This will check that passed request is a configured type
            and the string value conforms to expected size (e.g. an MD5 hash is 32 characters long).

        Args:
            requests (Iterable[dict[str,str]]): collection of key/value pairs representing a query for the database.
                key = label of adapter type
                value = what to query for
                e.g. [{'md5': 'd41d8cd98f00b204e9800998ecf8427e'}]

        Returns:
            set[HexAdapter]: set of unique, valid requests
        """
        valid = set()
        for request in requests:
            if isinstance(request, dict):
                reqs = set(request.keys()) & set(self._valid_reqs.keys())
                for req in reqs:
                    r = request[req].strip().lower()
                    if len(r) == self._valid_reqs[req].struct_size() * 2:
                        h = self._valid_reqs[req](r)
                        valid.add(h)
        return valid
    
    def process_requests(self, requests: Iterable[dict[str,str]]) -> dict[str,dict]:
        """Query database for all valid requests

        Args:
            requests (Iterable[dict[str,str]]): collection of key/value pairs representing a query for the database.
                key = label of adapter type
                value = what to query for
                e.g. [{'md5': 'd41d8cd98f00b204e9800998ecf8427e'}]

        Returns:
            dict[str,dict]: reply containing full row data for query.
                key = value from query
                value = row data. None if not found. INVALID_HASH is hash does not parse correctly by adapter
                e.g.
                [{'d41d8cd98f00b204e9800998ecf8427e': {...}},
                {'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': None},
                {'123abcxyz': 'INVALID_HASH'}]
        """
        assert self._conn is not None, "Not connected"
        replies = dict()
        for req in self.parse_requests(requests=requests):
            key = str(req)
            try:
                rowid = self.row_id(req)
            except ValueError:
                # invalid hash i.e. text is not valid hex
                replies[key] = "INVALID_HASH"
                continue
            except:
                replies[key] = "ERROR_ROWID"
                continue
            
            if rowid is None:
                replies[key] = None
                continue
            
            try:
                itm = cast(HashanaData, self.item_by_id(rowid, HashanaData))
            except:
                # should probably never happen unless something breaks after getting rowid
                replies[key] = "ERROR_UNKOWN"
            else:
                replies[key] = itm.as_dict()
        return replies

class HashanaTFReplier(HashanaReplier):
    def process_requests(self, requests: Iterable[dict[str,str]]) -> bool:
        """Query database for all valid requests.

        Args:
            requests (Iterable[dict[str,str]]): collection of key/value pairs representing a query for the database.
                key = label of adapter type
                value = what to query for
                e.g. [{'md5': 'd41d8cd98f00b204e9800998ecf8427e'}]

        Returns:
            bool: True if hash exists in database. False if it doesn't.
                key = value from query
                value = True/False
                e.g.
                [{'d41d8cd98f00b204e9800998ecf8427e': True},
                {'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': False},
                {'123abcxyz': 'False'}]
        """
        assert self._conn is not None, "Not connected"
        replies = dict()
        for req in self.parse_requests(requests=requests):
            key = str(req)
            try:
                rowid = self.row_id(req)
            except ValueError:
                # invalid hash i.e. text is not valid hex
                replies[key] = False
                continue
            except:
                replies[key] = "ERROR_ROWID"
                continue
            
            replies[key] = rowid is not None
            
        return replies

if __name__ == "__main__":
    pass
