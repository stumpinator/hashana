import sqlite3
from collections.abc import Iterable, Iterator
from typing import cast, List
from struct import pack
from pathlib import Path

from .adapters import SQLAdapter, TableAdapter, HexAdapter, GroupAdapterB, ByteAdapter, ByteOrder
from .adapted import FileSizeB, MD5B, SHA1B, SHA256B, HBufferB, BLOBFileB
from .hasher import Hasher
from .exceptions import InvalidHexError, NotConnectedError, InvalidAdapterError, InvalidDBModeError


HASH_ZERO_LENGTH = {'file_size': 0, 
                    'md5': 'd41d8cd98f00b204e9800998ecf8427e', 
                    'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                    'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}


class HashanaDataB(GroupAdapterB):
    """combines multiple metadata for use in hashana database/csv.
        uses bytes for backing data.
    """
    default_label: str = "hashana"
    default_table_name = "hashana"
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)

    @classmethod
    def data_types(cls) -> Iterator[SQLAdapter]:
        # guarantees order when iterating
        yield FileSizeB
        yield MD5B
        yield SHA1B
        yield SHA256B
    
    @classmethod
    def from_rds_row(cls, **kwds):
        buffer = bytearray(pack(FileSizeB.structure('!'), int((kwds['file_size']))))
        buffer += bytes.fromhex(kwds['md5'])
        buffer += bytes.fromhex(kwds['sha1'])
        buffer += bytes.fromhex(kwds['sha256'])
        return cls(buffer, byte_order=ByteOrder.NET)
    
    def as_dict(self) -> dict:
        ret = dict()
        ret['byte_order'] = self._stored_order
        objs: list[ByteAdapter] = [x for x in self.as_objs()]
        ret[FileSizeB.label()] = objs[0].as_ints()[0]
        ret[MD5B.label()] = objs[1].as_hex()
        ret[SHA1B.label()] = objs[2].as_hex()
        ret[SHA256B.label()] = objs[3].as_hex()
        return ret
    
    def as_csv_line(self) -> str:
        objs: list[ByteAdapter] = [x for x in self.as_objs()]
        itms = [str(objs.pop(0).as_ints()[0])]
        for o in objs:
            itms.append(o.as_hex())
        return ','.join(itms) + '\n'
    
    @classmethod
    def from_csv_line(cls, line: str):
        values = line.strip().split(',')
        buffer = bytearray(pack(FileSizeB.structure('!'), int((int(values[0])))))
        buffer += bytes.fromhex(values[1])
        buffer += bytes.fromhex(values[2])
        buffer += bytes.fromhex(values[3])
        return cls(buffer, byte_order=ByteOrder.NET)


class HashanaSQLite:
    """Interface to read hashana sqlite database.
    """
    _path: str
    _pathobj: Path
    _conn: sqlite3.Connection
    _autocommit: bool
    _tracking: int
    _readonly: bool
    _synchronous: str
    _journal_mode: str
    
    def __init__(self,
                 path: str,
                 autocommit: bool = True,
                 journal_mode: str = 'WAL',
                 synchronous: str = None,
                 readonly: bool = True):
        """
        Args:
            path (str): path to sqlite database
            autocommit (bool, optional): perform commit automatically on close. Defaults to True.
            journal_mode (str, optional): sqlite journal mode. Supports: None/WAL/MEMORY. Defaults to 'WAL'.
            synchronous (str, optional): sqlite synchronous pragma option. Supprots: None/EXTRA/OFF. Defaults to None.
            readonly (bool): read only mode
        """
        self._synchronous = synchronous # EXTRA, OFF
        self._journal_mode = journal_mode # WAL, MEMORY
        self._path = path
        self._conn = None
        self._autocommit = autocommit
        self._tracking = 0
        self._pathobj = Path(self._path)
        self._readonly = readonly
        if readonly and not self._pathobj.exists():
            raise FileNotFoundError("Path is not a valid file. Turn off readonly mode or choose existing database")
        
    def __enter__(self):
        self.connect()
        return self
    
    def _create_conn(self) -> sqlite3.Connection:
        sconn: sqlite3.Connection = None
        if self._readonly:
            file_uri = f"{self._pathobj.as_uri()}?mode=ro"
            sconn = sqlite3.connect(file_uri, uri=True)
        else:
            sconn = sqlite3.connect(self._path)
            # automagic pragma statements
            if self._synchronous in ['EXTRA', 'OFF']:
                sconn.execute(f"PRAGMA synchronous = {self._synchronous}")
            if self._journal_mode in ['WAL', 'MEMORY']:
                sconn.execute(f"PRAGMA journal_mode = {self._journal_mode}")
        
        return sconn
    
    def connect(self) -> bool:
        self._tracking += 1
        if self._conn is None:
            self._conn = self._create_conn()
            return True
        return None
            
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close(self._autocommit)
    
    def __del__(self):
        if self._conn is not None:
            self._tracking = 1
            self.close(False)
    
    def close(self, commit: bool = False) -> bool:
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
        if self._conn is None:
            raise NotConnectedError("Not connected")
        
        if not self._readonly:
            self._conn.commit()
    
    @property
    def path(self):
        return self._path
    
    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn
    
    @property
    def connected(self) -> bool:
        return self._conn is not None
    
    @property
    def autocommit(self):
        return self._autocommit
    
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
    
    def calculate_signature(self, adapter: ByteAdapter|HexAdapter|SQLAdapter, hasher_cfg: dict|None = None) -> dict:
        """hack clone of the dbhash program. determines if *contents* of database have changed.
        it is not reading the database file itself.
        it produces consistent results but it is slow if the database has many rows and/or no index.
        wrapper for calculate_signature_hex_sql

        Args:
            adapter (ByteAdapter|HexAdapter|SQLAdapter): class to determine packing and sql statements.
                must extend both SQLAdapater plus (ByteAdapter OR HexAdapter)
            hasher_cfg (dict, None): configuration for the hasher.
                Defaults to None which uses all Hasher defaults
            hasher (Hasher): hasher instance used to hash the bytes and produce report

        Raises:
            NotConnectedError: no connection

        Returns:
            dict: report of hashed bytestream
        """
        return self.calculate_signature_hex_sql(structure=adapter.structure(), 
                                                select_all_sql=adapter.sql_select_all_ordered(), 
                                                hasher_cfg=hasher_cfg)
    
    def calculate_signature_hex_sql(self, structure: str, select_all_sql: str, hasher_cfg: dict|None = None) -> dict:
        """hack clone of the dbhash program. determines if *contents* of database have changed.
        it is not reading the database file itself.
        it produces consistent results but it is slow if the database has many rows and/or no index.

        Args:
            structure (str): how to pack data. see ByteAdapter or struct
            select_all_sql (str): sql command to select all items. ORDER BY should be included for consistency
            hasher_cfg (dict, None): configuration for the hasher.
                Defaults to None which uses all Hasher defaults

        Raises:
            NotConnectedError: no connection

        Returns:
            dict: report of hashed bytestream
        """
        if self._conn is None:
            raise NotConnectedError("Not connected")
        # get all items, ordered, and convert to bytes to hash
        bytestream = map(lambda tpl: pack(structure, *tpl), 
                        self._conn.execute(select_all_sql))
        hasher_cfg = hasher_cfg or dict()
        hasher = Hasher(**hasher_cfg)
        set(hasher.update(b) for b in bytestream)
        return hasher.report()
    
    def has_entry(self, sql_item: SQLAdapter) -> bool:
        """check if entry exists in database. Ignores how many times entry appears.

        Args:
            sql_item (SQLAdapter): item to check. this is an instance of the item not the class itself.

        Raises:
            InvalidAdapterError: sql_item is not instance of SQLAdapter
            NotConnectedError: no connection
            
        Returns:
            bool: True if exists at least once in database. otherwise False
        """
        if self._conn is None:
            raise NotConnectedError("Not connected")
        if not isinstance(sql_item, SQLAdapter):
            raise InvalidAdapterError("Item instance does not support SQLAdapter interface")
        db_entries = self._conn.execute(sql_item.sql_has_entry(), sql_item.as_sql_values()).fetchone()[0]
        return db_entries >= 1
    
    def item_count(self, sql_class: SQLAdapter) -> int:
        """Count number of rows/items in database for the specified data class.

        Args:
            sql_class (SQLAdapter): Data class to count. Must be a subclass of SQLAdapter

        Raises:
            InvalidAdapterError: sql_class is not subclass of SQLAdapter
            NotConnectedError: no connection
            
        Returns:
            int: Number of entries for sql_class in database
        """
        if self._conn is None:
            raise NotConnectedError("Not connected")
        if not issubclass(sql_class, SQLAdapter):
            raise InvalidAdapterError("Class must support SQLAdapter interface")
        sql_class = cast(SQLAdapter, sql_class)
        db_entries = self._conn.execute(sql_class.sql_item_count()).fetchone()[0]
        return db_entries
    
    def items(self, sql_class: SQLAdapter, ordered: bool = False) -> Iterator:
        """Enumerates items of sql class. optionally sorted.

        Args:
            sql_class (SQLAdapter): Data class to count. Must be a subclass of SQLAdapter
            ordered (bool, optional): Should the sql statement add ORDER BY. Defaults to False.

        Raises:
            InvalidAdapterError: sql_class is not subclass of SQLAdapter
            NotConnectedError: no connection

        Yields:
            Iterator: Instances of sql_class type with database values
        """
        if self._conn is None:
            raise NotConnectedError("Not connected")
        if not issubclass(sql_class, SQLAdapter):
            raise InvalidAdapterError("Class must support SQLAdapter interface")
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
            NotConnectedError: no connection
            InvalidHexError: could not convert hex into sql
            InvalidAdapterError: sql_item does not support SQLAdapter interface

        Returns:
            int: rowid if exists, otherwise None
        """
        if self._conn is None:
            raise NotConnectedError("Not connected")
        if not isinstance(sql_item, SQLAdapter):
            raise InvalidAdapterError("Item instance does not support SQLAdapter interface")
        
        try:
            sql_val = sql_item.as_sql_values()
        except:
            raise InvalidHexError("Invalid hex string")
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
            InvalidAdapterError: sql_class is not subclass of SQLAdapter
            NotConnectedError: no connection

        Returns:
            SQLAdapter: Data class of specified type if item exists, otherwise None
        """
        if self._conn is None:
            raise NotConnectedError("Not connected")
        if not issubclass(sql_class, SQLAdapter):
            raise InvalidAdapterError("Class must support SQLAdapter interface")
        sql_class = cast(SQLAdapter, sql_class)
        row = self._conn.execute(sql_class.sql_select_by_id(), (rowid,)).fetchone()
        if row is not None:
            return sql_class.from_sql_values(*row)
        else:
            return None

    def _ro_check(self):
        if self._readonly:
            raise InvalidDBModeError("Database connection is in read only mode")

    def import_blob(self,
                    blob_file: str,
                    adapter: ByteAdapter|SQLAdapter|TableAdapter = HashanaDataB,
                    byte_order: str = None,
                    uniqueset: set = None) -> int:
        """Import data from a blob of data
        
        Args:
            blob_file (str): path to blob file
            adapter (GroupAdapterB): ByteAdapter + SQLAdapter + TableAdapter to transform data for database
                defaults to HashanaDataB which includes FileSize, MD5, SHA1, SHA256
            byte_order (str): byte order of data in blob
            uniqueset (set): set of hashes used for tracking duplicates across multiple files.
                if none, duplicates will not be tracked. this is faster and uses less memory.
        
        Returns:
            int - number of items inserted
        """
        self._ro_check()
        
        inserted = 0
        
        blobfile = BLOBFileB(adapter=adapter, file_path=blob_file, byte_order=byte_order)
        sqlinsert = adapter.sql_insert()
        
        for i in blobfile.items():
            if uniqueset is not None:
                hashid = hash(i)
                if hashid in uniqueset:
                    continue
                uniqueset.add(hashid)
            inserted += 1
            self._conn.execute(sqlinsert, i.as_sql_values())
        
        return inserted

    def import_rds(self,
                    rds_file: str,
                    adapter: ByteAdapter|SQLAdapter|TableAdapter = HashanaDataB,
                    buffer_size: int = 4096,
                    uniqueset: set = None) -> int:
        """Import data from a NSRL RDS data set.
        
        Args:
            rds_file (str): path to rds file
            adapter (GroupAdapterB): ByteAdapter + SQLAdapter + TableAdapter to transform data for database
                defaults to HashanaDataB which includes FileSize, MD5, SHA1, SHA256
            uniqueset (set): set of hashes used for tracking duplicates across multiple files.
                if none, duplicates will not be tracked. this is faster and uses less memory.
        
        Returns:
            int - number of items inserted
        """
        self._ro_check()
        
        buffr = HBufferB(HashanaDataB, size=buffer_size, byte_order='!')
        inserted = 0
        
        if uniqueset is None:
            qry = "SELECT file_size,md5,sha1,sha256 FROM FILE;"
        else:
            # the RDS set hashes should all be in uppercase, but ensure for consistency
            qry = "SELECT file_size,upper(md5),upper(sha1),upper(sha256) FROM FILE;"
        
        for ds in RDSReader(rds_file).enum_tuples(query=qry, uniqueset=uniqueset):
            buffr.add_bytes(pack(FileSizeB.structure('!'), int((ds[0]))))
            buffr.add_bytes(bytes.fromhex(ds[1]))
            buffr.add_bytes(bytes.fromhex(ds[2]))
            buffr.add_bytes(bytes.fromhex(ds[3]))
            if buffr.full:
                inserted += self.insert_buffer_class(buffr, sql_class=adapter, clear=True)
        inserted += self.insert_buffer_class(buffr, sql_class=adapter, clear=True)
        
        return inserted

    def create_tables(self, tables:Iterable[TableAdapter]) -> set[TableAdapter]:
        """create tables in database. does not create indexes (see create_indexes)

        Args:
            tables (Iterable[TableAdapter]): all tables to create in database

        Returns:
            set[TableAdapter]: _description_
        """
        self._ro_check()
        if self._conn is None:
            raise NotConnectedError("Not connected")
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
        self._ro_check()
        if self._conn is None:
            raise NotConnectedError("Not connected")
        created = set()
        for tbl in indexes:
            if tbl not in created:
                created.add(tbl)
                for idx in tbl.sql_table_create_indexes():
                    self._conn.execute(idx)
        return created

    def insert_buffer(self, buffer: HBufferB, clear: bool = False) -> int:
        """inserts multiple items to the database using a buffer. single transaction.
        wrapper for insert_buffer_class
        
        Args:
            buffer (HBufferB): buffer item to be inserted. 
            clear (bool, optional): automatically call clear on buffer when finished. Defaults to False.
        
        Raises:
            ValueError: buffer adapter is not subclass of SQLAdapter
            
        Returns:
            int: number of new items added to database
        """
        return self.insert_buffer_class(buffer=buffer, sql_class=buffer.adapter, clear=clear)

    def insert_buffer_class(self, buffer: HBufferB, sql_class: SQLAdapter, clear: bool = False) -> int:
        """inserts multiple items to the database using a buffer. single transaction.

        Args:
            buffer (HBufferB): buffer item to be inserted.
            sql_class (SQLAdapter): data class to insert into database
            clear (bool, optional): automatically call clear on buffer when finished. Defaults to False.
        
        Raises:
            InvalidAdapterError: sql_class is not subclass of SQLAdapter
            NotConnectedError: no connection
            
        Returns:
            int: number of new items added to database
        """
        self._ro_check()
        if self._conn is None:
            raise NotConnectedError("Not connected")
        if len(buffer) <= 0:
            return 0
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
        self._ro_check()
        if self._conn is None:
            raise NotConnectedError("Not connected")
        inserted = 0
        for itm in hash_items:
            inserted += self._conn.execute(itm.sql_insert(), itm.as_sql_values()).rowcount
        return inserted

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

    @classmethod
    def from_rds_list(cls, rds_list: Iterable[str], output_db: str, adapter: ByteAdapter|SQLAdapter|TableAdapter = HashanaDataB) -> int:
        """creates a hashana sqlite database from the NSRL RDS. it is recommended to use the "minimal" set.
            This is very slow and requires a lot of memory (20GB+ for all sets) due to tracking duplicates.
            The duplicate tracking in python was faster than letting sqlite3 get unique values (in testing).
            Of course, all these recommendations depend heavily on hardware.

        Args:
            rds_list (Iterable[str]): an iterable list of fiel paths to the NSRL RDS sqlite databases.
            output_db (str): path to newly created hashana sqlite database
            adapter (GroupAdapterB): ByteAdapter + SQLAdapter + TableAdapter to transform data for database
                defaults to HashanaDataB which includes FileSize, MD5, SHA1, SHA256

        Returns:
            int: number of unique items inserted into database
        """
        trackset = set()
        inserted = 0
        
        with cls(output_db, readonly=False) as hashana_db:
            hashana_db.create_tables([adapter])
            for i in range(0, len(rds_list)):
                inserted += hashana_db.import_rds(rds_list[i], adapter=adapter, uniqueset=trackset)
            hashana_db.commit()
            hashana_db.create_indexes([adapter])
        return inserted


class HashanaDBReader(HashanaSQLite):
    """Interface to read hashana sqlite database.
    """
    
    def __init__(self, path: str):
        """
        Args:
            path (str): path to sqlite database
        """
        super().__init__(path=path,
                         autocommit=False,
                         readonly=True)


class HashanaDBWriter(HashanaSQLite):
    """Interface to create/modify hashana sqlite database.
    """
    def __init__(self,
                 path: str,
                 autocommit: bool = True,
                 journal_mode: str = 'WAL',
                 synchronous: str = None):
        """
        Args:
            path (str): path to sqlite database
            autocommit (bool, optional): perform commit automatically on close. Defaults to True.
            journal_mode (str, optional): sqlite journal mode. Supports: None/WAL/MEMORY. Defaults to 'WAL'.
            synchronous (str, optional): sqlite synchronous pragma option. Supprots: None/EXTRA/OFF. Defaults to None.
        """
        super().__init__(path=path,
                         autocommit=autocommit,
                         journal_mode=journal_mode,
                         synchronous=synchronous,
                         readonly=False)
 

class RDSReader:
    """Read and enumerate files in the NSRL Reference Data Set (RDS)"""
    
    path: Path
    sql_file_count: str = r"""SELECT COUNT(*) FROM FILE;"""
    sql_hash_count: str = r"""SELECT COUNT(*) FROM (SELECT md5 FROM FILE WHERE file_size > 0 GROUP BY md5);"""
    
    _custom_columns: frozenset = frozenset(('md5','sha1','sha256','file_size'))
    
    @staticmethod
    def dict_factory(cursor, row) -> dict:
        """row factory used with sqlite3 to return dictionaries
        
        Returns:
            dict: dictionary with key/value cooresponding to column/row
        """
        fields = [column[0] for column in cursor.description]
        return {key: value for key, value in zip(fields, row)}
    
    def __init__(self, path):
        """
        Args:
            path (str): path to NSRL RDS sqlite database
        """
        self.path = Path(path)

    def file_count(self) -> int:
        """number of entries in the FILE view.
           fast but not very useful since it gets every entry including duplicates

        Returns:
            int: row count
        """
        file_uri = f"{self.path.as_uri()}?mode=ro"
        with sqlite3.connect(file_uri, uri=True) as con:
            x = con.execute(self.sql_file_count).fetchone()[0]
        return x

    def hash_count(self) -> int:
        """number of unique entries in the FILE table.
           very slow but no duplicates.

        Returns:
            int: row count
        """
        file_uri = f"{self.path.as_uri()}?mode=ro"
        with sqlite3.connect(file_uri, uri=True) as con:
            x = con.execute(self.sql_hash_count).fetchone()[0]
        return x
    
    def custom_columns(self, columns: Iterable[str] = None) -> set[str]:
        """test provided columns against available.

        Args:
            columns (Iterable[str], optional): If None use all available.
            If no matches return all available columns.
            
            Defaults to None.

        Returns:
            set[str]: usable columns for generating queries
        """
        if columns is not None:
            clmns = set(columns).intersection(self._custom_columns)
            if len(clmns) > 0:
                return clmns
        return self.available_columns()
    
    @classmethod
    def available_columns(cls) -> set[str]:
        """usable column names

        Returns:
            set[str]: valid columns that can be used in queries
        """
        return set(cls._custom_columns)
    
    def sql_select_column_filter(self, columns: Iterable[str] = None, distinct: bool = False) -> str:
        """Generate a sql statement with optional columns and distinct

        Args:
            columns (Iterable[str], optional): which columns to select. 
                Defaults to None which will get all columns.
            distinct (bool, optional): only get unique/distinct items. Defaults to False.

        Returns:
            str: sql select statement
        """
        clmns = self.custom_columns(columns)
        selects = ','.join(clmns)
        if distinct:
            sql = f"SELECT {selects} FROM FILE WHERE file_size >= 0 GROUP BY {selects};"
        else:
            sql = f"SELECT {selects} FROM FILE;"
        return sql
    
    def enum_dicts(self, query: str) -> Iterator[dict]:
        """enumerates items in database using dictionary factory

        Args:
            query (str): sql statement for RDS database

        Yields:
            Iterator[dict]: all rows returned by query
        """
        file_uri = f"{self.path.as_uri()}?mode=ro"
        with sqlite3.connect(file_uri, uri=True) as con:
            con.row_factory = RDSReader.dict_factory
            for row in con.execute(query):
                yield row

    def enum_tuples(self, query: str, uniqueset: set = None) -> Iterator[tuple]:
        """enumerates items in database

        Args:
            query (str): sql statement for RDS database
            uniqueset (set|None): duplicate tracking. If None (default) do not track duplicates

        Yields:
            Iterator[tuple]: all rows returned by query
        """
        file_uri = f"{self.path.as_uri()}?mode=ro"
        with sqlite3.connect(file_uri, uri=True) as con:
            for row in con.execute(query):
                if uniqueset is not None:
                    hashid = hash(row)
                    if hashid in uniqueset:
                        continue
                    uniqueset.add(hashid)
                yield row

    @classmethod
    def enum_tuples_multi(cls, rds_list: List[str], query: str, uniqueset: set = None) -> Iterator[tuple]:
        """enumerates items in multiple RDS data sets

        Args:
            file_list (List[str]): RDS datasets to iterate over
            query (str): query executed to generate results
            uniqueset (set, optional): duplicate tracking. If None (default) do not track duplicates

        Yields:
            Iterator[tuple]: all rows returned by query from each file
        """
        for f in rds_list:
            for ds in cls(f).enum_tuples(query, uniqueset=uniqueset):
                yield ds

    def enum_by_columns(self, columns: Iterable[str] = None, distinct: bool = False) -> Iterator[dict]:
        """get items from RDS database returning only specific column data

        Args:
            distinct (bool, optional): only get unique/distinct items. Defaults to False.
            columns (Iterable[str], optional): which columns to select. 
                Defaults to None which will get all columns.

        Yields:
            Iterator[dict]: all rows in dictionary form
        """
        sql = self.sql_select_column_filter(distinct=distinct, columns=columns)
        for itm in self.enum_dicts(sql):
            yield itm
    
    def enum_all(self, distinct: bool = False) -> Iterator[dict]:
        """get all items with default columns from RDS database

        Args:
            distinct (bool, optional): only get unique/distinct items. Defaults to False.

        Yields:
            Iterator[dict]: all rows in dictionary form
        """
        sql = self.sql_select_column_filter(distinct=distinct)
        for itm in self.enum_dicts(sql):
            yield itm

    def enum_group(self, adapter: GroupAdapterB, distinct: bool = False) -> Iterator[GroupAdapterB]:
        """Create adapter object for every entry in the RDS Database

        Args:
            adapter (GroupAdapterB): adapter to format data
            distinct (bool, optional): True will get only unique items but is slower. Defaults to False.

        Yields:
            Iterator[GroupAdapterB]: converted rds metadata into group adapter
        """
        for d in self.enum_all(distinct=distinct):
            yield adapter.from_rds_row(**d)
            
    def enum_blobs(self,
                   adapter: GroupAdapterB,
                   buff_size: int = 4096,
                   distinct: bool = False) -> Iterator[memoryview]:
        """Enumerates RDS data into chunks (blobs)

        Args:
            adapter (GroupAdapterB): adapter to format data
            buff_size (int, optional): Number of items in buffer. total size will be buff_size * struct_size. Defaults to 4096.
            distinct (bool, optional): True will get only unique items but is slower. Defaults to False.

        Yields:
            Iterator[memoryview]: converted rds metadata in binary form. read only.
        """
        hb = HBufferB(adapter, buff_size)
        for i in self.enum_group(adapter=adapter, distinct=distinct):
            hb.add_adapted(i)
            if hb.full:
                yield hb.snapshot()
                hb.clear()
        if len(hb) > 0:
            yield hb.snapshot()
    
    def enum_buffers(self,
                     adapter: GroupAdapterB,
                     buff_size: int = 4096,
                     distinct: bool = False) -> Iterator[HBufferB]:
        """Enumerates RDS data into buffers. Similar to enum_blobs but each item in iterator is separate HBuffer instance

        Args:
            adapter (GroupAdapterB): adapter to format data
            buff_size (int, optional): Number of items in buffer. total size will be buff_size * struct_size. Defaults to 4096.
            distinct (bool, optional): True will get only unique items but is slower. Defaults to False.. Defaults to False.

        Yields:
            Iterator[HBuffer]: converted rds metadata as buffers
        """
        for mv in self.enum_blobs(adapter=adapter, buff_size=buff_size, distinct=distinct):
            hb = HBufferB(adapter, buff_size)
            hb.add_bytes(mv)
            yield hb

    @classmethod
    def make_blob(cls,
                rds_list: List[str],
                blob_path: str,
                hasher_cfg: dict = None,
                append: bool = False,
                uniqueset: set = None,
                adapter: GroupAdapterB = HashanaDataB) -> dict:
        """convert to a blob of data based on an adapter's byte layout

        Args:
            rds_list (Iterable[str]): an iterable list of file paths to the NSRL RDS sqlite databases.
            blob_path (str): output blob file.
            hasher_cfg (dict, optional): Hasher configuration. None will disable hashing.
                Set to empty dictionary to use defaults.
                Defaults to None.
            append (bool, optional): if file exists, append bytes to end of file.
                Defaults to False.
            uniqueset (set, optional): track uniques using a python set. None will disable python tracking.
                Defaults to None.
            adapter (GroupAdapterB, optional): adapter to convert to bytes.
                Defaults to HashanaDataB.

        Raises:
            FileNotFoundError: specified output file is a directory

        Returns:
            dict: hasher report. will be only filesize if hashing is disabled
        """
        if not isinstance(hasher_cfg, dict):
            hasher_cfg = dict(md5=False, sha1=False, sha256=False, sha224=False, sha384=False, sha512=False)
        hasher = Hasher(**hasher_cfg)
        total_bytes = 0
        
        outblob = Path(blob_path)
        
        if outblob.exists() and outblob.is_dir():
            raise FileNotFoundError("output file is a directory")
        
        if outblob.exists() and append:
            out_file = open(outblob.absolute(), 'ba')
        else:
            out_file = open(outblob.absolute(), 'wb')
        
        clms = "file_size,md5,sha1,sha256"
        qry = f"SELECT {clms} FROM FILE"
        for itm in cls.enum_tuples_multi(rds_list=rds_list, query=qry, uniqueset=uniqueset):
            ga = adapter.from_rds_row(file_size=itm[0],
                                       md5=itm[1],
                                       sha1=itm[2],
                                       sha256=itm[3])
            gbytes = ga.as_bytes()
            total_bytes += out_file.write(gbytes)
            hasher.update(gbytes)

        out_file.close()
        
        return hasher.report()

    @classmethod
    def make_csv(cls, rds_list: Iterable[str], output_csv: str) -> int:
        """creates a hashana csv file from the NSRL RDS. it is recommended to use the "minimal" set.
            This is very slow and requires a lot of memory (20GB+ for all sets) due to tracking duplicates.
            The duplicate tracking in python was faster than letting sqlite3 get unique values (in testing).
            Of course, all these recommendations depend heavily on hardware.

        Args:
            rds_list (Iterable[str]): an iterable list of file paths to the NSRL RDS sqlite databases.
            output_csv (str): path to newly created hashana csv

        Returns:
            int: number of unique items inserted into file
        """
        tracking = set()
        clms = "file_size,md5,sha1,sha256"
        qry = f"SELECT {clms} FROM FILE"
        with open(output_csv, 'wt', newline='') as csvfile:
            csvfile.write(clms + '\n')
            for rds in rds_list:
                for ds in cls(rds).enum_tuples_multi(rds_list, query=qry, uniqueset=set()):
                    hashid = hash(ds)
                    #hashid = hash(ds['3'])
                    if hashid in tracking:
                        continue
                    tracking.add(hashid)
                    csvfile.write(','.join(ds) + '\n')
        return len(tracking)


class HashanaReplier(HashanaDBReader):
    """Basic query handler.
    """
    _default_reqs: list[HexAdapter] = [MD5B, SHA1B, SHA256B]
    _valid_reqs: dict[str,HexAdapter]
    
    def __init__(self, db_path: str, valid_requests: Iterable[HexAdapter] = None):
        """
        Args:
            db_path (str): path to sqlite database
            valid_requests (Iterable[HexAdapter], optional): Which type of queries are valid for this handler. 
                Defaults to None which uses defaults (MD5, SHA1, and SHA256).

        Raises:
            InvalidAdapterError: invalid request type
        """
        if valid_requests:
            self._valid_reqs = dict()
            for req in valid_requests:
                if not callable(req) or not issubclass(req, HexAdapter):
                    raise InvalidAdapterError("Hash request must be HexAdapter, callable, and have associated hash algorithm in Hasher")
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
        if self._conn is None:
            raise NotConnectedError("Not connected")
        replies = dict()
        for req in self.parse_requests(requests=requests):
            key = str(req)
            try:
                rowid = self.row_id(req)
            except InvalidHexError:
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
                itm = cast(HashanaDataB, self.item_by_id(rowid, HashanaDataB))
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
        if self._conn is None:
            raise NotConnectedError("Not connected")
        replies = dict()
        for req in self.parse_requests(requests=requests):
            key = str(req)
            try:
                rowid = self.row_id(req)
            except InvalidHexError:
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
