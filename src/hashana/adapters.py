from abc import abstractmethod, ABCMeta
from collections.abc import Iterable, Iterator
from struct import pack, unpack, calcsize
from typing import cast, Dict
from enum import StrEnum


class ByteOrder(StrEnum):
    NATIVE = '@'
    STANDARD = '='
    LITTLE = '<'
    BIG = '>'
    NET = '!'


class SQLAdapter(metaclass=ABCMeta):
    """Abstract class/interface for interacting with data in sqlite3
    """
    
    INT_DEFAULT: str = "INTEGER DEFAULT NULL"
    
    default_table_name: str = None
    _sql_insert: str = None
    _sql_has_entry: str = None
    _sql_item_count: str = None
    _sql_select: str = None
    _sql_select_all: str = None
    _sql_select_all_ordered: str = None
    _sql_select_by_id: str = None
    
    def __init__(self):
        pass
    
    @classmethod
    def sql_insert_multiple(cls, count: int) -> str:
        """generates sql for inserting multiple rows in one command
            e.g.
            INSERT OR IGNORE INTO table_name(column_0,column_1) VALUES (?,?),(?,?)
           
        Args:
            count (int): number of row data to insert

        Returns:
            str: sql statement
        """
        count = max(1, count)
        columns = list(cls.sql_columns().keys())
        pcount = len(columns)
        columns = ','.join(columns)
        params = '(' + ','.join(['?' for _ in range(0,pcount)]) + ')'
        if count > 1:
            params = ','.join(f"{params}" for _ in range(0,count))
        # INSERT OR IGNORE INTO {table}(column_0,column_1 ...) VALUES (?,? ...),(?,? ...),(?,? ...)
        return f"INSERT OR IGNORE INTO {cls.sql_table_name()}({columns}) VALUES {params}"
    
    @classmethod
    def sql_insert(cls) -> str:
        """generates sql for inserting values. used for inserting single row or executemany with generator
            e.g.
            INSERT OR IGNORE INTO table_name(column_0,column_1) VALUES (?,?)

        Returns:
            str: sql statement
        """
        if cls._sql_insert is None:
            columns = list(cls.sql_columns().keys())
            pcount = len(columns)
            columns = ','.join(columns)
            params = ','.join(['?' for _ in range(0,pcount)])
            cls._sql_insert = f"INSERT OR IGNORE INTO {cls.sql_table_name()}({columns}) VALUES ({params})"
        # INSERT OR IGNORE INTO {table}(column_0,column_1 ...) VALUES (?,? ...)
        return cls._sql_insert
    
    @classmethod
    def sql_has_entry(cls) -> str:
        """generates sql statement to determine how many instances of values are in database.
            used to determine if an item already exists in the table.
            e.g.
            SELECT COUNT(*) FROM table_name WHERE column_0 = ? AND column_1 = ?
           
        Returns:
            str: sql statement
        """
        if cls._sql_has_entry is None:
            wheres = ' AND '.join(f"{x} = ?" for x in cls.sql_columns().keys())
            cls._sql_has_entry = f"SELECT COUNT(*) FROM {cls.sql_table_name()} WHERE {wheres}"
        # SELECT COUNT(*) FROM {table} WHERE {column_0} = ? AND {column_1} = ? ...
        return cls._sql_has_entry
    
    @classmethod
    def sql_item_count(cls) -> str:
        """generates sql to determine how many items of a specific class (e.g. SHA256) are in database.
            tests that all columns associated are NOT NULL
            e.g.
            SELECT COUNT(*) FROM table_name WHERE column_0 IS NOT NULL AND column_1 IS NOT NULL
           
        Returns:
            str: sql statement
        """
        if cls._sql_item_count is None:
            wheres = ' AND '.join(f"{x} IS NOT NULL" for x in cls.sql_columns().keys())
            cls._sql_item_count = f"SELECT COUNT(*) FROM {cls.sql_table_name()} WHERE {wheres}"
        # SELECT COUNT(*) FROM {table} WHERE {column_0} IS NOT NULL AND {column_1} IS NOT NULL ...
        return cls._sql_item_count
    
    @classmethod
    def sql_select(cls) -> str:
        """generates sql to select the rowid of a specific item
            e.g.
            SELECT rowid FROM table_name WHERE column_0 = ? AND column_1 = ?

        Returns:
            str: sql statement
        """
        if cls._sql_select is None:
            wheres = ' AND '.join(f"{x} = ?" for x in cls.sql_columns().keys())
            cls._sql_select = f"SELECT rowid FROM {cls.sql_table_name()} WHERE {wheres}"
        # SELECT rowid FROM {table} WHERE {column_0} = ? AND {column_1} = ? ...
        return cls._sql_select
    
    @classmethod
    def sql_select_by_id(cls) -> str:
        """generates sql to select item columns by rowid
            e.g.
            SELECT column_0,column_1 FROM table_name WHERE rowid = ?

        Returns:
            str: sql statement
        """
        if cls._sql_select_by_id is None:
            cls._sql_select_by_id = cls.sql_select_all() + " WHERE rowid = ?"
        # SELECT {column_0,column_1,...} FROM {table} WHERE rowid = ?
        return cls._sql_select_by_id
    
    @classmethod
    def sql_select_all(cls) -> str:
        """generates sql to select all item columns from the table
            e.g.
            SELECT column_0,column_1 FROM table_name

        Returns:
            str: sql statement
        """
        if cls._sql_select_all is None:
            columns = ','.join(cls.sql_columns().keys())
            cls._sql_select_all = f"SELECT {columns} FROM {cls.sql_table_name()}"
        # SELECT {column_0,column_1,...} FROM {table}
        return cls._sql_select_all
    
    @classmethod
    def sql_select_all_ordered(cls) -> str:
        """generates sql to select all item columns from the table with ORDERING by columns.
            used to get consistent results in case order matters
            e.g.
            SELECT column_0,column_1 FROM table_name ORDER BY column_0,column_1

        Returns:
            str: sql statement
        """
        if cls._sql_select_all_ordered is None:
            columns = ','.join(cls.sql_columns().keys())
            cls._sql_select_all_ordered = f"SELECT {columns} FROM {cls.sql_table_name()} ORDER BY {columns}" 
        # SELECT {column_0,column_1,...} FROM {table}
        return cls._sql_select_all_ordered
    
    @abstractmethod
    def as_sql_values(self) -> tuple:
        """
        Returns:
            tuple[Any]: values for inserting into database
        """
        raise NotImplementedError
    
    @classmethod
    def sql_table_name(cls) -> str:
        """
        Returns:
            str: table name used for generating sql statements
        """
        return cls.default_table_name
    
    @classmethod
    @abstractmethod
    def sql_columns(cls) -> dict[str,str]:
        """all columns expected in the table.
            key = column name
            value = column creation options

        Returns:
            dict: key/value pair of columns and options to create column in sql
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def from_sql_values(cls, *args):
        """create a instance from tuple of values returned with sql_select_all
        """
        raise NotImplementedError


class TableAdapter(metaclass=ABCMeta):
    """Abstract class/interface for creating tables and indexes in a sqlite3 database
    """
    
    default_table_name: str = None
    _sql_table_drop: str = None
    _sql_table_create: str = None
    _sql_table_columns: str = None
    _sql_indexes: dict = None
    
    def __init__(self):
        pass
    
    @classmethod
    def sql_table_create(cls) -> str:
        """generates sql to create a table
            e.g.
                CREATE TABLE IF NOT EXISTS table_name(rowid INTEGER PRIMARY KEY NOT NULL, 
                                                        column_0 INTEGER, column_1 INTEGER)

        Returns:
            str: sql statement
        """
        if cls._sql_table_create is None:
            columns = ','.join(cls.sql_table_columns())
            cls._sql_table_create = f"CREATE TABLE IF NOT EXISTS {cls.sql_table_name()}({columns})"
        return cls._sql_table_create
    
    @classmethod
    def sql_table_drop(cls) -> str:
        """generates sql to drop table
            e.g.
                DROP TABLE IF EXISTS table_name

        Returns:
            str: sql statement
        """
        if cls._sql_table_drop is None:
            cls._sql_table_drop = f"DROP TABLE IF EXISTS {cls.sql_table_name()}"
        return cls._sql_table_drop
    
    @classmethod
    def sql_table_create_indexes(cls) -> Iterator[str]:
        """generates sql to create indexes
            e.g.
                CREATE INDEX IF NOT EXISTS IDX_NAME ON table_name(column_0, column_1)
        
        Yields:
            Iterator[str]: sql statements
        """
        for k,v in cls.sql_indexes().items():
            columns = ','.join(v)
            yield f"CREATE INDEX IF NOT EXISTS {k} ON {cls.sql_table_name()}({columns})"
    
    @classmethod
    def sql_table_drop_indexes(cls) -> Iterator[str]:
        """generates sql to drop indexes
            e.g.
                DROP INDEX IF EXISTS IDX_NAME
        
        Yields:
            Iterator[str]: sql statements
        """
        for k in cls.sql_indexes().keys():
            yield f"DROP INDEX IF EXISTS {k}"
    
    @classmethod
    def sql_table_name(cls) -> str:
        """
        Returns:
            str: table name used for generating sql statements
        """
        return cls.default_table_name
    
    @classmethod
    @abstractmethod
    def data_types(cls) -> Iterable[SQLAdapter]:
        """individual types this data class is wrapping. order needs to be consistent with each call.
        
        Yields:
            Iterator[SQLAdapter]: data types combined representing set of data
        """
        raise NotImplementedError
    
    @classmethod
    @abstractmethod
    def sql_table_columns(cls) -> Iterable[str]:
        """generate list of column creation statements

        Returns:
            Iterable[str]: all column statements required to create table
        """
        raise NotImplementedError
    
    @classmethod
    @abstractmethod
    def sql_indexes(cls) -> dict[str,tuple[str]]:
        """generate table indexes used for creating/dropping indexes
            k = name of index
            v = columns

        Returns:
            dict: k/v representing index names and columns they will index
        """
        raise NotImplementedError


class HexAdapter(metaclass=ABCMeta):
    """Used for transforming hex (strings) into other data types like bytes or integer tuples
    also used for packing and unpacking into bytes"""
    _hexed: str
    # class level, initialized on first access
    _structure: str = None
    _struct_size: int = None
    
    def __init__(self, hexed: str):
        """
        Args:
            hexed (str): hex string representing object
        """
        # store hexed string consistently by stripping whitespace and using lowercase
        self._hexed = hexed.strip().lower()
    
    def as_bytes(self) -> bytes:
        """convert hex string into bytes

        Returns:
            bytes: hex converted into bytes
        """
        return bytes.fromhex(self._hexed)
    
    def as_ints(self) -> tuple[int]:
        """convert hex string into integers based on structure

        Returns:
            tuple[int]: data as tuple of integers
        """
        return unpack(self.structure(), self.as_bytes())

    def as_dict(self) -> dict:
        """generate dictionary to represent data.
            key = label
            value = hexed

        Returns:
            dict: key/value pair representing class and instance
        """
        return {self.label():self.as_hex()}
    
    def as_hex(self) -> str:
        """
        Returns:
            str: hex string representing data class
        """
        return self._hexed
    
    def __str__(self):
        return self._hexed

    def __repr__(self):
        return self._hexed
    
    def __hash__(self):
        return hash(self._hexed)
    
    @classmethod
    def structure(cls) -> str:
        """byte order and data layout. see python struct

        Returns:
            str: binary layout in python struct format, including byte order
        """
        if cls._structure is None:
            cls._structure = f"{cls.struct_order()}{cls.struct_layout()}"
        return cls._structure
    
    @classmethod
    def struct_order(cls) -> str:
        """byte order used in struct definitions. same as python struct package
        Default: @ (native)
        Valid characters: @ = < > !

        Returns:
            str: single character representing byte order
        """
        return "@"
    
    @classmethod
    @abstractmethod
    def label(cls) -> str:
        """
        Returns:
            str: Unique label used for various automated serialization
        """
        raise NotImplementedError
    
    @classmethod
    @abstractmethod
    def struct_layout(cls) -> str:
        """data layout. see python struct

        Returns:
            str: binary layout in python struct format without byte order specification
        """
        raise NotImplementedError
    
    @classmethod
    def struct_size(cls) -> int:
        """size, in bytes, based on structure

        Returns:
            int: number of bytes needed to store hex in byte form
        """
        if cls._struct_size is None:
            cls._struct_size = calcsize(cls.structure())
        return cls._struct_size

    @classmethod
    def packed_count(cls) -> int:
        """Returns number of objects (e.g. ints) required for packing. or how may objects returned when unpacking
        
        typically this would be len(struct_layout) but that can be wrong if shorthand notation is used
        """
        return len(cls.struct_layout())
    
    @classmethod
    def from_ints(cls, *args):
        """create instance of class from tuple of integers. order and item count must match structure

        Returns:
            HexAdapter instance
        """
        b = pack(cls.structure(), *args)
        return cls.from_bytes(b)

    @classmethod
    def from_bytes(cls, bs: bytes, offset: int = 0, byte_order: str = None):
        """create instance of class from bytes. reads up to struct_size bytes.

        Args:
            bs (bytes): bytes to convert to hex
            offset (int): index to start reading bytes. Defaults to 0.

        Returns:
            HexAdapter instance
        """
        end = offset + cls.struct_size()
        return cls(bs[offset:end].hex())
    
    @classmethod
    def from_hex(cls, hs: str, offset: int = 0):
        """create instance of class from hex string. reads up to (struct_size * 2) characters
        default constructor will take properly sized hex. this is useful for pulling pieces out of larger hex string.

        Args:
            hs (str): string of hex characters
            offset (int, optional): index to start reading characters. Defaults to 0.

        Returns:
            HexAdapter instance
        """
        end = offset + (cls.struct_size() * 2)
        return cls(hs[offset:end])
    
    @classmethod
    def from_keywords(cls, **kwds):
        """create instance of class from keywords or dictionary.
        """
        key = cls.label()
        if key in kwds:
            return cls(kwds[key])
        else:
            raise KeyError(f"Missing keyword {key}")


class ByteAdapter(metaclass=ABCMeta):
    """Used for transforming bytes into other data types like hex strings or integer tuples
    also used for packing and unpacking into/from bytes"""
    _bytes: bytes
    _stored_order: str
    
    # default label that will be returned when an object calls property label
    default_label: str = None
    # default structure that will be returned when an object calls property struct_layout
    default_struct_layout: str = None
    # default byte order returned by struct_order
    default_struct_order: str = str(ByteOrder.NET)
    # default packed count returned by packed_count
    default_packed_count: int = None
    # class level stuff that gets cached on use
    _structures: Dict[str, str] = None
    _struct_sizes: Dict[str, int] = None
    
    def __init__(self, raw: bytes|bytearray|memoryview, byte_order: str = None):
        byte_order = byte_order or self.struct_order()
        if len(raw) != self.struct_size(byte_order=byte_order):
            raise Exception("Invalid byte size")
        if isinstance(raw, bytes):
            self._bytes = raw
        else:
            self._bytes = bytes(raw)
        self._stored_order = byte_order or self.struct_order()
        
    def stored_struct(self) -> str:
        return f"{self._stored_order}{self.struct_layout()}"
    
    @property
    def byte_order(self) -> str:
        """The byte order internal bytes were stored with
        """
        return self._stored_order
    
    def as_bytes(self) -> bytes:
        return self._bytes
    
    def as_ints(self, byte_order: str = None) -> tuple[int]:
        byte_order = byte_order or self._stored_order
        return unpack(self.structure(byte_order=byte_order), self._bytes)

    def as_dict(self) -> dict:
        return {self.label():self.as_hex(), 'byte_order':self._stored_order}
    
    def as_hex(self) -> str:
        """
        Returns:
            str: hex string representing data class
        """
        return self._bytes.hex()
    
    def __str__(self):
        return self._bytes.hex()

    def __repr__(self):
        return self._bytes.hex()
    
    def __hash__(self):
        return hash(self._bytes)
    
    @classmethod
    def structure(cls, byte_order: str = None) -> str:
        """byte order and data layout. see python struct

        Returns:
            str: binary layout in python struct format, including byte order
        """
        if cls._structures is None:
            cls._structures = dict()
        byte_order = byte_order or cls.struct_order()
        return cls._structures.setdefault(byte_order, f"{byte_order}{cls.struct_layout()}")
    
    @classmethod
    def struct_size(cls, byte_order: str = None) -> int:
        """size, in bytes, based on structure

        Returns:
            int: number of bytes needed to store hex in byte form
        """
        if cls._struct_sizes is None:
            cls._struct_sizes = dict()
        byte_order = byte_order or cls.struct_order()
        return cls._struct_sizes.setdefault(byte_order, calcsize(cls.structure(byte_order=byte_order)))

    @classmethod
    def struct_order(cls) -> str:
        """default byte order used in struct definitions. same as python struct package
        Default: ! network / big-endian
        Valid characters: @ = < > !

        Returns:
            str: single character representing byte order
        """
        return cls.default_struct_order
    
    @classmethod
    def struct_layout(cls) -> str:
        """data layout. see python struct

        Returns:
            str: binary layout in python struct format without byte order specification
        """
        return cls.default_struct_layout
    
    @classmethod
    def packed_count(cls) -> int:
        """Returns number of objects (e.g. ints) required for packing. or how may objects returned when unpacking
        
        typically this would be len(struct_layout) but that can be wrong if shorthand notation is used
        """
        return cls.default_packed_count
    
    @classmethod
    def label(cls) -> str:
        """
        Returns:
            str: Unique label used for various automated serialization
        """
        return cls.default_label
    
    @classmethod
    def from_ints(cls, *args, byte_order: str = None):
        """create instance of class from tuple of integers. order and item count must match structure

        Returns:
            ByteAdapter instance
        """
        
        b = pack(cls.structure(byte_order=byte_order), *args)
        return cls.from_bytes(b, byte_order=byte_order)

    @classmethod
    def from_bytes(cls, bs: bytes, offset: int = 0, byte_order: str = None):
        """create instance of class from bytes. reads up to struct_size bytes.

        Args:
            bs (bytes): bytes to convert to hex
            offset (int): index to start reading bytes. Defaults to 0.

        Returns:
            ByteAdapter instance
        """
        byte_order = byte_order or cls.struct_order()
        end = offset + cls.struct_size(byte_order=byte_order)
        return cls(bs[offset:end], byte_order=byte_order)
    
    @classmethod
    def from_hex(cls, hs: str, offset: int = 0, byte_order: str = None):
        """create instance of class from hex string. reads up to (struct_size * 2) characters
        default constructor will take properly sized hex. this is useful for pulling pieces out of larger hex string.

        Args:
            hs (str): string of hex characters
            offset (int, optional): index to start reading characters. Defaults to 0.
            byte_order (str, optional): byte order the hex was encoded with. Use default if not provided. 

        Returns:
            ByteAdapter instance
        """
        end = offset + (cls.struct_size(byte_order=byte_order) * 2)
        return cls(bytes.fromhex(hs[offset:end]), byte_order=byte_order)
    
    @classmethod
    def from_keywords(cls, **kwds):
        """create instance of class from keywords or dictionary.
        """
        key = cls.default_label
        if key not in kwds:
            raise KeyError(f"Missing keyword {key}")
        return cls.from_hex(kwds[key],
                            byte_order=kwds.get('byte_order', None))


class CSVAdapter(metaclass=ABCMeta):
    """Used for converting data class to/from csv file
    """
    def __init__(sefl):
        pass
    
    @abstractmethod
    def as_csv_line(self) -> str:
        """
        Returns:
            str: string representation of data for inserting into csv
        """
        raise NotImplementedError
    
    @classmethod
    @abstractmethod
    def from_csv_line(cls, line: str):
        """create instance from comma seperated values.

        Args:
            line (str): comma separated values. should be consistent with as_csv_line

        Returns:
            HashanaData
        """
        raise NotImplementedError
    
    @classmethod
    @abstractmethod
    def csv_header(cls) -> str:
        """first line to be written in a csv file

        Returns:
            str: csv header
        """
        raise NotImplementedError


class BLOBAdapterB(metaclass=ABCMeta):
    """Used for interacting with binary chunks aka blobs
    """
    _adapter: ByteAdapter|HexAdapter
    _byte_order: str
    _c_structure: str
    _c_struct_size: int
    
    def __init__(self, 
                 adapter: ByteAdapter|HexAdapter, 
                 byte_order: str = None, 
                 structure: str = None, 
                 struct_size: int = None):
        """
        Args:
            adapter (ByteAdapter): adapter for underlying storage. determines how data is packed/unpacked
        """
        if not byte_order in ByteOrder:
            self._byte_order = adapter.struct_order()
        else:
            self._byte_order = byte_order
        self._adapter = adapter
        self._c_structure = structure or self._adapter.structure(byte_order=self._byte_order)
        self._c_struct_size = struct_size or self._adapter.struct_size(byte_order=self._byte_order)

    @property
    def adapter(self) -> ByteAdapter|HexAdapter:
        return self._adapter

    @property
    def byte_order(self) -> str:
        return self._byte_order

    def structure(self) -> str:
        """byte order and data layout of individual items (i.e. underlying adapter). see python struct

        Returns:
            str: binary layout in python struct format, including byte order
        """
        return self._c_structure    

    def struct_size(self) -> int:
        """size, in bytes, based on underlying adapter's structure

        Returns:
            int: number of bytes needed to store in byte form
        """
        return self._c_struct_size

    def items(self) -> Iterator[ByteAdapter]:
        """enumerates items contained in the BLOB

        Yields:
            Iterator[ByteAdapter]: ByteAdapter items converted from underlying binary data
        """
        stepping = self.struct_size()
        ba = bytearray(stepping * 64 * 1024)
        mv = memoryview(ba)
        for sz in self.slice_into(mv):
            for i in range(0, sz, stepping):
                yield self._adapter.from_bytes(mv, i, byte_order=self._byte_order)
                #yield self._adapter(mv[i:i+stepping], byte_order=self._byte_order)
    
    def slices(self, stepping: int = 1) -> Iterator[memoryview]:
        """enumerates bytes of data at a time

        Args:
            stepping (int, optional): positive integer representing number of objects in slice.
            slice will be (stepping * struct_size) bytes. Defaults to 1. Less than 1 will be ignored.

        Yields:
            Iterator[memoryview]: read only memory view of slice
        """
        stepping = max(stepping,1) * self.struct_size()
        ba = bytearray(stepping)
        mv = memoryview(ba)
        for sz in self.slice_into(mv):
            yield mv[0:sz].toreadonly()
    
    def add_adapted(self, adapted: ByteAdapter) -> bool:
        """Adds an item that matches the underlying adapter type
        """
        return self.add_bytes(adapted.as_bytes()) > 0
    
    @abstractmethod
    def as_tuples(self) -> Iterator[tuple]:
        """unpacks each item into a tuple

        Yields:
            Iterator[tuple]: tuple of values for each item in BLOB
        """
        raise NotImplementedError
    
    @abstractmethod
    def slice_into(self, buffer) -> Iterable[int]:
        """Copy data into buffer. Copies buffer sized chunks until all data copied.

        Args:
            buffer: Writable buffer to copy into

        Yields:
            Iterator[int]: number of bytes copied
        """
        raise NotImplementedError
    
    @abstractmethod
    def add_bytes(self, data: bytes) -> int:
        """inserts bytes into underlying storage

        Args:
            data (bytes): bytes to copy

        Returns:
            int: number of bytes copied
        """
        raise NotImplementedError
    
    @abstractmethod
    def clear(self):
        """resets underlying storage"""
        raise NotImplementedError


class GroupAdapter(HexAdapter, SQLAdapter, TableAdapter, CSVAdapter, metaclass=ABCMeta):
    """combines multiple data types for use in database/csv
    """
    _struct_layout: str = None
    _valid_keys: set = None
    
    def __init__(self, hexed: str):
        super().__init__(hexed)
        super(HexAdapter, self).__init__()
        super(TableAdapter, self).__init__()
    
    @classmethod
    def valid_keys(cls) -> list[str]:
        """
        Returns:
            list[str]: list of data type labels in same consistent order as data_types
        """
        if cls._valid_keys is None:
            cls._valid_keys = [dt.label() for dt in cls.data_types()]
        return cls._valid_keys
    
    @classmethod
    def from_pieces(cls, **kwds):
        """creates instance of class from individual hex items

        Returns:
            GroupAdapter instance
        """
        hexes = []
        for key in cls.valid_keys():
            if key in kwds:
                hexes.append(cast(HexAdapter, kwds[key]).as_hex())
            else:
                raise KeyError(f"Missing keyword: {key}")
        return cls(''.join(hexes))
    
    def as_pieces(self) -> tuple[HexAdapter]:
        """convert to individual hex items

        Returns:
            tuple[HexAdapter]: items in same order as data_types
        """
        offset = 0
        ret = []
        for dt in self.data_types():
            end = offset + (cast(HexAdapter, dt).struct_size() * 2)
            ret.append(cast(HexAdapter,dt).from_hex(self.as_hex()[offset:end]))
            offset = end
        return tuple(ret)
    
    @classmethod
    def from_keywords(cls, **kwds):
        """create instance of class from keywords or dictionary.
        """
        hexes = []
        for key in cls.valid_keys():
            if key in kwds:
                hexes.append(kwds[key])
            else:
                raise KeyError(f"Missing keyword: {key}")
        return cls(''.join(hexes))
    
    # HexAdapter
    @classmethod
    def struct_layout(cls) -> str:
        """combined data layout of all items in group

        Returns:
            str: binary layout in python struct format without byte order specification
        """
        if cls._struct_layout is None:
            cls._struct_layout = ''.join(cast(HexAdapter,h).struct_layout() for h in cls.data_types())
        return cls._struct_layout
    
    # HexAdapter
    def as_dict(self) -> dict:
        ret = dict()
        offset = 0
        for dt in self.data_types():
            end = offset + (cast(HexAdapter, dt).struct_size() * 2)
            ret[dt.label()] = self.as_hex()[offset:end]
            offset = end
        return ret
    
    # TableAdapter        
    @classmethod
    def sql_indexes(cls)  -> dict[str,tuple[str]]:
        idxs = dict()
        for dt in cls.data_types():
            k = f"IDX_{dt.label().upper()}"
            v = tuple(dt.sql_columns().keys())
            idxs[k] = v
        return idxs

    # TableAdapter
    @classmethod
    def sql_table_columns(cls) -> Iterable[str]:
        tc = list()
        tc.append('rowid INTEGER PRIMARY KEY NOT NULL')
        for dtype in cls.data_types():
            for k,v in dtype.sql_columns().items():
                tc.append(f"{k} {v}")
        return tc
    
    # SQLAdapter
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        cols = dict()
        for t in cls.data_types():
            cols = cols | t.sql_columns()
        return cols
    
    # SQLAdapter
    def as_sql_values(self) -> tuple[int]:
        return self.as_ints()
    
    # SQLAdapter
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)
    
    # CSVAdapter
    def as_csv_line(self) -> str:
        offset = 0
        itms = list()
        for dt in self.data_types():
            end = offset + (cast(HexAdapter, dt).struct_size() * 2)
            itms.append(self.as_hex()[offset:end])
            offset = end
        return ','.join(itms) + '\n'
    
    # CSVAdapter
    @classmethod
    def from_csv_line(cls, line: str):
        return cls(line.strip().replace(',',''))
    
    # CSVAdapter
    @classmethod
    def csv_header(cls) -> str:
        return ','.join(h.label() for h in cls.data_types()) + '\n'


class GroupAdapterB(ByteAdapter, SQLAdapter, TableAdapter, CSVAdapter, metaclass=ABCMeta):
    """combines multiple data types for use in database/csv
    """
    
    _struct_layout: str = None
    _valid_keys: set = None
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
        super(ByteAdapter, self).__init__()
        super(TableAdapter, self).__init__()
    
    @classmethod
    def valid_keys(cls) -> list[str]:
        """
        Returns:
            list[str]: list of data type labels in same consistent order as data_types
        """
        if cls._valid_keys is None:
            cls._valid_keys = [dt.label() for dt in cls.data_types()]
        return cls._valid_keys
    
    @classmethod
    def from_rds_row(cls, **kwds):
        """create an instance from a dictionary row of RDS dataset
        """
        return cls.from_keywords(**kwds)
    
    # ByteAdapter
    @classmethod
    def from_keywords(cls, **kwds):
        """create instance of class from keywords or dictionary.
        values should be the repr value of the expected class
        """
        byte_order = kwds.get('byte_order', None)
        intlist = list()
        for c in cls.data_types():
            c = cast(ByteAdapter, c)
            kwdobj = kwds.get(c.label(), None)
            
            if isinstance(kwdobj, int):
                o = c.from_ints(kwdobj, byte_order=byte_order)
            elif isinstance(kwdobj, str):
                o = c.from_hex(kwdobj, byte_order=byte_order)
            elif isinstance(kwdobj, bytes):
                o = c.from_bytes(kwdobj, byte_order=byte_order)
            elif isinstance(kwdobj, ByteAdapter):
                o = kwdobj
            else:
                raise ValueError(f"{c.label()} must be of type int, str, bytes, or ByteAdapter")
            
            intlist.extend(o.as_ints())
        return cls.from_ints(*intlist, byte_order=byte_order)
    
    @classmethod
    def from_objs(cls, *args, byte_order: str = None):
        """Create an instance from individual parts
        
        Args:
            positional arguments should be instances of each object in group. order should match data_types
            byte_order (str, optional): byte order of all items. uses default if None
        """
        valid = list(cls.data_types())
        if len(valid) > len(args):
            raise TypeError(f"Excpected {len(valid)} objects but only got {len(args)}")
        intlist = []
        for i in range(0, len(valid)):
            if not isinstance(args[i], valid[i]):
                raise TypeError(f"Argument {i} should be instance of {valid[i].__name__} \
                    but got {type(args[i]).__name__}")
            o: ByteAdapter = args[i]
            intlist.extend(o.as_ints())
        return cls.from_ints(*intlist, byte_order=byte_order)
    
    def as_objs(self) -> Iterator[ByteAdapter]:
        """Enumerates objects contained in group
        
        The default will fail if the underlying data is packed and the total size is not the same size as
          all individual item sizes added together.
          This will typically happen in native byte order: ByteOrder.NATIVE or '@'
        """
        idx = 0
        for cls in self.data_types():
            cls = cast(ByteAdapter, cls)
            end = idx + cls.struct_size(byte_order=self._stored_order)
            yield cls(self._bytes[idx:end], byte_order=self._stored_order)
            idx = end
    
    # ByteAdapter
    @classmethod
    def struct_layout(cls) -> str:
        """combined data layout of all items in group

        Returns:
            str: binary layout in python struct format without byte order specification
        """
        if cls._struct_layout is None:
            cls._struct_layout = ''.join(cast(ByteAdapter,h).struct_layout() for h in cls.data_types())
        return cls._struct_layout
    
    # ByteAdapter
    def as_dict(self) -> dict:
        ret = dict()
        ret['byte_order'] = self._stored_order
        for o in self.as_objs():
            ret[o.label()] = o.as_hex()
        return ret
    
    # TableAdapter        
    @classmethod
    def sql_indexes(cls)  -> dict[str,tuple[str]]:
        idxs = dict()
        for dt in cls.data_types():
            k = f"IDX_{dt.label().upper()}"
            v = tuple(dt.sql_columns().keys())
            idxs[k] = v
        return idxs

    # TableAdapter
    @classmethod
    def sql_table_columns(cls) -> Iterable[str]:
        tc = list()
        tc.append('rowid INTEGER PRIMARY KEY NOT NULL')
        for dtype in cls.data_types():
            for k,v in dtype.sql_columns().items():
                tc.append(f"{k} {v}")
        return tc
    
    # SQLAdapter
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        cols = dict()
        for t in cls.data_types():
            cols = cols | t.sql_columns()
        return cols
    
    # SQLAdapter
    def as_sql_values(self) -> tuple[int]:
        return self.as_ints()
    
    # SQLAdapter
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)
    
    # CSVAdapter
    def as_csv_line(self) -> str:
        return ','.join([o.as_hex() for o in self.as_objs()])
    
    # CSVAdapter
    @classmethod
    def from_csv_line(cls, line: str, byte_order: str = None):
        return cls.from_hex(line.strip().replace(',',''), byte_order=byte_order)
    
    # CSVAdapter
    @classmethod
    def csv_header(cls) -> str:
        return ','.join(h.label() for h in cls.data_types()) + '\n'


if __name__ == "__main__":
    pass