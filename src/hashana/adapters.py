from abc import abstractmethod, ABCMeta
from collections.abc import Iterable, Iterator
from struct import pack, unpack, calcsize
from typing import cast


class SQLAdapter(metaclass=ABCMeta):
    """Abstract class/interface for interacting with data in sqlite3
    """
    
    INT_DEFAULT: str = "INTEGER DEFAULT NULL"
    
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
    @abstractmethod
    def label(cls) -> str:
        """
        Returns:
            str: Unique label used for various automated serialization
        """
        raise NotImplementedError
    
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
    @abstractmethod
    def sql_table_name(cls) -> str:
        """
        Returns:
            str: table name used for generating sql statements
        """
        raise NotImplementedError
    
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
    
class TableAdapter(SQLAdapter, metaclass=ABCMeta):
    """Abstract class/interface for creating tables and indexes in a sqlite3 database
    """
    
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
        return {self.label():self.hexed}
    
    def __str__(self):
        return self._hexed

    def __repr__(self):
        return self._hexed
    
    def __hash__(self):
        return hash(self._hexed)
    
    @property
    def hexed(self) -> str:
        """
        Returns:
            str: hex string representing data class
        """
        return self._hexed
    
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
        Default: ! (network, big-endian)
        Valid characters: @ = < > !

        Returns:
            str: single character representing byte order
        """
        return "!"
    
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
    def integer_count(cls) -> int:
        """integer objects when converting to/from structure.
            by default this is just the length of struct_layout, but that assumes no shorthand notation.

        Returns:
            int: number of python integer objects required/produced
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
    def from_bytes(cls, bs: bytes, offset: int = 0):
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
            raise ValueError(f"Missing keyword {key}")

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

class BLOBAdapter(metaclass=ABCMeta):
    """Used for interacting with binary chunks aka blobs
    """
    _hex_adapter: HexAdapter
    
    def __init__(self, hex_adapter: HexAdapter):
        """
        Args:
            hex_adapter (HexAdapter): adapter for underlying storage. determines how data is packed/unpacked
        """
        self._hex_adapter = hex_adapter

    def structure(self) -> str:
        """byte order and data layout of individual items (i.e. underlying hex adapter). see python struct

        Returns:
            str: binary layout in python struct format, including byte order"""
        return self._hex_adapter.structure()    

    def struct_size(self) -> int:
        """size, in bytes, based on underlying hex adapter's structure

        Returns:
            int: number of bytes needed to store hex in byte form
        """
        return self._hex_adapter.struct_size()

    def items(self) -> Iterator[HexAdapter]:
        """enumerates hex items contained in the BLOB

        Yields:
            Iterator[HexAdapter]: HexAdapter items converted from underlying binary data
        """
        stepping = self.struct_size()
        ba = bytearray(stepping * 1024)
        mv = memoryview(ba)
        for sz in self.slice_into(mv):
            for i in range(0, sz, stepping):
                yield self._hex_adapter(mv[i:i+stepping].hex())
    
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
    
    def add_hex(self, hex: HexAdapter) -> int:
        """adds a hex item to underlying BLOB

        Args:
            hex (HexAdapter): item to add

        Returns:
            int: number of bytes added to BLOB
        """
        return self.add_bytes(hex.as_bytes())
    
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

class GroupAdapter(HexAdapter, TableAdapter, CSVAdapter, metaclass=ABCMeta):
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
                hexes.append(cast(HexAdapter, kwds[key]).hexed)
            else:
                raise ValueError(f"Missing keyword: {key}")
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
            ret.append(dt(self._hexed[offset:end]))
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
                raise ValueError(f"Missing keyword: {key}")
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
            ret[dt.label()] = self._hexed[offset:end]
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
            itms.append(self._hexed[offset:end])
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

if __name__ == "__main__":
    pass