from collections.abc import Iterable, Iterator
from struct import iter_unpack
from os import remove

from .adapters import HexAdapter, SQLAdapter, BLOBAdapter, CSVAdapter
from .wrapped import BasicCSV
from .exceptions import InvalidHexError, InvalidIPAddressError, InvalidAdapterError


class IP6(HexAdapter, SQLAdapter):
    """IPv6 Hex Adapter
    """
    def __init__(self, hexed: str):
        if hexed is None:
            raise InvalidHexError("Invalid Address")
        super().__init__(hexed)
    
    @classmethod
    def struct_layout(cls) -> str:
        return "qq"

    @classmethod
    def label(cls) -> str:
        return "ipv6"
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(ipv6_0=SQLAdapter.INT_DEFAULT,
                    ipv6_1=SQLAdapter.INT_DEFAULT)
    
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)
    
    @staticmethod
    def split_address(address: str) -> tuple[str]:
        """Splits IPv6 address into list representing pieces of address as shorts.

        Args:
            address (str): IPv6 address in string/text format. Can be shortened form. must be only address (no port)

        Raises:
            InvalidIPAddressError: Invalid string representation of an IP6 Address.

        Returns:
            tuple[str]: list of 8 strings representing pieces of address. Strings can be empty (meaning 0 or 0000)
        """
        if ":::" in address:
            raise InvalidIPAddressError("Invalid address: too many colons")
        split1 = address.strip().split('::')
        if len(split1) > 2:
            raise InvalidIPAddressError("Invalid address: multiple instances of ::")
        elif len(split1) == 1:
            h = split1[0].split(':')
            if len(h) != 8:
                raise InvalidIPAddressError("Invalid address: not wide enough")
        else:
            h = split1[0].split(':')
            h2 = split1[1].split(':')
            total = len(h) + len(h2)
            if total > 8:
                raise InvalidIPAddressError("Invalid address: too wide")
            h.extend('' for x in range(0, (8 - total)))
            h.extend(h2)
        return h
    
    @classmethod
    def from_address(cls, address: str):
        """creates instance from address. uses split_address to parse addresses.

        Args:
            address (str): ipv6 address in text/string format
        """
        h = IP6.split_address(address)
        return cls(f"{h[0]:0>4}{h[1]:0>4}{h[2]:0>4}{h[3]:0>4}{h[4]:0>4}{h[5]:0>4}{h[6]:0>4}{h[7]:0>4}")

class MAC(HexAdapter, SQLAdapter):
    """MAC address hex adapter
    """
    def __init__(self, hexed: str):
        if hexed is None:
            raise InvalidHexError("Invalid Address")
        super().__init__(hexed.replace(':',''))
    
    @classmethod
    def struct_layout(cls) -> str:
        return "hhh"
    
    @classmethod
    def label(cls) -> str:
        return "macaddr"

    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(macaddr_0=SQLAdapter.INT_DEFAULT,
                    macaddr_1=SQLAdapter.INT_DEFAULT,
                    macaddr_2=SQLAdapter.INT_DEFAULT)
    
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)

class CRC32(HexAdapter, SQLAdapter):
    """CRC32 Hex Adapter
    """
    def __init__(self, hexed: str):
        if hexed is None:
            raise InvalidHexError("Invalid digest")
        super().__init__(hexed)
    
    @classmethod
    def struct_layout(cls) -> str:
        return "i"
    
    @classmethod
    def label(cls) -> str:
        return "crc32"
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(crc32=SQLAdapter.INT_DEFAULT)
    
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)

class MD5(HexAdapter, SQLAdapter):
    """MD5 Hex/SQL Adapter"""
    def __init__(self, hexed: str):
        if hexed is None:
            raise InvalidHexError("Invalid digest")
        super().__init__(hexed)
        super(HexAdapter, self).__init__()
    
    @classmethod
    def struct_layout(cls) -> str:
        return "iiii"
    
    @classmethod
    def label(cls) -> str:
        return "md5"
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(md5_0=SQLAdapter.INT_DEFAULT,
                    md5_1=SQLAdapter.INT_DEFAULT,
                    md5_2=SQLAdapter.INT_DEFAULT,
                    md5_3=SQLAdapter.INT_DEFAULT)
    
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)
    
class SHA1(HexAdapter, SQLAdapter):
    """SHA1 Hex/SQL Adapter"""
    def __init__(self, hexed: str):
        if hexed is None:
            raise InvalidHexError("Invalid digest")
        super().__init__(hexed)
        super(HexAdapter, self).__init__()
    
    @classmethod
    def struct_layout(cls) -> str:
        return "iiiii"
    
    @classmethod
    def label(cls) -> str:
        return "sha1"
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(sha1_0=SQLAdapter.INT_DEFAULT,
                    sha1_1=SQLAdapter.INT_DEFAULT,
                    sha1_2=SQLAdapter.INT_DEFAULT,
                    sha1_3=SQLAdapter.INT_DEFAULT,
                    sha1_4=SQLAdapter.INT_DEFAULT)
    
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)

class SHA224(HexAdapter, SQLAdapter):
    """SHA224 Hex/SQL Adapter"""
    def __init__(self, hexed: str):
        if hexed is None:
            raise InvalidHexError("Invalid digest")
        super().__init__(hexed)
        super(HexAdapter, self).__init__()
    
    @classmethod
    def struct_layout(cls) -> str:
        return "qqqi"
    
    @classmethod
    def label(cls) -> str:
        return "sha224"
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"

    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(sha224_0=SQLAdapter.INT_DEFAULT,
                    sha224_1=SQLAdapter.INT_DEFAULT,
                    sha224_2=SQLAdapter.INT_DEFAULT,
                    sha224_3=SQLAdapter.INT_DEFAULT)
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()

    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)

class SHA256(HexAdapter, SQLAdapter):
    """SHA256 Hex/SQL Adapter"""
    def __init__(self, hexed: str):
        if hexed is None:
            raise InvalidHexError("Invalid digest")
        super().__init__(hexed)
        super(HexAdapter, self).__init__()
    
    @classmethod
    def struct_layout(cls) -> str:
        return "qqqq"
    
    @classmethod
    def label(cls) -> str:
        return "sha256"
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"

    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(sha256_0=SQLAdapter.INT_DEFAULT,
                    sha256_1=SQLAdapter.INT_DEFAULT,
                    sha256_2=SQLAdapter.INT_DEFAULT,
                    sha256_3=SQLAdapter.INT_DEFAULT)
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()

    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)

class SHA384(HexAdapter, SQLAdapter):
    """SHA384 Hex/SQL Adapter"""
    def __init__(self, hexed: str):
        if hexed is None:
            raise InvalidHexError("Invalid digest")
        super().__init__(hexed)
        super(HexAdapter, self).__init__()
    
    @classmethod
    def struct_layout(cls) -> str:
        return "qqqqqq"
    
    @classmethod
    def label(cls) -> str:
        return "sha384"
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"

    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(sha384_0=SQLAdapter.INT_DEFAULT,
                    sha384_1=SQLAdapter.INT_DEFAULT,
                    sha384_2=SQLAdapter.INT_DEFAULT,
                    sha384_3=SQLAdapter.INT_DEFAULT,
                    sha384_4=SQLAdapter.INT_DEFAULT,
                    sha384_5=SQLAdapter.INT_DEFAULT)
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()

    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)

class SHA512(HexAdapter, SQLAdapter):
    """SHA512 Hex/SQL Adapter"""
    def __init__(self, hexed: str):
        if hexed is None:
            raise InvalidHexError("Invalid digest")
        super().__init__(hexed)
        super(HexAdapter, self).__init__()
    
    @classmethod
    def struct_layout(cls) -> str:
        return "qqqqqqqq"
    
    @classmethod
    def label(cls) -> str:
        return "sha512"
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"

    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(sha512_0=SQLAdapter.INT_DEFAULT,
                    sha512_1=SQLAdapter.INT_DEFAULT,
                    sha512_2=SQLAdapter.INT_DEFAULT,
                    sha512_3=SQLAdapter.INT_DEFAULT,
                    sha512_4=SQLAdapter.INT_DEFAULT,
                    sha512_5=SQLAdapter.INT_DEFAULT,
                    sha512_6=SQLAdapter.INT_DEFAULT,
                    sha512_7=SQLAdapter.INT_DEFAULT)
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()

    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)

class FileSize(HexAdapter, SQLAdapter):
    """Simple Hex/SQL Adapter for length/size/bytes"""
    def __init__(self, hexed: str):
        if hexed is None:
            raise InvalidHexError("Invalid size")
        super().__init__(hexed)
        super(HexAdapter, self).__init__()
    
    @classmethod
    def struct_layout(cls) -> str:
        return "q"
    
    @classmethod
    def label(cls) -> str:
        return "file_size"
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @classmethod
    def sql_table_name(cls) -> str:
        return "hashana"
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(file_size="INTEGER DEFAULT -1 NOT NULL")

    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)

class HBuffer(BLOBAdapter):
    """Buffer to store multiple HexAdapter items in efficient binary format.

    Raises:
        IndexError: invalid index specified

    """
    _buffer: bytearray
    _memview: memoryview
    _index: int
    
    def __init__(self, hex_adapter: HexAdapter, size: int = 4096):
        """
        Args:
            hex_adapter (HexAdapter): adapter for underlying storage. determines how data is packed/unpacked
            size (int, optional): Max number of items that can be stored in buffer. Defaults to 4096.
        """
        super().__init__(hex_adapter)
        self._index = 0
        self._buffer = bytearray(max(1, size) * self.struct_size())
        self._memview = memoryview(self._buffer)
    
    def slice_into(self, buffer) -> Iterator[int]:
        stepping = len(buffer)
        for i in range(0, self._index, stepping):
            w = min(stepping, self._index - i)
            buffer[0:w] = self._memview[i:i+w]
            yield w
    
    def add_bytes(self, data: bytes) -> int:
        ret = len(data)
        end = self._index + ret
        self._memview[self._index:end] = data
        self._index = end
        return ret
    
    def snapshot(self) -> memoryview:
        """
        Returns:
            memoryview: read only snapshot of memory contents
        """
        return self._memview[0:self._index].toreadonly()
    
    def as_tuples(self) -> Iterator[tuple[int]]:
        for tpl in iter_unpack(self._hex_adapter.structure(), self._memview[0:self._index]):
            yield tpl
    
    def clear(self):
        """resets index. does not clear bytes or change size of buffer
        """
        self._index = 0
    
    @property
    def full(self) -> bool:
        """
        Returns:
            bool: True if no more items can be added to buffer. otherwise False
        """
        return (len(self._buffer) - self._index) >= self.struct_size()

    @property
    def hex_adapter(self) -> HexAdapter:
        """Hex Adapter for individual items in buffer
        """
        return self._hex_adapter
    
    @property
    def size(self) -> int:
        """
        Returns:
            int: max items that can be contained (packed) inside buffer
        """
        return int(len(self._buffer) / self.struct_size())
    
    def __len__(self) -> int:
        """
        Returns:
            int: number of items in buffer. total size of buffer in bytes is len * hex_adapter.struct_size()
        """
        return int(self._index / self.struct_size())
    
    def __getitem__(self, key: int) -> HexAdapter:
        """index support

        Args:
            key (int): index of item to get

        Raises:
            IndexError: invalid index specified

        Returns:
            HexAdapter: hex item
        """
        if not isinstance(key, int):
            raise IndexError("Index must be int type")
        if key > len(self):
            raise IndexError("Index out of range")
        stepping = self.struct_size()
        i = key * stepping
        return self._hex_adapter(self._memview[i:i+stepping].hex())

class BLOBFile(BLOBAdapter):
    """store and read hex items in a binary file. space efficient but slow to read with many objects due to no index
    """
    _file: str
    
    def __init__(self, hex_adapter: HexAdapter, file_path: str):
        """
        Args:
            hex_adapter (HexAdapter): adapter for underlying storage. determines how data is packed/unpacked
            file_path (str): path to file where binary data will be stored/read
        """
        self._file = file_path
        super().__init__(hex_adapter)
    
    def add_many(self, blobs: Iterable[bytes]) -> int:
        """add multiple items to file

        Args:
            blobs (Iterable[bytes]): bytes to be written to file

        Returns:
            int: total number of bytes written
        """
        total = 0
        with open(self._file, 'ba') as f:
            for data in blobs:
                total += f.write(data)
        return total
        
    def slice_into(self, buffer) -> Iterator[int]:
        with open(self._file, 'rb', buffering=0) as f:
            while n := f.readinto(buffer):
                yield n
    
    def blobs(self, buff_size: int = 4096) -> Iterator[memoryview]:
        """enumerate chunks of file into memoryview objects
        
        Args:
            buff_size (int, optional): number of items to copy at a time. total size will be buff_size * struct_size
            Defaults to 4096. Numbers less than 1 will be treated as 1.

        Yields:
            Iterator[memoryview]: read only memory snapshots
        """
        stepping = self.struct_size()
        ba = bytearray(stepping * max(buff_size,1))
        mv = memoryview(ba)
        for sz in self.slice_into(mv):
            yield mv[0:sz].toreadonly()
    
    def as_tuples(self) -> Iterator[tuple[int]]:
        stepping = self.struct_size()
        ba = bytearray(stepping * 1024)
        mv = memoryview(ba)
        for sz in self.slice_into(mv):
            for tpl in iter_unpack(self._hex_adapter.structure(), mv[0:sz]):
                yield tpl
    
    def add_bytes(self, data: bytes) -> int:
        """insert bytes to end of file. basic wrapper of filehandle.write(data)

        Args:
            data (bytes): bytes representing hexed item(s)

        Returns:
            int: number of bytes written to file
        """
        with open(self._file, 'ba') as f:
            return f.write(data)
    
    def clear(self):
        """deletes the file
        """
        remove(self._file)
                        
class AdaptedCSV(BasicCSV):
    """Read/writes CSV file. Requires items to implement CSVAdapter
    """
    _csv_adapter = None
    
    def __init__(self, path: str, csv_adapter: CSVAdapter):
        """
        Args:
            path (str): path to CSV file where data will be read/write
            csv_adapter (CSVAdapter): adapter class to convert to/from csv lines
        """
        if not issubclass(csv_adapter, CSVAdapter):
            raise InvalidAdapterError("Adapter must support CSVAdapter interface")
        super().__init__(path)
        self._csv_adapter = csv_adapter
        
    def insert_adapted(self, data: Iterator[CSVAdapter]):
        """insert items into CSV. clobbers existing items.

        Args:
            data (Iterator[CSVAdapter]): items to insert. must support CSVAdapter interface
        """
        with open(self.path, 'wt') as f:
            f.write(self._csv_adapter.csv_header())
            for d in data:
                f.write(d.as_csv_line())
            
    def enum_adapted(self) -> Iterator[CSVAdapter]:
        """enumerates items in the csv file

        Yields:
            Iterator[CSVAdapter]: items converted using CSVAdapter
        """
        for line in self.enum_lines():
            yield self._csv_adapter.from_csv_line(line)

if __name__ == "__main__":
    pass