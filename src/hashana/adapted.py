from collections.abc import Iterable, Iterator
from struct import iter_unpack, unpack, pack
from itertools import groupby
from multiprocessing.shared_memory import SharedMemory
from os import remove

from .adapters import HexAdapter, SQLAdapter, ByteAdapter, BLOBAdapterB, ByteOrder
from .exceptions import InvalidHexError, InvalidIPAddressError, InvalidAdapterError


class IP4B(ByteAdapter, SQLAdapter):
    """IPv4 Adapter
    """

    default_label: str = "ipv4"
    default_struct_layout: str = "I"
    default_packed_count: int = 1
    
    default_table_name: str = "hashana"
    
    address_str: str
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
        self.address_str = None
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @property
    def address(self):
        if self.address_str is None:
           self.address_str = self.as_address()
        return self.address_str
    
    def as_address(self) -> str:
        return '.'.join(str(z) for z in unpack("BBBB", self._bytes))
    
    def as_bits(self) -> str:
        x = unpack('>I', self._bytes)[0]
        x = f"{x:b}"
        zlen = 32 - len(x)
        return f"{'0' * zlen}{x}"
    
    @classmethod
    def from_address(cls, address_str: str, byte_order: str = None):
        octs = address_str.split('.')
        if len(octs) != 4:
            raise InvalidIPAddressError(f"{address_str} is not a valid IPV4 address")
        z = pack("BBBB", *[int(x) for x in octs])
        c = cls(z, byte_order=byte_order)
        c.address_str = address_str
        return c
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(ipv4=SQLAdapter.INT_DEFAULT)
    
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)


class IP6B(ByteAdapter, SQLAdapter):
    """IPv6 Adapter
    """
    default_label: str = "ipv6"
    default_struct_layout: str = "qq"
    default_packed_count: int = 2
    
    default_table_name: str = "hashana"
    
    address_str: str
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
        self.address_str = None
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @property
    def address(self):
        if self.address_str is None:
           self.address_str = self.as_address()
        return self.address_str
    
    def as_address(self, squash: bool = False):
        if self.byte_order not in ByteOrder:
            return None
        il = unpack(f"{self.byte_order}8H", self._bytes)
        addr = ["{:x}".format(i) for i in il]
        if squash:
            addr = self.flatten_address(addr)
        else:
            addr = ':'.join(addr)
        return addr
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(ipv6_0=SQLAdapter.INT_DEFAULT,
                    ipv6_1=SQLAdapter.INT_DEFAULT)
    
    @staticmethod
    def flatten_address(hex_pieces: list[str]) -> str:
        sqshd = list()
        longest = 1
        for k,g in groupby(hex_pieces, key=lambda x: x=='0'):
            if k:
                zl = list(g)
                sqshd.append(zl)
                if len(zl) > longest:
                    longest = len(zl)
            else:
                sqshd.extend(list(g))
        
        if longest == 8:
            return "::0"
        
        i = 0
        mx = len(sqshd)
        while i < mx:
            if isinstance(sqshd[i], list):
                g = sqshd.pop(i)
                mx -= 1
                if len(g) == 1:
                    sqshd.insert(i, g[0])
                    i += 1
                    mx += 1
                elif len(g) == longest:
                    sqshd.insert(i, '')
                    longest = 0
                    i += 1
                    mx += 1
                else:
                    for h in g:
                        sqshd.insert(i, h)
                        i += 1
                        mx += 1
            i += 1
        if sqshd[0] == '':
            sqshd.insert(0, '')
        elif sqshd[-1] == '':
            sqshd.append('')
        return ':'.join(sqshd)
    
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
        
        h = split1[0].split(':')
        if len(split1) == 1:
            if len(h) != 8:
                raise InvalidIPAddressError("Invalid address: not wide enough")
        else:
            h2 = split1[1].split(':')
            total = len(h) + len(h2)
            if total > 8:
                raise InvalidIPAddressError("Invalid address: too wide. Was the port included?")
            elif total < 8:
                h.extend('' for x in range(0, (8 - total)))
            h.extend(h2)
        return h
    
    @classmethod
    def from_address(cls, address: str):
        """creates instance from address. uses split_address to parse addresses.

        Args:
            address (str): ipv6 address in text/string format
        """
        h = cls.split_address(address)
        ip6 = cls.from_hex(f"{h[0]:0>4}{h[1]:0>4}{h[2]:0>4}{h[3]:0>4}{h[4]:0>4}{h[5]:0>4}{h[6]:0>4}{h[7]:0>4}")
        ip6.address_str = address
        return ip6


class MACB(ByteAdapter, SQLAdapter):
    """MAC address hex adapter
    """
    
    default_label: str = "macaddr"
    default_struct_layout: str = "hhh"
    default_packed_count: int = 3
    
    default_table_name: str = "hashana"
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(macaddr_0=SQLAdapter.INT_DEFAULT,
                    macaddr_1=SQLAdapter.INT_DEFAULT,
                    macaddr_2=SQLAdapter.INT_DEFAULT)
    
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)


class CRC32B(ByteAdapter, SQLAdapter):
    """CRC32 Hex Adapter
    """
    default_label: str = "crc32"
    default_struct_layout: str = "i"
    default_packed_count: int = 1
    
    default_table_name: str = "hashana"
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(crc32=SQLAdapter.INT_DEFAULT)
    
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)


class MD5B(ByteAdapter, SQLAdapter):
    """MD5 Hex/SQL Adapter"""
    
    default_label: str = "md5"
    default_struct_layout: str = "iiii"
    default_packed_count: int = 4
    
    default_table_name: str = "hashana"
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(md5_0=SQLAdapter.INT_DEFAULT,
                    md5_1=SQLAdapter.INT_DEFAULT,
                    md5_2=SQLAdapter.INT_DEFAULT,
                    md5_3=SQLAdapter.INT_DEFAULT)
    
    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)


class SHA1B(ByteAdapter, SQLAdapter):
    default_label: str = "sha1"
    default_struct_layout: str = "iiiii"
    default_packed_count: int = 5
    
    default_table_name: str = "hashana"
    
    """SHA1 Hex/SQL Adapter"""
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
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
    

class SHA224B(ByteAdapter, SQLAdapter):
    """SHA224 Hex/SQL Adapter"""
    default_label: str = "sha224"
    default_struct_layout: str = "qqqi"
    default_packed_count: int = 4
    
    default_table_name: str = "hashana"
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
    
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


class SHA256B(ByteAdapter, SQLAdapter):
    """SHA256 Hex/SQL Adapter"""
    
    default_label: str = "sha256"
    default_struct_layout: str = "qqqq"
    default_packed_count: int = 4
    
    default_table_name: str = "hashana"
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
    
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


class SHA384B(ByteAdapter, SQLAdapter):
    """SHA384 Hex/SQL Adapter"""
    default_label: str = "sha384"
    default_struct_layout: str = "qqqqqq"
    default_packed_count: int = 6
    
    default_table_name: str = "hashana"
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
    
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


class SHA512B(ByteAdapter, SQLAdapter):
    """SHA512 Hex/SQL Adapter"""
    
    default_label: str = "sha512"
    default_struct_layout: str = "qqqqqqqq"
    default_packed_count: int = 4
    
    default_table_name: str = "hashana"
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
    
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


class FileSizeB(ByteAdapter, SQLAdapter):
    default_label: str = "file_size"
    default_struct_layout: str = "q"
    default_packed_count: int = 1
    
    default_table_name: str = "hashana"
    
    """Simple Adapter for length/size/bytes"""
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)
    
    def as_sql_values(self) -> tuple:
        return self.as_ints()
    
    @classmethod
    def sql_columns(cls) -> dict[str,str]:
        return dict(file_size="INTEGER DEFAULT -1 NOT NULL")

    @classmethod
    def from_sql_values(cls, *args):
        return cls.from_ints(*args)
    
    
class HBufferB(BLOBAdapterB):
    """Buffer to store multiple items in efficient binary format.

    Raises:
        IndexError: invalid index specified

    """
    _buffer: bytearray
    _memview: memoryview
    _index: int
    _full_threshold = int
    
    def __init__(self,
                 adapter: ByteAdapter|HexAdapter, 
                 byte_order: str = None,
                 structure: str = None, 
                 struct_size: int = None, 
                 size: int = 4096):
        """
        Args:
            adapter (ByteAdapter): adapter for underlying storage. determines how data is packed/unpacked
            size (int, optional): Max number of items that can be stored in buffer. Defaults to 4096.
            byte_order (str, optional): byte order. same as struct. see ByteOrder enum from adapters.
                defaults to adapter default
        """
        super().__init__(adapter, byte_order=byte_order, structure=structure, struct_size=struct_size)
        self._index = 0
        self._buffer = bytearray(max(1, size) * self.struct_size())
        self._full_threshold = len(self._buffer) - self.struct_size()
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
        if end > len(self._buffer):
            return 0
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
        for tpl in iter_unpack(self.structure(), self._memview[0:self._index]):
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
        return self._index > self._full_threshold

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
            int: number of items in buffer. total size of buffer in bytes is len * adapter.struct_size()
        """
        return int(self._index / self.struct_size())
    
    def __getitem__(self, key: int) -> ByteAdapter:
        """index support

        Args:
            key (int): index of item to get

        Raises:
            IndexError: invalid index specified

        Returns:
            ByteAdapter: item
        """
        if not isinstance(key, int):
            raise IndexError("Index must be int type")
        if key > len(self):
            raise IndexError("Index out of range")
        stepping = self.struct_size()
        i = key * stepping
        return self._adapter.from_bytes(self._memview, i, self._byte_order)
        #return self._adapter(self._memview[i:i+stepping], byte_order=self._byte_order)


class BLOBFileB(BLOBAdapterB):
    """store and read items in a binary file. space efficient but slow to read with many objects due to no index
    """
    _file: str
    
    def __init__(self,
                 adapter: ByteAdapter | HexAdapter,
                 file_path: str,
                 byte_order:str = None, 
                 structure: str = None, 
                 struct_size: int = None):
        """
        Args:
            adapter (ByteAdapter): adapter for underlying storage. determines how data is packed/unpacked
            file_path (str): path to file where binary data will be stored/read
        """
        self._file = file_path
        super().__init__(adapter=adapter, byte_order=byte_order, structure=structure, struct_size=struct_size)
    
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
            for tpl in iter_unpack(self.structure(), mv[0:sz]):
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
        
    @classmethod
    def combine(cls, adapter: ByteAdapter|HexAdapter, blob_files: list, out_file: str, byte_order: str|None=None):
        trackset = set()

        output = open(out_file, 'wb')
        
        for ofl in blob_files:
            hbb = cls(adapter=adapter, file_path=ofl, byte_order=byte_order)
            for i in hbb.items():
                hashid = hash(i)
                if hashid in trackset:
                    continue
                trackset.add(hashid)
                output.write(i.as_bytes())
        
        output.close()
        item_count = len(trackset)
        trackset.clear()
        if item_count == 0:
            return None
        return cls(adapter=adapter, file_path=out_file, byte_order=byte_order)


class SHMBufferB(BLOBAdapterB):
    """Uses a shared memory buffer for backing
    """
    _shmem: SharedMemory
    _max: int
    _index: int
    _created: bool
    _idx_struct: str
    _idx_sz: int
    _unlinked: bool
    _closed: bool
    _size: int
    _sz_adapter: ByteAdapter
    
    def __init__(self,
                 adapter: ByteAdapter|HexAdapter, 
                 size: int = 8192, 
                 name: str|None = None,
                 create: bool = False,
                 size_adapter: ByteAdapter = FileSizeB):
        super().__init__(adapter=adapter)
        self._sz_adapter = size_adapter
        self._idx_struct = size_adapter.structure(byte_order=ByteOrder.NET)
        self._idx_sz = size_adapter.struct_size(byte_order=ByteOrder.NET)
        min_size = (max(1, size) * self.struct_size()) + self._idx_sz
        self._shmem = SharedMemory(name=name, create=create, size=min_size)
        self._max = (((self._shmem.size - self._idx_sz) // self.struct_size()) * self.struct_size()) + self._idx_sz
        self._index = self._idx_sz
        self._created = create
        self._unlinked = False
        self._closed = False
        self._size = (self._max - self._idx_sz) // self.struct_size()
    
    @property
    def name(self):
        return self._shmem.name
    
    def save_index(self):
        """writes index to buffer
        """
        sz = self._sz_adapter.from_ints(self._index, byte_order=ByteOrder.NET)
        self._shmem.buf[0:self._idx_sz] = sz.as_bytes()
        
    def load_index(self):
        """loads index from buffer
        """
        sz = self._sz_adapter.from_bytes(self._shmem.buf[0:self._idx_sz])
        newidx = sz.as_ints(byte_order=ByteOrder.NET)[0]
        if newidx < 0:
            raise IndexError("Stored SHMBufferB index out of range")
        self._index = newidx
    
    def add_bytes(self, data) -> int:
        ret = len(data)
        end = self._index + ret
        if end > self._max:
            return 0
        self._shmem.buf[self._index:end] = data
        self._index = end
        return ret
    
    def as_tuples(self) -> Iterator[tuple[int]]:
        for tpl in iter_unpack(self.adapter.structure(), self._shmem.buf[self._idx_sz:self._index]):
            yield tpl
    
    def clear(self):
        """resets index. does not clear bytes or change size of buffer
        """
        self._index = self._idx_sz
    
    def slice_into(self, buffer) -> Iterator[int]:
        stepping = len(buffer)
        for i in range(0, self._index, stepping):
            w = min(stepping, self._index - i)
            buffer[0:w] = self._shmem.buf[i:i+w]
            yield w
    
    def snapshot(self) -> memoryview:
        """
        Returns:
            memoryview: read only snapshot of memory contents
        """
        return self._shmem.buf[self._idx_sz:self._index].toreadonly()
    
    def close(self):
        """calls close on the shared memory. required for all when no longer in use.
        """
        if not self._closed:
            self._shmem.close()
            self._closed = True
            
    def unlink(self):
        """call unlink on the shared memory. required for creator.
        """
        if not self._unlinked and self._created:
            self._shmem.unlink()
            self._unlinked = True
        
    def __del__(self):
        self.close()
        self.unlink()
        if self._shmem is not None:
            del self._shmem

    @property
    def full(self) -> bool:
        """
        Returns:
            bool: True if no more bytes can be added to buffer. otherwise False
        """
        return self._index >= self._max
    
    @property
    def size(self) -> int:
        """
        Returns:
            int: max items that can be contained (packed) inside buffer
        """
        return self._size
    
    def __len__(self) -> int:
        """
        Returns:
            int: number of items in buffer. total size of buffer in bytes is (len * adapter.struct_size()) + index
        """
        return int((self._index - self._idx_sz) // self.struct_size())
    
    def __getitem__(self, key: int) -> ByteAdapter|HexAdapter:
        """index support

        Args:
            key (int): index of item to get

        Raises:
            IndexError: invalid index specified

        Returns:
            ByteAdapter|HexAdapter: adapted item
        """
        if not isinstance(key, int):
            raise IndexError("Index must be int type")
        if key > len(self):
            raise IndexError("Index out of range")
        stepping = self.struct_size()
        i = (key * stepping) + self._idx_sz
        return self.adapter.from_bytes(self._shmem.buf, i)


if __name__ == "__main__":
    pass