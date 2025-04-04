import unittest

from hashana.adapters import ByteAdapter, BLOBAdapterB, GroupAdapterB, SQLAdapter
from collections.abc import Iterable, Iterator


class ByteAdapterAdapted(ByteAdapter):
    
    default_label = "default-class-lbl"
    default_struct_layout: str = "iii"
    default_packed_count: int = 3
        

class ByteAdapterAdaptedToo(ByteAdapter):
    
    default_label = "default-class-lbl_2"
    default_struct_layout: str = "q"
    default_packed_count: int = 1
    
    
class BLOBAdapterBAdapted(BLOBAdapterB):
            
    def __init__(self, adapter: ByteAdapter, byte_order: str = None):
        super().__init__(adapter, byte_order=byte_order)
    
    def as_tuples(self):
        return None
    
    def slice_into(self, buffer):
        return None
    
    def add_bytes(self, data) -> int:
        return 0
    
    def clear(self):
        return None
            

class GroupAdapterBAdapted(GroupAdapterB):
    
    default_label = "testgroup"
    
    default_table_name: str = "testgroup"
    
    def __init__(self, raw: bytes|bytearray, byte_order: str = None):
        super().__init__(raw, byte_order=byte_order)

    @classmethod
    def data_types(cls) -> Iterator[SQLAdapter]:
        # guarantees order when iterating
        yield ByteAdapterAdapted
        yield ByteAdapterAdaptedToo
        

class TestByteAdapter(unittest.TestCase):
    
    def setUp(self):
        pass
    
    def tearDown(self):
        pass
    
    @classmethod
    def setUpClass(cls):
        return super().setUpClass()
    
    @classmethod
    def tearDownClass(cls):
        return super().tearDownClass()
    
    def test_abstract(self):
        self.assertNotEqual(ByteAdapterAdapted.structure('!'), ByteAdapterAdapted.structure('<'))
        self.assertEqual(ByteAdapterAdapted.struct_order(), '!')
        self.assertEqual(ByteAdapterAdapted.struct_layout(), 'iii')
        self.assertEqual(ByteAdapterAdapted.packed_count(), 3)
        self.assertEqual(ByteAdapterAdapted.struct_size(), 12)
    
    def test_instances(self):
        tbytes = (2,3,4)
        hexnet = '000000020000000300000004'
        banet = ByteAdapterAdapted.from_ints(*tbytes, byte_order='!')
        self.assertEqual(banet.as_hex(), hexnet)
        self.assertEqual(hash(banet.as_ints(byte_order='!')), hash(tbytes))
        self.assertEqual(banet.byte_order, '!')
        
        banet2 = ByteAdapterAdapted.from_hex(banet.as_hex(), byte_order='!')
        self.assertEqual(hash(banet), hash(banet2))
        
        banetdict = banet.as_dict()
        self.assertIn("default-class-lbl", banetdict.keys())
        self.assertIsNotNone(banetdict["default-class-lbl"])
        
        banet2 = ByteAdapterAdapted.from_keywords(**banetdict)
        self.assertEqual(banet2.as_hex(), hexnet)
        
        #label stuff
        balbl = ByteAdapterAdapted.from_ints(*tbytes)
        self.assertEqual(balbl.label(), 'default-class-lbl')
    
    
class TestBLOBAdapterB(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    @classmethod
    def setUpClass(cls):
        return super().setUpClass()
    
    @classmethod
    def tearDownClass(cls):
        return super().tearDownClass()
    
    def test_abstract(self):
        baa = BLOBAdapterBAdapted(adapter=ByteAdapterAdapted, byte_order='!')
        self.assertEqual(baa.adapter, ByteAdapterAdapted)
        self.assertEqual(baa.structure(), ByteAdapterAdapted.structure(byte_order='!'))
        self.assertEqual(baa.struct_size(), ByteAdapterAdapted.struct_size(byte_order='!'))
        

class TestGroupAdapterB(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    @classmethod
    def setUpClass(cls):
        return super().setUpClass()
    
    @classmethod
    def tearDownClass(cls):
        return super().tearDownClass()
    
    def test_abstract(self):
        self.assertIsNotNone(GroupAdapterBAdapted.struct_layout())
        self.assertNotEqual(GroupAdapterBAdapted.struct_layout(), ByteAdapterAdapted.struct_layout())
        self.assertNotEqual(GroupAdapterBAdapted.struct_layout(), ByteAdapterAdaptedToo.struct_layout())
        self.assertEqual(GroupAdapterBAdapted.sql_table_name(), "testgroup")
        
        ba1 = ByteAdapterAdapted.from_ints(1,2,3, byte_order='!')
        ba2 = ByteAdapterAdaptedToo.from_ints(6, byte_order='!')
        group = GroupAdapterBAdapted.from_objs(ba1, ba2, byte_order='!')
        self.assertEqual(group.struct_order(), '!')
        d = group.as_dict()
        self.assertIn('byte_order', d.keys())
        self.assertIn(ba1.label(), d.keys())
        self.assertIn(ba2.label(), d.keys())
        
        group2 = GroupAdapterBAdapted.from_keywords(**d)
        self.assertEqual(group.struct_order(), group2.struct_order())
        self.assertEqual(hash(group), hash(group2))
        
        group2 = GroupAdapterBAdapted.from_sql_values(1,2,3,6)
        self.assertEqual(hash(group), hash(group2))
        