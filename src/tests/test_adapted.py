import unittest

from hashana.adapted import (
    MD5B, SHA1B, SHA256B, FileSizeB, HBufferB, IP6B, MACB, CRC32B, SHA224B, SHA384B, SHA512B, IP4B
)
from hashana.adapters import SQLAdapter, ByteAdapter


class TestBasicAdapted(unittest.TestCase):
    
    def do_adapted(self, cls, init_tpl: tuple, be_hex: str, le_hex: str):
        sqlinit = cls.from_sql_values(*init_tpl)
        tints = sqlinit.as_ints()
        for i in range(0, len(tints)):
            self.assertEqual(tints[i], init_tpl[i])
        self.assertEqual(sqlinit.as_hex(), be_hex)
        
        tdict = sqlinit.as_dict()
        self.assertIn('byte_order', tdict.keys())
        self.assertIn(sqlinit.label(), tdict.keys())
        self.assertEqual(tdict[sqlinit.label()], be_hex)
        
        self.assertEqual(hash(sqlinit), hash(cls.from_keywords(**tdict)))
        
        border1 = cls.from_hex(be_hex, byte_order='>')
        border2 = cls.from_hex(le_hex, byte_order='<')
        
        b1ints = border1.as_ints()
        b2ints = border2.as_ints()
        
        for i in range(0,len(b1ints)):
            self.assertEqual(b1ints[i], b2ints[i])
    
    def test_ip4(self):
        self.assertEqual(IP4B.from_address('255.255.255.255').as_bits(), '11111111111111111111111111111111')
        self.assertEqual(IP4B.from_address('1.2.3.4').as_bits(), '00000001000000100000001100000100')
        self.assertEqual(IP4B.from_address('0.0.0.1').as_bits(), '00000000000000000000000000000001')
        self.assertEqual(IP4B.from_address('255.255.255.255').as_hex(), 'ffffffff')
        self.assertEqual(IP4B.from_address('0.0.0.0').as_hex(), '00000000')
        addrtst = IP4B.from_address('127.0.0.1')
        self.assertEqual(addrtst.as_hex(), '7f000001')
        self.assertEqual(addrtst.address, addrtst.as_address())
    
    def test_ip6(self):
        self.assertEqual(IP6B.from_address("fe80::1").as_hex(), 'fe800000000000000000000000000001')
        self.assertEqual(IP6B.from_address("::1").as_hex(), '00000000000000000000000000000001')
        self.assertEqual(IP6B.from_address("abcd::").as_hex(), 'abcd0000000000000000000000000000')
        
        addrtst = IP6B.from_address("123:456:0:00:000:0000:0:0")
        self.assertEqual(addrtst.as_address(), '123:456:0:0:0:0:0:0')
        self.assertEqual(addrtst.as_address(squash=True), '123:456::')
        
        addrtst = IP6B.from_address("::1234:0000:5678")
        self.assertEqual(addrtst.as_address(), '0:0:0:0:0:1234:0:5678')
        self.assertEqual(addrtst.as_address(squash=True), '::1234:0:5678')
        
        self.do_adapted(IP6B,
                        (12,24),
                        '000000000000000c0000000000000018',
                        '0c000000000000001800000000000000')
    
    
    def test_mac(self):
        self.do_adapted(MACB,
                        (12, 24, 36),
                        '000c00180024',
                        '0c0018002400')
    
    
    def test_crc32(self):
        self.do_adapted(CRC32B,
                        (7,),
                        '00000007',
                        '07000000')
    
    
    def test_sha1(self):
        self.do_adapted(SHA1B,
                        (1,2,3,4,5),
                        '0000000100000002000000030000000400000005', 
                        '0100000002000000030000000400000005000000')
    
    
    def test_sha224(self):
        self.do_adapted(SHA224B,
                        (9,8,7,6),
                        '00000000000000090000000000000008000000000000000700000006',
                        '09000000000000000800000000000000070000000000000006000000')
    
    
    def test_md5(self):
        self.do_adapted(MD5B,
                        (1,2,3,4),
                        '00000001000000020000000300000004',
                        '01000000020000000300000004000000')
        
    def test_sha256(self):
        self.do_adapted(SHA256B,
                        (5,6,7,8),
                        '0000000000000005000000000000000600000000000000070000000000000008',
                        '0500000000000000060000000000000007000000000000000800000000000000')
    
    def test_sha384(self):
        self.do_adapted(SHA384B,
                        (8,7,6,5,4,3),
                        '000000000000000800000000000000070000000000000006000000000000000500000000000000040000000000000003',
                        '080000000000000007000000000000000600000000000000050000000000000004000000000000000300000000000000')
        
    
    def test_sha512(self):
        self.do_adapted(SHA512B,
                        (15, 14, 13, 12, 11, 10, 9, 8),
                        '000000000000000f000000000000000e000000000000000d000000000000000c000000000000000b000000000000000a00000000000000090000000000000008',
                        '0f000000000000000e000000000000000d000000000000000c000000000000000b000000000000000a0000000000000009000000000000000800000000000000')
    
    def test_filesize(self):
        self.do_adapted(FileSizeB,
                        (6,),
                        '0000000000000006',
                        '0600000000000000')
    
    
        
class TestBLOBs(unittest.TestCase):
    
    def test_hbuffer(self):
        hb = HBufferB(adapter=MD5B, byte_order='!', size=10)
        m1 = MD5B.from_ints(1,2,3,4,byte_order=hb.byte_order)
        self.assertTrue(hb.add_adapted(m1))
        self.assertEqual(hb.byte_order, '!')
        self.assertEqual(len(hb), 1)
        self.assertEqual(hb.size, 10)
        
        for _ in range(0, 9):
            self.assertFalse(hb.full)
            self.assertTrue(hb.add_adapted(m1))
            
        self.assertTrue(hb.full)
        self.assertFalse(hb.add_adapted(m1))
        
        hb.clear()
        self.assertEqual(len(hb), 0)
        
        self.assertTrue(hb.add_adapted(m1))
        m2 = MD5B.from_ints(9,8,7,6,byte_order=hb.byte_order)
        self.assertTrue(hb.add_adapted(m2))
        self.assertEqual(len(hb), 2)
        
        self.assertEqual(hash(m1), hash(hb[0]))
        self.assertEqual(m1.byte_order, hb.byte_order)
        self.assertEqual(m2.byte_order, hb.byte_order)
        
        itmlist = [x for x in hb.items()]
        self.assertEqual(hash(m1), hash(itmlist[0]))
        self.assertEqual(hash(m2), hash(itmlist[1]))