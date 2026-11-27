import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import export_headers as ex
from refresh import last_complete_height


def header(n, previous):
    return dict(version=1, height=n, timestamp="2019-01-15T16:01:26Z", previous=previous,
                prev_root="22"*32, output_root="33"*32, range_proof_root="44"*32,
                kernel_root="55"*32, total_kernel_offset="66"*32, output_mmr_size=n+1,
                kernel_mmr_size=n+1, total_difficulty=n+1, secondary_scaling=17,
                nonce=123+n, edge_bits=29, cuckoo_solution=list(range(n, n+42)))


class Fixture:
    def __init__(self):
        self.records = []
        prev = "00"*32
        for height in range(4):
            h = header(height, prev)
            h["hash"] = prev = ex.binary(h)[1].hex()
            self.records.append(h)
    def call(self, method, args):
        return {"height": 3} if method == "get_tip" else self.records[args[0]]


class OperatorTest(unittest.TestCase):
    def test_four_exported_heights_match_frames(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td)/"dump"
            node = Fixture()
            ex.export(node, dest)
            raw = dest.read_bytes()
            self.assertEqual(3, last_complete_height(raw))
            start = 0
            for h in node.records:
                size = struct.unpack_from(">H", raw, start)[0]
                frame = raw[start+2:start+2+size]
                self.assertEqual(247 + (42*29+7)//8, size)
                self.assertEqual(h["height"], struct.unpack_from(">Q", frame,2)[0])
                self.assertEqual(h["hash"], hashlib.blake2b(frame[247:],digest_size=32).hexdigest())
                start += 2 + size
            self.assertEqual(start,len(raw))

    def test_chain_change_keeps_old_export(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td)/"dump"
            node = Fixture()
            ex.export(node, dest)
            before = dest.read_bytes()
            node.records[2]["previous"] = "ff"*32
            with self.assertRaises(ValueError):
                ex.export(node, dest)
            self.assertEqual(before, dest.read_bytes())
            self.assertEqual([dest], list(dest.parent.iterdir()))

    def test_incomplete_exports_are_rejected(self):
        for data in (b"",b"\0",b"\0\0",b"\x04\x01",b"\0\3ab",b"\0\1a\0"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                last_complete_height(data)

    def test_bounds_before_packing(self):
        for bits, solution in ((-1,[0]*42),(10**10,[0]*42),(29,[0]),(29,[1<<30]*42)):
            h = header(0,"00"*32)
            h.update(edge_bits=bits,cuckoo_solution=solution)
            with self.assertRaises(ValueError):
                ex.binary(h)


if __name__ == "__main__":
    unittest.main()
