"""Deterministic PE fixtures for the original-to-processed signature comparison.

Run: python -m unittest discover -s tests -p test_signature_test.py -v
"""
import contextlib
import io
import json
import lzma
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import signature_test as st


BASE = 0x140000000
CODE = bytes.fromhex("55 48 89 e5 48 83 ec 20 b8 2a 00 00 00 83 c0 01 83 f0 07 83 c0 09 48 83 c4 20 5d c3")


def pe_image(code=CODE, appended=None, compressed=False, duplicate=False):
    """Two-section PE64 plus optional relocated or LZMA-packed code."""
    text = bytearray(code.ljust(0x200, b"\xcc"))
    rdata = bytearray(0x200)
    struct.pack_into("<III", rdata, 0, 0x1000, 0x1000 + len(code), 0x2040)
    rdata[0x40:0x44] = bytes((1, 0, 0, 0))
    sections = [(".text", 0x1000, 0x200, 0x400, bytes(text), 0x60000020),
                (".rdata", 0x2000, 0x200, 0x600, bytes(rdata), 0x40000040)]
    if duplicate:
        text[0x100:0x100 + len(code)] = code
        sections[0] = (".text", 0x1000, 0x200, 0x400, bytes(text), 0x60000020)
    if appended is not None:
        text[:] = b"\xcc" * 0x200
        text[:5] = b"\xe9" + struct.pack("<i", 0x3000 - 0x1005)
        sections[0] = (".text", 0x1000, 0x200, 0x400, bytes(text), 0x60000020)
        relocated = appended.ljust(0x200, b"\xcc")
        if compressed:
            packed = bytearray(lzma.compress(relocated, format=lzma.FORMAT_ALONE))
            # Python's standard encoder uses an end marker. The recovery record
            # independently supplies the exact decoded size for either format.
            record = bytearray(124)
            record[:8] = b"SBRKCMP1"
            struct.pack_into("<5I", record, 8, 1, 0x3000, len(relocated), 124, len(packed))
            struct.pack_into("<Q", record, 44, 0x800)
            sections += [(".sbrk", 0x3000, 0x200, 0, b"", 0xe0000020),
                         (".sbpack", 0x4000, 0x200, 0x800,
                          (record + packed).ljust(0x200, b"\0"), 0xc0000040)]
        else:
            sections.append((".sbrk", 0x3000, 0x200, 0x800, relocated, 0x60000020))
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, len(sections), 0, 0, 0, 240, 0x22)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20b)
    struct.pack_into("<Q", data, opt + 24, BASE)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, opt + 56, (len(sections) + 1) * 0x1000, 0x400)
    struct.pack_into("<I", data, opt + 108, 16)
    struct.pack_into("<II", data, opt + 112 + 24, 0x2000, 12)
    for i, (name, va, vsize, raw, blob, chars) in enumerate(sections):
        header = opt + 240 + i * 40
        data[header:header + 8] = name.encode().ljust(8, b"\0")
        struct.pack_into("<IIII", data, header + 8, vsize, va, len(blob), raw)
        struct.pack_into("<I", data, header + 36, chars)
        if blob:
            if len(data) < raw + len(blob):
                data.extend(b"\0" * (raw + len(blob) - len(data)))
            data[raw:raw + len(blob)] = blob
    return st.parse_data(bytes(data))


def signature(img, start=0x1000, length=len(CODE), prefix=256):
    return st.build_signature(img, start, start + length, prefix)


class SignatureTests(unittest.TestCase):
    def test_original_control_and_appended_relocation(self):
        original = pe_image()
        sig = signature(original)
        own = st.search_all([sig], original, original.regions())[0]
        self.assertEqual(own.count, 1)
        self.assertEqual(own.locations["original-site"], 1)
        moved = pe_image(appended=CODE)
        found = st.search_all([sig], moved, moved.regions())[0]
        self.assertEqual(found.count, 1)
        self.assertEqual(found.locations["appended"], 1)
        self.assertEqual(found.examples[0].rva, 0x3000)
        self.assertTrue(st.entry_redirected(moved, 0x1000))

    def test_opcode_change_breaks_entry_but_keeps_body(self):
        original = pe_image()
        changed = pe_image(code=b"\x53" + CODE[1:])
        cut = st.body_start(original, 0x1000, 0x1000 + len(CODE), 16)
        body = st.build_signature(original, cut, 0x1000 + len(CODE), 256)
        body.fn_start = 0x1000
        entry_hits, body_hits = st.search_all([signature(original), body], changed, changed.regions())
        self.assertEqual(entry_hits.count, 0)
        self.assertEqual(body_hits.locations["original-site"], 1)

    def test_body_offset_aligns_to_instruction_boundary(self):
        original = pe_image()
        self.assertEqual(st.body_start(original, 0x1000, 0x101c, 2), 0x1004)
        self.assertIsNone(st.body_start(original, 0x1000, 0x101c, 28))

    def test_address_fields_masked_but_constants_preserved(self):
        code = bytes.fromhex("e8 11 22 33 44 48 8b 05 11 22 33 44 48 b8") + struct.pack("<Q", BASE + 0x2000)
        code += bytes.fromhex("83 c0 2a c3")
        original = pe_image(code=code)
        sig = signature(original, length=len(code))
        expected = set(range(1, 5)) | set(range(8, 12)) | set(range(14, 22))
        self.assertEqual({i for i, b in enumerate(sig.mask) if b}, expected)
        self.assertEqual(sig.wild, len(expected))
        modified = bytearray(code)
        for i in expected:
            modified[i] ^= 0xff
        self.assertIsNotNone(st.compile_regex(sig).fullmatch(modified))
        modified[-2] ^= 1  # small ADD constant remains concrete
        self.assertIsNone(st.compile_regex(sig).fullmatch(modified))

    def test_prefix_ending_inside_displacement(self):
        img = pe_image(code=bytes.fromhex("e8 11 22 33 44 c3"))
        sig = signature(img, length=6, prefix=3)
        self.assertEqual(sig.mask, b"\0\1\1")
        self.assertEqual(sig.wild, 2)

    def test_lzma_view_restores_signature_absent_from_file(self):
        sig = signature(pe_image())
        packed = pe_image(appended=CODE, compressed=True)
        self.assertIsNone(packed.rva_to_off(0x3000))
        self.assertEqual(st.search_all([sig], packed, packed.regions())[0].count, 0)
        restored = st.restore_code(packed)
        self.assertEqual(restored.restored_sections, (".sbrk",))
        found = st.search_all([sig], restored, restored.regions())[0]
        self.assertEqual(found.locations["appended"], 1)
        self.assertEqual(found.examples[0].rva, 0x3000)

    def test_duplicate_original_patterns_are_non_unique(self):
        img = pe_image(duplicate=True)
        found = st.search_all([signature(img)], img, img.regions())[0]
        self.assertEqual(found.count, 2)
        self.assertEqual(found.locations["original-site"], 1)
        self.assertEqual(found.locations["elsewhere"], 1)

    def test_overlapping_matches_and_bounded_examples(self):
        img = pe_image(code=b"A" * 128)
        sig = st.Signature(0x1000, 0x1080, 0x1000, b"AAA", bytes(3), 3, 0)
        found = st.search_all([sig], img, img.regions())[0]
        self.assertEqual(found.count, 126)
        self.assertLessEqual(len(found.examples), 6)

    def test_search_does_not_cross_section_boundary(self):
        img = pe_image()
        data = bytearray(img.data)
        data[0x5fe:0x602] = b"ABCD"
        img.data = bytes(data)
        sig = st.Signature(0x1000, 0x1200, 0x1000, b"ABCD", bytes(4), 1, 0)
        self.assertEqual(st.search_all([sig], img, img.regions())[0].count, 0)

    def test_wildcards_include_newlines_and_match_overlaps(self):
        img = pe_image(code=b"A\nA\nA\nA")
        sig = st.Signature(0x1000, 0x1007, 0x1000, b"AxA", bytes((0, 1, 0)), 1, 1)
        found = st.search_all([sig], img, img.regions())[0]
        self.assertEqual(found.count, 3)
        with patch.object(st, "ahocorasick", None):
            self.assertEqual(st.search_all([sig], img, img.regions())[0], found)
        wildcard_only = st.Signature(0x1000, 0x1200, 0x1000, b"xxx", b"\1\1\1", 1, 3)
        self.assertEqual(st.search_all([wildcard_only], img, img.regions())[0].count, 510)

    def test_corrupt_compression_is_not_reported_as_no_matches(self):
        img = pe_image(appended=CODE, compressed=True)
        data = bytearray(img.data)
        # Claim a decoded size inconsistent with both the stream and target.
        struct.pack_into("<I", data, 0x800 + 16, 511)
        img.data = bytes(data)
        with self.assertRaises(ValueError):
            st.restore_code(img)

    def test_no_runtime_records_fails_instead_of_empty_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "no-functions.dll"
            data = bytearray(pe_image().data)
            struct.pack_into("<II", data, 0x98 + 112 + 24, 0, 0)
            path.write_bytes(data)
            errors = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                self.assertEqual(st.main([str(path), str(path)]), 1)
            self.assertIn("no runtime-function records", errors.getvalue())

    @unittest.skipIf(st.ahocorasick is None, "optional native accelerator is not installed")
    def test_native_and_python_engines_agree(self):
        img = pe_image(duplicate=True)
        sigs = [signature(img)]
        native = st.search_all(sigs, img, img.regions())
        with patch.object(st, "ahocorasick", None):
            fallback = st.search_all(sigs, img, img.regions())
        self.assertEqual(native, fallback)

    def test_padding_and_truncated_images_rejected(self):
        self.assertIsNone(signature(pe_image(code=b"\xcc" * 32), length=32))
        with self.assertRaises(ValueError):
            st.parse_data(b"MZ")
        with self.assertRaises(ValueError):
            st.parse_data(pe_image().data[:-1])

    def test_cli_json_control_and_relocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, processed, report = root / "original.dll", root / "processed.dll", root / "report.json"
            original.write_bytes(pe_image().data)
            processed.write_bytes(pe_image(appended=CODE, compressed=True).data)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = st.main([str(original), str(processed), "--baseline", "--view", "both", "--json", str(report)])
            self.assertEqual(status, 0)
            result = json.loads(report.read_text())
            self.assertTrue(result["original_control"]["scanner_checked"])
            self.assertEqual(result["views"]["file"]["summary"]["entry"]["detected"], 0)
            self.assertEqual(result["views"]["decoded"]["summary"]["entry"]["detected"], 1)
            self.assertEqual(result["views"]["decoded"]["summary"]["entry"]["unique_original"],
                             {"tested": 1, "detected": 1})
            before = original.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                st.main([str(original), str(processed), "--json", str(original)])
            self.assertEqual(original.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
