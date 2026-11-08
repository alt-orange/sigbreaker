"""Structural assertions for the controlled native test fixtures."""
import struct


def relocated_export(data, export_name):
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    opt = pe + 24
    count = struct.unpack_from('<H', data, pe + 6)[0]
    table = opt + struct.unpack_from('<H', data, pe + 20)[0]
    sections = []
    for i in range(count):
        at = table + 40 * i
        name = data[at:at + 8].rstrip(b'\0')
        virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, at + 8)
        sections.append((name, virtual_size, rva, raw_size, raw))

    def offset(rva):
        return next(raw + rva - base for _, _, base, size, raw in sections if base <= rva < base + size)

    exports = offset(struct.unpack_from('<I', data, opt + 112)[0])
    names_count = struct.unpack_from('<I', data, exports + 24)[0]
    eat, names, ordinals = struct.unpack_from('<III', data, exports + 28)
    for i in range(names_count):
        name_at = offset(struct.unpack_from('<I', data, offset(names) + 4 * i)[0])
        name = data[name_at:data.index(0, name_at)].decode('ascii')
        if name != export_name:
            continue
        ordinal = struct.unpack_from('<H', data, offset(ordinals) + 2 * i)[0]
        rva = struct.unpack_from('<I', data, offset(eat) + 4 * ordinal)[0]
        at = offset(rva)
        if data[at] != 0xE9:
            return None
        target = rva + 5 + struct.unpack_from('<i', data, at + 1)[0]
        if not any((name == b'.text' or name.startswith(b'.sbrk')) and base <= target < base + size for name, size, base, _, _ in sections):
            return None
        runtime, size = struct.unpack_from('<II', data, opt + 112 + 3 * 8)
        entries = [struct.unpack_from('<III', data, offset(runtime) + index) for index in range(0, size, 12)]
        moved = next((entry for entry in entries if entry[0] == target), None)
        original = next((entry for entry in entries if entry[0] == rva), None)
        assert moved, 'rewritten export lacks runtime-function entry'
        unwind_at = offset(moved[2])
        flags = data[unwind_at] >> 3
        return {'entry_rva': rva, 'relocated_rva': target, 'original_unwind_rva': original[2] if original else None,
                'relocated_unwind_rva': moved[2], 'unwind_flags': flags,
                'code_begin': moved[0], 'code_end': moved[1]}


def section_names(data):
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    count = struct.unpack_from('<H', data, pe + 6)[0]
    table = pe + 24 + struct.unpack_from('<H', data, pe + 20)[0]
    return [data[table + i * 40:table + i * 40 + 8] for i in range(count)]


def check_section_preservation(before, after):
    old, new = section_names(before), section_names(after)
    assert new[:len(old)] == old, 'writer removed or renamed an existing section'
    assert all(name.startswith(b'.sbrk') for name in new[len(old):]), 'unexpected generated section'
    return 'append_section' if len(new) > len(old) else 'rebuild_text'
