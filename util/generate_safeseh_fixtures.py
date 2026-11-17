#!/usr/bin/env python3
"""Generate SafeSEH test fixtures from the stock x86 pegoat binary.

The stock pegoat.exe ships with a 64-byte load config directory, which is too
short to expose the SafeSEH fields. These fixtures grow the load config
directory to cover the SEHandlerTable/SEHandlerCount fields and append
file-backed sections that host the malformed handler tables:

* pegoat-safeseh-valid.exe: a fully readable, in-section handler table whose
  entries all resolve to reachable sections, i.e. a genuine Present.
* pegoat-safeseh-inconsistent.exe: a non-zero handler table paired with a
  zero count (or vice versa), i.e. a malformed load config.
* pegoat-safeseh-cross-section.exe: the handler table straddles the boundary
  of the two appended sections, so its range is not contained in one section.
* pegoat-safeseh-truncated.exe: the handler table points at the tail of the
  last appended section with a count whose entries run past the file end;
  the range is covered by the section's virtual size, but an entry cannot be
  read from the file buffer.

Run from the repository root:

    python3 util/generate_safeseh_fixtures.py
"""

import pathlib
import struct

import pefile

SOURCE = pathlib.Path("test/assets/32/pegoat.exe")
OUTPUT_DIR = pathlib.Path("test/assets/32")

# PE32 optional-header layout: the data directory array starts at offset 96
# and the load config directory is entry 10 (8 bytes each).
DATA_DIRECTORY_OFFSET = 96
LOAD_CONFIG_DIRECTORY_INDEX = 10

# IMAGE_LOAD_CONFIG_DIRECTORY32 offsets of the SafeSEH fields.
SE_HANDLER_TABLE_OFFSET = 64
SE_HANDLER_COUNT_OFFSET = 68

# The handler table lives in .data in the stock binary (RVA 0x3208, five
# handler RVAs, all inside .text).
TABLE_RVA = 0x3208
HANDLER_COUNT = 5

IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_READ = 0x40000000


def patch_dword(blob, offset, value):
    blob[offset:offset + 4] = struct.pack("<I", value)


def section_header(name, virtual_address, virtual_size, raw_offset, raw_size,
                   characteristics):
    return struct.pack(
        "<8sIIIIIIHHI",
        name.encode("ascii"),
        virtual_size,
        virtual_address,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        characteristics,
    )


def build_fixture(name, table_rva, handler_count, extra_sections,
                  table_bytes=None, table_file_offset=None):
    pe = pefile.PE(str(SOURCE))
    blob = bytearray(pe.__data__)

    load_config = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]
    ]
    load_config_offset = pe.get_offset_from_rva(load_config.VirtualAddress)
    directory_entry_offset = (
        pe.OPTIONAL_HEADER.get_file_offset()
        + DATA_DIRECTORY_OFFSET
        + LOAD_CONFIG_DIRECTORY_INDEX * 8
    )

    # Expose the SafeSEH fields by growing the load config directory to the
    # end of the SEHandlerCount field.
    patch_dword(blob, directory_entry_offset + 4, SE_HANDLER_COUNT_OFFSET + 4)
    patch_dword(blob, load_config_offset + SE_HANDLER_TABLE_OFFSET, table_rva)
    patch_dword(blob, load_config_offset + SE_HANDLER_COUNT_OFFSET, handler_count)

    section_table_offset = (
        pe.OPTIONAL_HEADER.get_file_offset() + pe.FILE_HEADER.SizeOfOptionalHeader
    )
    number_of_sections_offset = pe.DOS_HEADER.e_lfanew + 4 + 2

    next_raw_offset = len(blob)
    next_rva = pe.OPTIONAL_HEADER.SizeOfImage
    for index, section in enumerate(extra_sections):
        raw_size = section["raw_size"]
        virtual_size = section["virtual_size"]
        header = section_header(
            section["name"],
            next_rva,
            virtual_size,
            next_raw_offset,
            raw_size,
            section["characteristics"],
        )
        header_offset = section_table_offset + (pe.FILE_HEADER.NumberOfSections + index) * 40
        blob[header_offset:header_offset + 40] = header
        blob.extend(section["data"][:raw_size])
        next_raw_offset += raw_size
        next_rva += pe.OPTIONAL_HEADER.SectionAlignment

    patch_dword(blob, number_of_sections_offset,
                pe.FILE_HEADER.NumberOfSections + len(extra_sections))
    patch_dword(blob, pe.OPTIONAL_HEADER.get_file_offset() + 56, next_rva)

    if table_bytes is not None and table_file_offset is not None:
        blob[table_file_offset:table_file_offset + len(table_bytes)] = table_bytes

    destination = OUTPUT_DIR / name
    destination.write_bytes(blob)
    print(f"wrote {destination}")


def main():
    if not SOURCE.exists():
        raise SystemExit(f"missing source fixture: {SOURCE}")

    pe = pefile.PE(str(SOURCE))
    source_table_offset = pe.get_offset_from_rva(TABLE_RVA)
    handler_rvas = pe.__data__[
        source_table_offset:source_table_offset + HANDLER_COUNT * 4
    ]

    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    first_rva = pe.OPTIONAL_HEADER.SizeOfImage
    second_rva = first_rva + section_alignment
    third_rva = second_rva + section_alignment

    readable = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ

    # Two 0x200-byte sections. The cross table starts 4 bytes before the
    # second section, so its final entry crosses the section boundary.
    first_raw_offset = len(pe.__data__)
    second_raw_offset = first_raw_offset + file_alignment
    cross_table_rva = second_rva - 4
    cross_table_file_offset = second_raw_offset - 4

    # The truncated table starts at the last 4 raw bytes of the final appended
    # section. Its range is fully covered by the (larger) virtual size, but
    # the second entry would read past the end of the file buffer.
    truncated_rva = third_rva + file_alignment - 4
    truncated_file_offset = (
        len(pe.__data__) + 3 * file_alignment - 4
    )
    # Reads past the file end can still succeed within the last mmap page, so
    # use a count large enough to run well past the page boundary.
    truncated_count = file_alignment

    first_section = {
        "name": ".sa1",
        "raw_size": file_alignment,
        "virtual_size": file_alignment,
        "characteristics": readable,
        "data": b"\x00" * file_alignment,
    }
    second_section = {
        "name": ".sa2",
        "raw_size": file_alignment,
        "virtual_size": file_alignment,
        "characteristics": readable,
        "data": b"\x00" * file_alignment,
    }
    third_section = {
        "name": ".sa3",
        "raw_size": file_alignment,
        # Cover the whole table range virtually while keeping the on-disk
        # extent at one file-aligned block, forcing a truncated read.
        "virtual_size": file_alignment + truncated_count * 4,
        "characteristics": readable,
        "data": b"\x00" * file_alignment,
    }

    build_fixture("pegoat-safeseh-valid.exe", TABLE_RVA, HANDLER_COUNT, [], None)
    build_fixture("pegoat-safeseh-inconsistent.exe", TABLE_RVA, 0, [], None)
    build_fixture(
        "pegoat-safeseh-cross-section.exe",
        cross_table_rva,
        HANDLER_COUNT,
        [first_section, second_section],
        table_bytes=handler_rvas,
        table_file_offset=cross_table_file_offset,
    )
    build_fixture(
        "pegoat-safeseh-truncated.exe",
        truncated_rva,
        truncated_count,
        [first_section, second_section, third_section],
        table_bytes=handler_rvas,
        table_file_offset=truncated_file_offset,
    )


if __name__ == "__main__":
    main()
