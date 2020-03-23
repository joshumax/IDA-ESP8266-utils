# This should work on both old/new ROM dumps from the ESP8266
# Adapted from code based on boredpentester.com -Josh

#!/usr/bin/python

from struct import unpack_from
from idaapi import *


def accept_file(li, n):
    retval = 0
    li.seek(0)

    # ESP8266 FW magic
    if li.read(1) == "e9".decode("hex"):
        retval = "ESP8266 firmware"

    return retval


def load_file(li, neflags, format):
    li.seek(0)

    # Set our processor type to xtensa
    SetProcessorType("xtensa", SETPROC_ALL)

    # Load our initial ROM segment
    (magic, segments, flash_mode, flash_size_freq, entrypoint) = struct.unpack(
        '<BBBBI', li.read(8))

    print "Reading ROM boot firmware"
    print "Magic: %x" % magic
    print "Segments: %x" % segments
    print "Entry point: %x" % entrypoint

    # Add our boot ROM segment (may overlap with user segment after re-mapping!)
    (rom_addr, rom_size) = unpack_from("<II", li.read(8))
    li.file2base(16, rom_addr, rom_addr + rom_size, True)
    add_segm(0, rom_addr, rom_addr + rom_size, ".boot_rom", "CODE")
    idaapi.add_entry(0, entrypoint, "rom_entry", 1)

    print "\nReading boot loader code"
    print "ROM address: %x" % rom_addr
    print "ROM size: %x\n" % rom_size

    # Go to user ROM code (FIXME: Support ROM2+ slots too!)
    li.seek(0x1000, 0)

    # Read new ROM header if present (to seek past .irom.text)
    (magic1, magic2, config1, config2, entry, unused1, unused2, unused3,
     unused4, length) = struct.unpack('<BBBBIBBBBI', li.read(16))

    if magic1 != 0xE9:
        print "Got new ROM header, seeking past..."

        irom_segment_offset = li.tell()
        li.seek(length, 1)

        print "Generating .irom.text segment"

        # Map .irom.text from SPI flash
        mapped_spi_address = 0x40200000
        li.file2base(irom_segment_offset,
                     mapped_spi_address + irom_segment_offset,
                     mapped_spi_address + irom_segment_offset + length, True)
        add_segm(0, mapped_spi_address + irom_segment_offset,
                 mapped_spi_address + irom_segment_offset + length,
                 ".irom.text", "CODE")
    else:
        print "Got old ROM header, skipping back..."

        # No new ROM header stuff, go back...
        li.seek(-16, 1)

    # Load our user ROM segment
    (magic, segments, flash_mode, flash_size_freq, entrypoint) = struct.unpack(
        '<BBBBI', li.read(8))
    idaapi.add_entry(1, entrypoint, "user_entry", 1)

    print "\nReading user firmware"
    print "Magic: %x" % magic
    print "Segments: %x" % segments
    print "Entry point: %x\n" % entrypoint

    print "Reading user code:"
    for k in xrange(segments):
        (seg_addr, seg_size) = unpack_from("<II", li.read(8))
        file_offset = li.tell()

        # Based on the ESP8266 memory map
        if seg_addr == 0x40100000:
            seg_name = ".user_rom"
            seg_type = "CODE"
        elif seg_addr == 0x3FFE8000:
            seg_name = ".user_rom_data"
            seg_type = "DATA"
        elif seg_addr <= 0x3FFFFFFF:
            seg_name = ".data_seg_%d" % k
            seg_type = "DATA"
        elif seg_addr > 0x40100000:
            seg_name = ".code_seg_%d" % k
            seg_type = "CODE"
        else:
            seg_name = ".unknown_seg_%d" % k
            seg_type = "CODE"

        print "\nSeg name: %s" % seg_name
        print "Seg type: %s" % seg_type
        print "Seg address: %x" % seg_addr
        print "Seg size: %x" % seg_size

        # Add this discovered segment to our list!
        li.file2base(file_offset, seg_addr, seg_addr + seg_size, True)
        add_segm(0, seg_addr, seg_addr + seg_size, seg_name, seg_type)
        li.seek(file_offset + seg_size, 0)

    return 1
