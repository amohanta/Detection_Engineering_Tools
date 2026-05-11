#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import sys
import csv
from datetime import datetime, timedelta, timezone

# --------------------------- Helper functions ---------------------------
def decode_filetime(ft):
    """Convert Windows FILETIME (64-bit, units of 100 ns since 1601-01-01) to ISO datetime string."""
    if ft == 0:
        return ""
    try:
        windows_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        seconds = ft / 10_000_000.0
        dt = windows_epoch + timedelta(seconds=seconds)
        return dt.isoformat()
    except:
        return ""

# --------------------------- USN reason and source codes ---------------------------
USN_REASON_BASIC_INFO_CHANGE = 0x00008000
USN_REASON_CLOSE = 0x80000000
USN_REASON_COMPRESSION_CHANGE = 0x00020000
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_DATA_TRUNCATION = 0x00000004
USN_REASON_EA_CHANGE = 0x00000400
USN_REASON_ENCRYPTION_CHANGE = 0x00040000
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_HARD_LINK_CHANGE = 0x00010000
USN_REASON_INDEXABLE_CHANGE = 0x00004000
USN_REASON_INTEGRITY_CHANGE = 0x00800000
USN_REASON_NAMED_DATA_EXTEND = 0x00000020
USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010
USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040
USN_REASON_OBJECT_ID_CHANGE = 0x00080000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_REPARSE_POINT_CHANGE = 0x00100000
USN_REASON_SECURITY_CHANGE = 0x00000800
USN_REASON_STREAM_CHANGE = 0x00200000
USN_REASON_TRANSACTED_CHANGE = 0x00400000

REASON_LIST = {
    USN_REASON_BASIC_INFO_CHANGE: 'BASIC_INFO_CHANGE',
    USN_REASON_CLOSE: 'CLOSE',
    USN_REASON_COMPRESSION_CHANGE: 'COMPRESSION_CHANGE',
    USN_REASON_DATA_EXTEND: 'DATA_EXTEND',
    USN_REASON_DATA_OVERWRITE: 'DATA_OVERWRITE',
    USN_REASON_DATA_TRUNCATION: 'DATA_TRUNCATION',
    USN_REASON_EA_CHANGE: 'EA_CHANGE',
    USN_REASON_ENCRYPTION_CHANGE: 'ENCRYPTION_CHANGE',
    USN_REASON_FILE_CREATE: 'FILE_CREATE',
    USN_REASON_FILE_DELETE: 'FILE_DELETE',
    USN_REASON_HARD_LINK_CHANGE: 'HARD_LINK_CHANGE',
    USN_REASON_INDEXABLE_CHANGE: 'INDEXABLE_CHANGE',
    USN_REASON_INTEGRITY_CHANGE: 'INTEGRITY_CHANGE',
    USN_REASON_NAMED_DATA_EXTEND: 'NAMED_DATA_EXTEND',
    USN_REASON_NAMED_DATA_OVERWRITE: 'NAMED_DATA_OVERWRITE',
    USN_REASON_NAMED_DATA_TRUNCATION: 'NAMED_DATA_TRUNCATION',
    USN_REASON_OBJECT_ID_CHANGE: 'OBJECT_ID_CHANGE',
    USN_REASON_RENAME_NEW_NAME: 'RENAME_NEW_NAME',
    USN_REASON_RENAME_OLD_NAME: 'RENAME_OLD_NAME',
    USN_REASON_REPARSE_POINT_CHANGE: 'REPARSE_POINT_CHANGE',
    USN_REASON_SECURITY_CHANGE: 'SECURITY_CHANGE',
    USN_REASON_STREAM_CHANGE: 'STREAM_CHANGE',
    USN_REASON_TRANSACTED_CHANGE: 'TRANSACTED_CHANGE'
}

USN_SOURCE_AUXILIARY_DATA = 0x00000002
USN_SOURCE_DATA_MANAGEMENT = 0x00000001
USN_SOURCE_REPLICATION_MANAGEMENT = 0x00000004
USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT = 0x00000008

SOURCE_LIST = {
    USN_SOURCE_AUXILIARY_DATA: 'AUXILIARY_DATA',
    USN_SOURCE_DATA_MANAGEMENT: 'DATA_MANAGEMENT',
    USN_SOURCE_REPLICATION_MANAGEMENT: 'REPLICATION_MANAGEMENT',
    USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT: 'CLIENT_REPLICATION_MANAGEMENT'
}

def resolve_reason_codes(reason):
    flags = reason
    parts = []
    for flag in sorted(REASON_LIST.keys()):
        if reason & flag:
            parts.append(REASON_LIST[flag])
            flags &= ~flag
    if flags:
        parts.append(hex(flags))
    return ' | '.join(parts) if parts else ''

def resolve_source_codes(source):
    flags = source
    parts = []
    for flag in sorted(SOURCE_LIST.keys()):
        if source & flag:
            parts.append(SOURCE_LIST[flag])
            flags &= ~flag
    if flags:
        parts.append(hex(flags))
    return ' | '.join(parts) if parts else ''

# --------------------------- USN record classes ---------------------------
class USN_RECORD_V2_OR_V3:
    def __init__(self, buf, is_version_3):
        self.is_version_3 = is_version_3
        self.offset_increment = 16 if is_version_3 else 0
        self.record_raw = buf
        min_len = 62 + self.offset_increment
        if len(buf) < min_len:
            raise ValueError("Buffer too small for USN record")
        self.record_len = struct.unpack('<L', buf[:4])[0]
        if self.record_len < 8 or self.record_len % 8 != 0 or self.record_len > len(buf):
            raise ValueError("Invalid record length")
        major = self.get_major_version()
        if (is_version_3 and major != 3) or (not is_version_3 and major != 2):
            raise ValueError(f"Version mismatch: expected {3 if is_version_3 else 2}, got {major}")

    def get_record_length(self): return self.record_len
    def get_major_version(self): return struct.unpack('<H', self.record_raw[4:6])[0]
    def get_minor_version(self): return struct.unpack('<H', self.record_raw[6:8])[0]

    def get_file_reference_number(self):
        if not self.is_version_3:
            return struct.unpack('<Q', self.record_raw[8:16])[0]
        lo = struct.unpack('<Q', self.record_raw[8:16])[0]
        hi = struct.unpack('<Q', self.record_raw[16:24])[0]
        return (hi << 64) | lo

    def get_parent_file_reference_number(self):
        if not self.is_version_3:
            return struct.unpack('<Q', self.record_raw[16:24])[0]
        lo = struct.unpack('<Q', self.record_raw[24:32])[0]
        hi = struct.unpack('<Q', self.record_raw[32:40])[0]
        return (hi << 64) | lo

    def get_usn(self):
        return struct.unpack('<Q', self.record_raw[24 + self.offset_increment:32 + self.offset_increment])[0]

    def get_timestamp(self):
        ts = struct.unpack('<Q', self.record_raw[32 + self.offset_increment:40 + self.offset_increment])[0]
        return decode_filetime(ts)

    def get_reason(self):
        return struct.unpack('<L', self.record_raw[40 + self.offset_increment:44 + self.offset_increment])[0]

    def get_source_info(self):
        return struct.unpack('<L', self.record_raw[44 + self.offset_increment:48 + self.offset_increment])[0]

    def get_security_id(self):
        return struct.unpack('<L', self.record_raw[48 + self.offset_increment:52 + self.offset_increment])[0]

    def get_file_attributes(self):
        return struct.unpack('<L', self.record_raw[52 + self.offset_increment:56 + self.offset_increment])[0]

    def get_file_name_length(self):
        return struct.unpack('<H', self.record_raw[56 + self.offset_increment:58 + self.offset_increment])[0]

    def get_file_name_offset(self):
        return struct.unpack('<H', self.record_raw[58 + self.offset_increment:60 + self.offset_increment])[0]

    def get_file_name(self):
        off = self.get_file_name_offset()
        length = self.get_file_name_length()
        name_raw = self.record_raw[off:off + length]
        return name_raw.decode('utf-16le', errors='replace')

class USN_RECORD_V4:
    def __init__(self, buf):
        if len(buf) < 80:
            raise ValueError("Buffer too small for USN record v4")
        self.record_raw = buf
        self.record_len = struct.unpack('<L', buf[:4])[0]
        if self.record_len < 8 or self.record_len % 8 != 0 or self.record_len > len(buf):
            raise ValueError("Invalid record length")
        major = self.get_major_version()
        if major != 4:
            raise ValueError(f"Expected version 4, got {major}")

    def get_record_length(self): return self.record_len
    def get_major_version(self): return struct.unpack('<H', self.record_raw[4:6])[0]
    def get_minor_version(self): return struct.unpack('<H', self.record_raw[6:8])[0]

    def get_file_reference_number(self):
        lo = struct.unpack('<Q', self.record_raw[8:16])[0]
        hi = struct.unpack('<Q', self.record_raw[16:24])[0]
        return (hi << 64) | lo

    def get_parent_file_reference_number(self):
        lo = struct.unpack('<Q', self.record_raw[24:32])[0]
        hi = struct.unpack('<Q', self.record_raw[32:40])[0]
        return (hi << 64) | lo

    def get_usn(self):
        return struct.unpack('<Q', self.record_raw[40:48])[0]

    def get_timestamp(self):
        # V4 does not store a timestamp inside the record; it is derived from context.
        # We return empty string.
        return ""

    def get_reason(self):
        return struct.unpack('<L', self.record_raw[48:52])[0]

    def get_source_info(self):
        return struct.unpack('<L', self.record_raw[52:56])[0]

    def get_security_id(self):
        # V4 does not contain security ID; return 0
        return 0

    def get_file_attributes(self):
        # V4 does not contain file attributes; return 0
        return 0

    def get_file_name_length(self):
        # V4 does not contain a file name; return 0
        return 0

    def get_file_name_offset(self):
        return 0

    def get_file_name(self):
        return ""

    def get_remaining_extents(self):
        return struct.unpack('<L', self.record_raw[56:60])[0]

    def get_number_of_extents(self):
        return struct.unpack('<H', self.record_raw[60:62])[0]

    def get_extent_size(self):
        return struct.unpack('<H', self.record_raw[62:64])[0]

def get_usn_record(buf):
    if len(buf) < 8:
        raise ValueError("Buffer too small")
    record_len, major, minor = struct.unpack('<LHH', buf[:8])
    if record_len < 8 or record_len > len(buf):
        raise ValueError("Invalid record length")
    if major == 2:
        return USN_RECORD_V2_OR_V3(buf[:record_len], False)
    elif major == 3:
        return USN_RECORD_V2_OR_V3(buf[:record_len], True)
    elif major == 4:
        return USN_RECORD_V4(buf[:record_len])
    else:
        raise NotImplementedError(f"USN version {major}.{minor} not supported")

# --------------------------- Parser ---------------------------
class ChangeJournalParser:
    def __init__(self, file_object):
        self.file_object = file_object
        self.file_object.seek(0, 2)
        self.file_size = self.file_object.tell()
        self.file_object.seek(0)

    def usn_records(self):
        chunk_size = 8192
        pos = 0
        while pos < self.file_size:
            self.file_object.seek(pos)
            buf = self.file_object.read(chunk_size)
            if not buf:
                break
            # Skip zeroed blocks quickly
            tmp = buf.lstrip(b'\x00')
            if not tmp:
                pos += len(buf)
                continue
            # Align to 8 bytes
            new_pos = pos + len(buf) - len(tmp)
            if new_pos % 8 != 0:
                new_pos -= new_pos % 8
            if new_pos < pos:
                new_pos = pos
            self.file_object.seek(new_pos)
            buf = self.file_object.read(chunk_size)
            if not buf:
                break
            try:
                usn = get_usn_record(buf)
            except (ValueError, NotImplementedError):
                pos = new_pos + 8
                continue
            yield usn
            pos = new_pos + usn.get_record_length()

# --------------------------- Main ---------------------------
def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python usn_parser.py <UsnJrnl_$J_file>")
    input_path = sys.argv[1]
    output_path = input_path + "_output.csv"

    try:
        with open(input_path, "rb") as f:
            parser = ChangeJournalParser(f)
            rows = []
            for rec in parser.usn_records():
                row = {
                    "RecordLength": rec.get_record_length(),
                    "MajorVersion": rec.get_major_version(),
                    "MinorVersion": rec.get_minor_version(),
                    "FileReference": rec.get_file_reference_number(),
                    "ParentReference": rec.get_parent_file_reference_number(),
                    "USN": rec.get_usn(),
                    "Timestamp": rec.get_timestamp(),
                    "ReasonCodes": resolve_reason_codes(rec.get_reason()),
                    "SourceInfo": resolve_source_codes(rec.get_source_info()),
                    "SecurityId": rec.get_security_id(),
                    "FileAttributes": rec.get_file_attributes(),
                    "FileName": rec.get_file_name(),
                }
                # For V4, add extent info if present
                if isinstance(rec, USN_RECORD_V4):
                    row["RemainingExtents"] = rec.get_remaining_extents()
                    row["NumberOfExtents"] = rec.get_number_of_extents()
                    row["ExtentSize"] = rec.get_extent_size()
                else:
                    row["RemainingExtents"] = ""
                    row["NumberOfExtents"] = ""
                    row["ExtentSize"] = ""
                rows.append(row)

        if rows:
            fieldnames = ["RecordLength", "MajorVersion", "MinorVersion", "FileReference",
                          "ParentReference", "USN", "Timestamp", "ReasonCodes", "SourceInfo",
                          "SecurityId", "FileAttributes", "FileName", "RemainingExtents",
                          "NumberOfExtents", "ExtentSize"]
            with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
    except Exception as e:
        sys.exit(f"Error: {e}")

if __name__ == "__main__":
    main()