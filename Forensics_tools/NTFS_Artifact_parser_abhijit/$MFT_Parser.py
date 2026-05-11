#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import csv
import sys
from datetime import datetime, timedelta, timezone

# --------------------------- Attributes module (simplified) ---------------------------
class AttributeTypes:
    ATTR_TYPE_STANDARD_INFORMATION = 0x10
    ATTR_TYPE_ATTRIBUTE_LIST = 0x20
    ATTR_TYPE_FILE_NAME = 0x30
    ATTR_TYPE_OBJECT_ID = 0x40
    ATTR_TYPE_SECURITY_DESCRIPTOR = 0x50
    ATTR_TYPE_VOLUME_NAME = 0x60
    ATTR_TYPE_VOLUME_INFORMATION = 0x70
    ATTR_TYPE_DATA = 0x80
    ATTR_TYPE_INDEX_ROOT = 0x90
    ATTR_TYPE_INDEX_ALLOCATION = 0xA0
    ATTR_TYPE_BITMAP = 0xB0
    ATTR_TYPE_REPARSE_POINT = 0xC0
    ATTR_TYPE_EA_INFORMATION = 0xD0
    ATTR_TYPE_EA = 0xE0
    ATTR_TYPE_LOGGED_UTILITY_STREAM = 0x100

    AttributeTypes = {
        ATTR_TYPE_STANDARD_INFORMATION: ('$STANDARD_INFORMATION', None),
        ATTR_TYPE_ATTRIBUTE_LIST: ('$ATTRIBUTE_LIST', None),
        ATTR_TYPE_FILE_NAME: ('$FILE_NAME', None),
        ATTR_TYPE_OBJECT_ID: ('$OBJECT_ID', None),
        ATTR_TYPE_SECURITY_DESCRIPTOR: ('$SECURITY_DESCRIPTOR', None),
        ATTR_TYPE_VOLUME_NAME: ('$VOLUME_NAME', None),
        ATTR_TYPE_VOLUME_INFORMATION: ('$VOLUME_INFORMATION', None),
        ATTR_TYPE_DATA: ('$DATA', None),
        ATTR_TYPE_INDEX_ROOT: ('$INDEX_ROOT', None),
        ATTR_TYPE_INDEX_ALLOCATION: ('$INDEX_ALLOCATION', None),
        ATTR_TYPE_BITMAP: ('$BITMAP', None),
        ATTR_TYPE_REPARSE_POINT: ('$REPARSE_POINT', None),
        ATTR_TYPE_EA_INFORMATION: ('$EA_INFORMATION', None),
        ATTR_TYPE_EA: ('$EA', None),
        ATTR_TYPE_LOGGED_UTILITY_STREAM: ('$LOGGED_UTILITY_STREAM', None),
    }

def decode_filetime(ft):
    """Convert Windows FILETIME to Python datetime (UTC)."""
    if ft == 0:
        return None
    try:
        windows_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        seconds = ft / 10_000_000.0
        return windows_epoch + timedelta(seconds=seconds)
    except:
        return None

class StandardInformation:
    def __init__(self, data):
        if len(data) >= 48:
            self.created, self.modified, self.mft_changed, self.accessed = struct.unpack('<QQQQ', data[:32])
            self.file_attributes = struct.unpack('<L', data[32:36])[0] if len(data) > 32 else 0
            self.alloc_size = struct.unpack('<Q', data[40:48])[0] if len(data) >= 48 else 0
        else:
            self.created = self.modified = self.mft_changed = self.accessed = 0
            self.file_attributes = 0
            self.alloc_size = 0

    def get_created(self): return decode_filetime(self.created)
    def get_modified(self): return decode_filetime(self.modified)
    def get_mft_changed(self): return decode_filetime(self.mft_changed)
    def get_accessed(self): return decode_filetime(self.accessed)
    def get_alloc_size(self): return self.alloc_size

class FileName:
    def __init__(self, data):
        if len(data) >= 66:
            self.parent_ref = struct.unpack('<Q', data[0:8])[0]
            self.created = struct.unpack('<Q', data[8:16])[0]
            self.modified = struct.unpack('<Q', data[16:24])[0]
            self.mft_changed = struct.unpack('<Q', data[24:32])[0]
            self.accessed = struct.unpack('<Q', data[32:40])[0]
            self.alloc_size = struct.unpack('<Q', data[40:48])[0]
            self.data_size = struct.unpack('<Q', data[48:56])[0]
            self.flags = struct.unpack('<L', data[56:60])[0]
            self.name_length = struct.unpack('B', data[64:65])[0]
            name_start = 66
            if len(data) >= name_start + self.name_length * 2:
                name_raw = data[name_start:name_start + self.name_length * 2]
                self.name = name_raw.decode('utf-16le', errors='replace')
            else:
                self.name = ""
        else:
            self.parent_ref = 0
            self.name = ""

    def get_parent_directory(self): return self.parent_ref
    def get_file_name(self): return self.name
    def get_flags(self): return self.flags

# --------------------------- MFT parsing helpers ---------------------------
FILE_RECORD_SEGMENT_SIZES_SUPPORTED = [1024, 4096]
MULTI_SECTOR_HEADER_SIGNATURE_GOOD = b'FILE'
MULTI_SECTOR_HEADER_SIGNATURES_SUPPORTED = [MULTI_SECTOR_HEADER_SIGNATURE_GOOD, b'BAAD', b'CHKD']
UPDATE_SEQUENCE_STRIDE = 512
FILE_RECORD_SEGMENT_IN_USE = 1
FILE_FILE_NAME_INDEX_PRESENT = 2
FORM_CODE_RESIDENT = 0
FORM_CODE_NONRESIDENT = 1

def decode_mapping_pairs(mapping_pairs):
    data_runs = []
    i = 0
    curr_offset = 0
    while i < len(mapping_pairs):
        header_byte = mapping_pairs[i]
        if header_byte == 0:
            break
        i += 1
        count_length = header_byte & 0x0F
        offset_length = header_byte >> 4
        if count_length == 0 or count_length > 8 or offset_length > 8:
            raise ValueError("Invalid mapping pair")
        count = int.from_bytes(mapping_pairs[i:i+count_length], 'little', signed=True)
        i += count_length
        if offset_length > 0:
            offset = int.from_bytes(mapping_pairs[i:i+offset_length], 'little', signed=True)
            i += offset_length
        else:
            offset = None
        if offset is None:
            data_runs.append((None, count))
        else:
            curr_offset += offset
            data_runs.append((curr_offset, count))
    return data_runs

class AttributeRecordResident:
    def __init__(self, type_code, name, value):
        self.type_code = type_code
        self.name = name
        self.value = value
    def type_str(self):
        return AttributeTypes.AttributeTypes.get(self.type_code, (hex(self.type_code), None))[0]
    def value_decoded(self):
        if self.type_code == 0x10:          # $STANDARD_INFORMATION
            return StandardInformation(self.value)
        elif self.type_code == 0x30:        # $FILE_NAME
            return FileName(self.value)
        else:
            return None

class AttributeRecordNonresident:
    def __init__(self, type_code, name, mapping_pairs, lowest_vcn, highest_vcn, file_size, is_merged=False):
        self.type_code = type_code
        self.name = name
        self.lowest_vcn = lowest_vcn
        self.highest_vcn = highest_vcn
        self.file_size = file_size
        if not is_merged:
            self.mapping_pairs = mapping_pairs
            self.data_runs = decode_mapping_pairs(mapping_pairs)
    def type_str(self):
        return AttributeTypes.AttributeTypes.get(self.type_code, (hex(self.type_code), None))[0]

class FileRecordSegment:
    def __init__(self, buf, suggested_mft_number=None):
        self.frs_data = bytearray(buf)
        if len(buf) not in FILE_RECORD_SEGMENT_SIZES_SUPPORTED:
            raise ValueError("Invalid FRS size")
        self.usa_offset, self.usa_size = struct.unpack('<HH', self.frs_data[4:8])
        signature = self.frs_data[0:4]
        if signature not in MULTI_SECTOR_HEADER_SIGNATURES_SUPPORTED:
            raise ValueError("Invalid signature")
        self.short_version = self.usa_offset < 48
        self.suggested_mft_number = suggested_mft_number
        self._apply_update_sequence_array()
        self._validate_header()

    def _apply_update_sequence_array(self):
        seq_num = self.frs_data[self.usa_offset:self.usa_offset+2]
        for i in range(1, self.usa_size):
            update = self.frs_data[self.usa_offset + i*2 : self.usa_offset + i*2 + 2]
            sector_offset = i * UPDATE_SEQUENCE_STRIDE - 2
            self.frs_data[sector_offset] = update[0]
            self.frs_data[sector_offset+1] = update[1]

    def _validate_header(self):
        pass

    def is_bad(self):
        return self.frs_data[:4] != MULTI_SECTOR_HEADER_SIGNATURE_GOOD

    def is_base_file_record_segment(self):
        return self.get_base_file_record_segment() == 0

    def is_in_use(self):
        return (self.get_flags() & FILE_RECORD_SEGMENT_IN_USE) != 0

    def get_master_file_table_number(self):
        if self.short_version:
            return self.suggested_mft_number
        hi, lo = struct.unpack('<HL', self.frs_data[42:48])
        return (hi << 32) | lo

    def get_sequence_number(self):
        return struct.unpack('<H', self.frs_data[16:18])[0]

    def get_flags(self):
        return struct.unpack('<H', self.frs_data[22:24])[0]

    def get_base_file_record_segment(self):
        return struct.unpack('<Q', self.frs_data[32:40])[0]

    def get_first_attribute_offset(self):
        return struct.unpack('<H', self.frs_data[20:22])[0]

    def get_first_free_byte_offset(self):
        return struct.unpack('<L', self.frs_data[24:28])[0]

    def get_logfile_sequence_number(self):
        return struct.unpack('<Q', self.frs_data[8:16])[0]

    def attributes(self):
        pos = self.get_first_attribute_offset()
        end = self.get_first_free_byte_offset()
        while pos < end:
            header = self.frs_data[pos:pos+16]
            if len(header) < 16:
                break
            type_code, record_length, form_code, name_len, name_off, flags, instance = struct.unpack('<LLBBHHH', header)
            if type_code == 0xFFFFFFFF:
                break
            if record_length < 16 or pos + record_length > end:
                break
            name = None
            if name_len > 0:
                name_raw = self.frs_data[pos+name_off : pos+name_off + name_len*2]
                name = name_raw.decode('utf-16le', errors='replace')
            if form_code == FORM_CODE_RESIDENT:
                value_len, value_off, _, _ = struct.unpack('<LHBB', self.frs_data[pos+16:pos+24])
                value = self.frs_data[pos+value_off : pos+value_off+value_len]
                yield AttributeRecordResident(type_code, name, value)
            else:
                if pos + 64 > end:
                    break
                lowest_vcn, highest_vcn, mapping_pairs_offset, comp_unit, reserved, allocated, filesize, valid = struct.unpack('<QQHB5sqqq', self.frs_data[pos+16:pos+64])
                mapping_pairs = self.frs_data[pos+mapping_pairs_offset : pos+record_length]
                yield AttributeRecordNonresident(type_code, name, mapping_pairs, lowest_vcn, highest_vcn, filesize)
            pos += record_length

class FileRecord:
    def __init__(self, base_frs, child_frs_list):
        self.base_frs = base_frs
        self.child_frs_list = child_frs_list

    def attributes(self, merge_attributes=False):
        for attr in self.base_frs.attributes():
            yield attr
        for child in self.child_frs_list:
            for attr in child.attributes():
                yield attr

    def get_data_size(self, data_attribute_name=None):
        for attr in self.attributes():
            if attr.type_code == 0x80 and ((data_attribute_name is None and attr.name is None) or (attr.name == data_attribute_name)):
                if hasattr(attr, 'file_size'):
                    return attr.file_size
                elif hasattr(attr, 'value'):
                    return len(attr.value)
        return None

    def is_in_use(self):
        return self.base_frs.is_in_use()

    def get_flags(self):
        return self.base_frs.get_flags()

    def get_master_file_table_number(self):
        return self.base_frs.get_master_file_table_number()

class MasterFileTableParser:
    def __init__(self, file_object, do_first_pass=True):
        self.file_object = file_object
        self.child_cache = {}
        self.file_object.seek(0)
        signature = self.file_object.read(4)
        if signature != MULTI_SECTOR_HEADER_SIGNATURE_GOOD:
            raise ValueError("Invalid MFT signature")
        self.file_object.seek(28)
        self.file_record_segment_size = struct.unpack('<L', self.file_object.read(4))[0]
        if self.file_record_segment_size not in FILE_RECORD_SEGMENT_SIZES_SUPPORTED:
            raise ValueError("Unsupported FRS size")
        self.file_object.seek(0, 2)
        self.file_size = self.file_object.tell()
        self.file_object.seek(0)
        if do_first_pass:
            self._first_pass()

    def _first_pass(self):
        pos = 0
        while pos < self.file_size:
            self.file_object.seek(pos)
            buf = self.file_object.read(self.file_record_segment_size)
            if len(buf) != self.file_record_segment_size:
                break
            try:
                frs = FileRecordSegment(buf, suggested_mft_number=pos // self.file_record_segment_size)
            except:
                pos += self.file_record_segment_size
                continue
            if not frs.is_base_file_record_segment():
                parent_ref = frs.get_base_file_record_segment()
                child_num = pos // self.file_record_segment_size
                self.child_cache.setdefault(parent_ref, []).append(child_num)
            pos += self.file_record_segment_size

    def get_file_record_segment_by_number(self, num):
        offset = num * self.file_record_segment_size
        if offset >= self.file_size:
            raise ValueError("Invalid FRS number")
        self.file_object.seek(offset)
        buf = self.file_object.read(self.file_record_segment_size)
        return FileRecordSegment(buf, suggested_mft_number=num)

    def file_records(self, in_use_file_records_only=False):
        pos = 0
        while pos < self.file_size:
            self.file_object.seek(pos)
            buf = self.file_object.read(self.file_record_segment_size)
            if len(buf) != self.file_record_segment_size:
                break
            try:
                frs = FileRecordSegment(buf, suggested_mft_number=pos // self.file_record_segment_size)
            except:
                pos += self.file_record_segment_size
                continue
            if in_use_file_records_only and not frs.is_in_use():
                pos += self.file_record_segment_size
                continue
            if frs.is_base_file_record_segment():
                mft_num = frs.get_master_file_table_number()
                seq_num = frs.get_sequence_number()
                ref = (seq_num << 48) | mft_num
                child_list = self.child_cache.get(ref, [])
                child_frss = [self.get_file_record_segment_by_number(c) for c in child_list]
                yield FileRecord(frs, child_frss)
            pos += self.file_record_segment_size

# --------------------------- CSV export ---------------------------
def filetime_to_iso(ft):
    if ft is None or ft == 0:
        return ""
    dt = decode_filetime(ft)
    return dt.isoformat() if dt else ""

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python MFTFileParser.py <MFT_file>")
    
    input_file = sys.argv[1]
    output_file = input_file + "_out.csv"

    try:
        f = open(input_file, 'rb')
    except Exception as e:
        sys.exit(f"Error: Cannot open file - {e}")

    try:
        mft_parser = MasterFileTableParser(f, do_first_pass=True)
    except Exception as e:
        f.close()
        sys.exit(f"Error: Failed to parse MFT - {e}")

    rows = []
    total = 0
    try:
        for file_record in mft_parser.file_records(in_use_file_records_only=False):
            total += 1

            mft_num = file_record.get_master_file_table_number()
            seq_num = file_record.base_frs.get_sequence_number()
            in_use = file_record.is_in_use()
            flags = file_record.get_flags()
            is_dir = bool(flags & FILE_FILE_NAME_INDEX_PRESENT)

            std_info = None
            file_names = []
            for attr in file_record.attributes(merge_attributes=False):
                if attr.type_code == 0x10:
                    decoded = attr.value_decoded()
                    if decoded:
                        std_info = decoded
                elif attr.type_code == 0x30:
                    decoded = attr.value_decoded()
                    if decoded:
                        file_names.append(decoded)

            primary_fn = None
            for fn in file_names:
                if primary_fn is None or (fn.get_flags() & 2):
                    primary_fn = fn
            parent_ref = primary_fn.get_parent_directory() if primary_fn else ""
            file_name = primary_fn.get_file_name() if primary_fn else ""

            created = modified = changed = accessed = ""
            if std_info:
                created = filetime_to_iso(std_info.get_created())
                modified = filetime_to_iso(std_info.get_modified())
                changed = filetime_to_iso(std_info.get_mft_changed())
                accessed = filetime_to_iso(std_info.get_accessed())

            data_size = file_record.get_data_size()
            alloc_size = std_info.get_alloc_size() if std_info else ""

            rows.append({
                'MFTNumber': mft_num,
                'SequenceNumber': seq_num,
                'InUse': in_use,
                'Flags': flags,
                'IsDirectory': is_dir,
                'ParentReference': parent_ref,
                'FileName': file_name,
                'Created': created,
                'Modified': modified,
                'Changed': changed,
                'Accessed': accessed,
                'DataSize': data_size if data_size is not None else "",
                'AllocatedSize': alloc_size,
                'NumberOfFileNames': len(file_names),
                'AttributeCount': sum(1 for _ in file_record.attributes(merge_attributes=False))
            })
    finally:
        f.close()

    if rows:
        fieldnames = ['MFTNumber', 'SequenceNumber', 'InUse', 'Flags', 'IsDirectory',
                      'ParentReference', 'FileName', 'Created', 'Modified', 'Changed',
                      'Accessed', 'DataSize', 'AllocatedSize', 'NumberOfFileNames', 'AttributeCount']
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

if __name__ == '__main__':
    main()