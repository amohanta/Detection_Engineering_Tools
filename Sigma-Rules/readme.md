# Sigma Detection Section Keywords Reference

> This document covers **only the `detection:` section** of Sigma rules â€”
> field names, value modifiers, condition operators, and how they map to
> MiniEDR BRule syntax.  Metadata fields (`title`, `author`, `date`, `tags`,
> `logsource`, etc.) are intentionally excluded.

---

## Table of Contents

1. [Detection Section Structure](#1-detection-section-structure)
2. [Selection Blocks](#2-selection-blocks)
3. [Field Names by Category](#3-field-names-by-category)
   - [process_creation](#31-process_creation)
   - [registry_set / registry_event](#32-registry_set--registry_event)
   - [ps_script / ps_module / ps_classic_start](#33-ps_script--ps_module--ps_classic_start)
   - [dns_query](#34-dns_query)
   - [network_connection](#35-network_connection)
   - [create_remote_thread](#36-create_remote_thread)
   - [image_load](#37-image_load)
   - [wmi_event](#38-wmi_event)
   - [file_event / file_delete / file_access](#39-file_event--file_delete--file_access)
   - [process_access](#310-process_access)
   - [pipe_created](#311-pipe_created)
   - [driver_load](#312-driver_load)
4. [Value Modifiers](#4-value-modifiers)
5. [Condition Operators](#5-condition-operators)
6. [Special Value Syntax](#6-special-value-syntax)
7. [Filter Blocks](#7-filter-blocks)
8. [MiniEDR BRule Mapping](#8-miniedr-brule-mapping)
9. [Conversion Coverage Summary](#9-conversion-coverage-summary)

---

## 1. Detection Section Structure

A Sigma `detection:` block has two parts: **selection blocks** (what to match)
and a **condition** (how to combine them).

```yaml
detection:
  selection_main:           # named selection block
    Image|endswith: '\cmd.exe'
    CommandLine|contains|all:
      - '/c'
      - 'powershell'

  filter_legitimate:        # named filter block (exclusion)
    ParentImage|endswith: '\explorer.exe'

  condition: selection_main and not filter_legitimate
```

Rules may define **multiple named blocks** and combine them in `condition`.
Block names are arbitrary â€” only `condition` and `timeframe` are reserved.
Any block whose name starts with `filter` is treated as an exclusion.

---

## 2. Selection Blocks

### Block as a dict (AND across fields)
All fields in the block must match (implicit AND):
```yaml
selection:
  Image|endswith: '\powershell.exe'
  CommandLine|contains: '-enc'
```

### Block as a list (OR across items)
Each list item is OR'd:
```yaml
selection:
  CommandLine|contains:
    - 'Invoke-Mimikatz'
    - 'sekurlsa::logonpasswords'
    - 'lsadump::dcsync'
```

### List of dicts (OR of AND groups)
Each dict item is AND'd internally; items are OR'd:
```yaml
selection:
  - Image|endswith: '\7z.exe'
    CommandLine|contains: '.dmp'
  - Image|endswith: '\rar.exe'
    CommandLine|contains: '.dump'
```

### Keyword blocks (plain lists without field names)
Used with `keywords` block name â€” matches anywhere in the log:
```yaml
keywords:
  - 'mimikatz'
  - 'sekurlsa'
```

---

## 3. Field Names by Category

Field names are **case-insensitive** in Sigma but conventionally PascalCase.
Counts below are from analysis of ~2,383 real Sigma rules.

### 3.1 `process_creation`
*1,167 rules â€” maps to MiniEDR `processCreate`*

| Field | Usage Count | Description |
|---|---|---|
| `CommandLine` | 1,512 | Full command line of the spawned process |
| `Image` | 939 | Full path of the process executable |
| `OriginalFileName` | 574 | PE OriginalFileName metadata (rename detection) |
| `ParentImage` | 204 | Full path of the parent process |
| `Description` | 71 | PE Description field from version info |
| `ParentCommandLine` | 52 | Command line of the parent process |
| `Product` | 45 | PE Product name from version info |
| `Hashes` | 39 | Process image hash (MD5, SHA1, SHA256, IMPHASH) |
| `IntegrityLevel` | 25 | Process integrity level (Low/Medium/High/System) |
| `Company` | 17 | PE Company name from version info |
| `User` | 12 | User account running the process |
| `ParentUser` | 3 | User account of the parent process |
| `CurrentDirectory` | 2 | Working directory of the process |
| `FileVersion` | 2 | PE FileVersion string |
| `LogonId` | 1 | Logon session ID |

**Most common `CommandLine` modifier combos:**
- `CommandLine|contains` â€” 914 rules (substring match)
- `CommandLine|contains|all` â€” 409 rules (all substrings must be present)
- `CommandLine|contains|windash` â€” 92 rules (treats `-` and `/` as equivalent)
- `CommandLine|endswith` â€” 47 rules
- `CommandLine|re` â€” 36 rules (regex)

---

### 3.2 `registry_set` / `registry_event`
*204 + 32 rules â€” maps to MiniEDR `regValueSet`*

| Field | Usage Count | Description |
|---|---|---|
| `TargetObject` | 346 | Full registry key path being written |
| `Details` | 154 | Registry value data being written |
| `Image` | 9 | Process performing the registry write |
| `EventType` | 7 | Registry operation type (SetValue, CreateKey, etc.) |
| `NewName` | 4 | New name when a key/value is renamed |
| `EventID` | 1 | Windows Event ID |

**Common `TargetObject` patterns:**
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SYSTEM\CurrentControlSet\Services\
HKCU\SOFTWARE\Classes\
SOFTWARE\Microsoft\Windows Defender\
```

---

### 3.3 `ps_script` / `ps_module` / `ps_classic_start`
*160 + 33 + 9 rules â€” maps to MiniEDR `powershellScript`*

| Field | Usage Count | Description |
|---|---|---|
| `ScriptBlockText` | 241 | PowerShell script block content (Script Block Logging) |
| `Payload` | varies | Script payload (classic PowerShell logging) |
| `MessageData` | varies | Event message data |

**Notes:**
- `ps_script` = PowerShell Script Block Logging (Event 4104)
- `ps_module` = PowerShell Module Logging (Event 4103)
- `ps_classic_start` = Classic PowerShell logging (Event 400/800)
- Nearly all rules use `ScriptBlockText|contains` or `ScriptBlockText|contains|all`

---

### 3.4 `dns_query`
*22 rules â€” maps to MiniEDR `dnsQuery`*

| Field | Usage Count | Description |
|---|---|---|
| `QueryName` | 22 | DNS domain name being queried |
| `Image` | 8 | Process making the DNS query |

**Common modifiers:** `endswith` (TLD matching), `contains` (domain substring),
`startswith`, `contains|all`

---

### 3.5 `network_connection`
*51 rules â€” maps to MiniEDR `networkConnect`*

| Field | Usage Count | Description |
|---|---|---|
| `Initiated` | 40 | `true` = outbound, `false` = inbound |
| `Image` | 27 | Process making the connection |
| `DestinationHostname` | 19 | Destination DNS hostname |
| `DestinationPort` | 9 | Destination TCP/UDP port number |
| `SourcePort` | 2 | Source port |
| `DestinationIp` | 2 | Destination IP address (often `cidr` modifier) |
| `CommandLine` | 2 | Command line of connecting process |
| `SourceIsIpv6` | 1 | IPv6 source flag |

**Note:** `Initiated: 'true'` means the process initiated the connection outbound.
Most C2/exfiltration rules filter on `Initiated: 'true'`.

---

### 3.6 `create_remote_thread`
*11 rules â€” maps to MiniEDR `remoteThread`*

| Field | Usage Count | Description |
|---|---|---|
| `TargetImage` | 7 | Process receiving the remote thread |
| `SourceImage` | 7 | Process creating the remote thread |
| `StartModule` | 2 | DLL where thread start address is located |
| `StartAddress` | 1 | Memory address of the thread start routine |

---

### 3.7 `image_load`
*98 rules â€” maps to MiniEDR `imageLoad`*

| Field | Usage Count | Description |
|---|---|---|
| `ImageLoaded` | 103 | Full path of the DLL/module being loaded |
| `Image` | 46 | Process loading the DLL |
| `OriginalFileName` | 6 | PE OriginalFileName of the loaded DLL |
| `Signed` | 5 | Whether the image is signed (`'true'`/`'false'`) |
| `Description` | 3 | PE Description of the loaded DLL |
| `SignatureStatus` | 2 | Signature status string (e.g. `'Expired'`) |
| `Hashes` | 2 | Hash of the loaded image |
| `CommandLine` | 1 | Command line of the loading process |

---

### 3.8 `wmi_event`
*3 rules â€” maps to MiniEDR `wmiActivity`*

| Field | Usage Count | Description |
|---|---|---|
| `Destination` | 3 | WMI event consumer destination/command |
| `EventID` | 1 | Windows Event ID |

---

### 3.9 `file_event` / `file_delete` / `file_access`
*165 + 12 + 7 rules â€” **NOT supported in MiniEDR v45** (no file write/create ETW)*

| Field | Usage Count | Description |
|---|---|---|
| `TargetFilename` | 253 | Full path of the file being created/modified/deleted |
| `Image` | 63 | Process performing the file operation |
| `ParentImage` | 3 | Parent of the process performing file operation |
| `CommandLine` | 2 | Command line of the process |

---

### 3.10 `process_access`
*23 rules â€” **NOT supported in MiniEDR v45** (no OpenProcess ETW, only LSASS)*

| Field | Usage Count | Description |
|---|---|---|
| `CallTrace` | 18 | DLL call stack trace for the access |
| `TargetImage` | 16 | Process being accessed |
| `GrantedAccess` | 15 | Access mask granted (e.g. `0x1010`) |
| `SourceImage` | 12 | Process requesting access |

---

### 3.11 `pipe_created`
*17 rules â€” **NOT supported in MiniEDR v45** (no named pipe ETW)*

| Field | Description |
|---|---|
| `PipeName` | Name of the named pipe being created |
| `Image` | Process creating the pipe |

---

### 3.12 `driver_load`
*10 rules â€” **NOT supported in MiniEDR v45** (no driver load ETW)*

| Field | Description |
|---|---|
| `ImageLoaded` | Full path of the driver being loaded |
| `Hashes` | Driver hash |
| `Signed` | Whether driver is signed |
| `SignatureStatus` | Driver signature status |

---

## 4. Value Modifiers

Modifiers are appended to field names with `|` and transform how values are matched.
Usage counts are from analysis of ~2,383 real Sigma rules.

| Modifier | Count | Meaning | Example |
|---|---|---|---|
| `contains` | 1,825 | Field contains the value as a substring | `CommandLine\|contains: 'mimikatz'` |
| `endswith` | 1,753 | Field ends with the value | `Image\|endswith: '\powershell.exe'` |
| `contains\|all` | 650 | Field contains **all** listed values (AND) | `CommandLine\|contains\|all: ['-enc', '-nop']` |
| `startswith` | 101 | Field starts with the value | `Image\|startswith: 'C:\Windows\Temp\'` |
| `contains\|windash` | 94 | Like `contains` but treats `-` and `/` as identical | `CommandLine\|contains\|windash: '-ExecutionPolicy'` |
| `re` | 69 | Value is a regular expression | `CommandLine\|re: '(?i).*powershell.*-e[ncodmd]{0,5}\s'` |
| `base64offset\|contains` | 7 | Matches base64-encoded versions of the value at all offsets | `ScriptBlockText\|base64offset\|contains: 'IEX'` |
| `all` | 6 | All values in a list must match (standalone) | `\|all: [value1, value2]` |
| `cidr` | 2 | CIDR network range match | `DestinationIp\|cidr: '192.168.0.0/16'` |
| `re\|i` | 1 | Case-insensitive regex | `CommandLine\|re\|i: 'pattern'` |
| `fieldref` | 1 | Compare field value to another field's value | `TargetFilename\|fieldref: Image` |

### Modifier Chaining Rules
- Modifiers chain left-to-right: `Field|mod1|mod2`
- `contains|all` means every value in the list must be found as a substring
- `contains|windash` replaces all occurrences of `-` with either `-` or `/`
- `base64offset|contains` generates three base64 variants (offset 0, 1, 2) and checks all

### No modifier (plain equality)
When no modifier is specified, the match is **exact equality**:
```yaml
IntegrityLevel: High        # exact match
Initiated: 'true'           # exact match (string)
EventType: SetValue         # exact match
```

---

## 5. Condition Operators

The `condition:` field combines named selection/filter blocks.

| Operator | Count | Meaning |
|---|---|---|
| `and` | 899 | Both sides must match |
| `1 of` | 812 | At least one of the named blocks must match |
| `not` | 747 | Negation â€” block must NOT match |
| `all of` | 673 | All named blocks must match |
| `or` | 135 | Either side must match (usually implicit in lists) |

### Pattern Examples

```yaml
# Single block
condition: selection

# Combine two blocks
condition: selection_main and not filter_legit

# One of multiple selections
condition: 1 of selection_*

# All selections required
condition: all of selection_*

# At least one selection, excluding filters
condition: 1 of selection_* and not 1 of filter_*

# Counting (timeframe required)
condition: selection | count() > 5

# Nested groups
condition: (selection_a or selection_b) and not filter
```

### Wildcards in Block Names
`*` can be used as a wildcard in condition block references:
- `1 of selection_*` â€” matches any block starting with `selection_`
- `all of filter_*` â€” matches all blocks starting with `filter_`
- `1 of them` â€” matches any block (equivalent to `1 of *`)
- `all of them` â€” all blocks must match

---

## 6. Special Value Syntax

### Null / None
```yaml
CommandLine: null     # field must be empty/absent
Image: ''             # empty string
```

### Numeric values
```yaml
DestinationPort: 4444          # exact integer
GrantedAccess: '0x1010'        # hex string
```

### Boolean values
```yaml
Initiated: 'true'
Signed: 'false'
```

### Lists (OR within a field)
```yaml
Image|endswith:
  - '\cmd.exe'
  - '\powershell.exe'
  - '\wscript.exe'
```
This means: `Image` ends with any of these values.

### `contains|all` (AND within a field)
```yaml
CommandLine|contains|all:
  - '-ExecutionPolicy'
  - 'Bypass'
  - 'DownloadString'
```
This means: `CommandLine` must contain **all three** substrings.

---

## 7. Filter Blocks

Blocks whose name starts with `filter` are **exclusions**. They are referenced
in `condition` with `not`:

```yaml
detection:
  selection:
    Image|endswith: '\net.exe'
    CommandLine|contains: 'user'

  filter_main:
    ParentImage|endswith: '\services.exe'

  filter_optional:
    Image|startswith: 'C:\Windows\WinSxS\'

  condition: selection and not 1 of filter_*
```

### Common filter patterns
| Pattern | Purpose |
|---|---|
| `filter_main` | Primary exclusion |
| `filter_optional` | Secondary exclusion (sometimes with `allow_list` note) |
| `filter_ms_*` | Microsoft process exclusions |
| `filter_*_paths` | Exclude known-good paths |
| `filter_null` | Exclude when a field is null/empty |

---

## 8. MiniEDR BRule Mapping

This table shows which Sigma fields are supported by `sigma_to_myedr.py`
and how they translate into MiniEDR `BRule` fields.

### 8.1 Supported Mappings

| Sigma Category | Sigma Field | MiniEDR Event | MiniEDR Field | Notes |
|---|---|---|---|---|
| `process_creation` | `Image` | `processCreate` | `child_image` | Substring match |
| `process_creation` | `ParentImage` | `processCreate` | `parent_image` | Substring match |
| `process_creation` | `CommandLine` | `processCreate` | `cmdline_contains` | `\|` for OR, `AND` for AND |
| `process_creation` | `CurrentDirectory` | `processCreate` | `child_path` | Substring match |
| `registry_set` | `TargetObject` | `regValueSet` | `registry` | Substring match |
| `registry_set` | `Details` | `regValueSet` | `registry` | Merged with TargetObject |
| `ps_script` | `ScriptBlockText` | `powershellScript` | `script_contains` | `\|` for OR |
| `ps_module` | `ScriptBlockText` | `powershellScript` | `script_contains` | Same engine |
| `dns_query` | `QueryName` | `dnsQuery` | `domain` | Substring match |
| `dns_query` | `Image` | `dnsQuery` | `dns_process` | Scope alert to process |
| `network_connection` | `DestinationIp` | `networkConnect` | `dest_ip` | Substring match |
| `network_connection` | `DestinationHostname` | `networkConnect` | `dest_ip` | Merged with DestinationIp |
| `network_connection` | `DestinationPort` | `networkConnect` | `dest_port` | Exact integer match |
| `create_remote_thread` | `SourceImage` | `remoteThread` | `parent_image` | Substring match |
| `create_remote_thread` | `TargetImage` | `remoteThread` | `child_image` | Substring match |
| `image_load` | `ImageLoaded` | `imageLoad` | `image_file` | Substring match |
| `image_load` | `Image` | `imageLoad` | `image_process` | Substring match |
| `wmi_event` | `Destination` | `wmiActivity` | `query_contains` | Substring match |

### 8.2 Unsupported Fields (Sigma â†’ MiniEDR gap)

| Sigma Field | Category | Why Not Supported |
|---|---|---|
| `OriginalFileName` | process_creation, image_load | Requires PE metadata parsing from ETW â€” not available in kernel process provider |
| `Hashes` | process_creation, image_load | Requires hash computation â€” not done in real-time ETW stream |
| `IntegrityLevel` | process_creation | Not exposed by kernel process ETW provider (needs token query) |
| `Description`, `Product`, `Company` | process_creation | PE version info not in ETW â€” requires file read at process start |
| `ParentCommandLine` | process_creation | Parent cmdline not in child's ETW event â€” requires separate lookup |
| `Signed`, `SignatureStatus` | image_load | Signature validation not in ETW â€” requires WinVerifyTrust call |
| `Initiated` | network_connection | MiniEDR captures all connections â€” no inbound/outbound flag |
| `GrantedAccess`, `CallTrace` | process_access | No OpenProcess ETW monitoring |
| `TargetFilename` | file_event | No file write/create ETW provider |
| `PipeName` | pipe_created | No named pipe ETW provider |
| `cidr` modifier | network_connection | No CIDR range matching â€” only substring |
| `re` modifier | all | No regex engine â€” substring only |
| `base64offset\|contains` | all | No base64 decoding in rule engine |
| `fieldref` modifier | all | No cross-field comparison |

### 8.3 Unsupported Categories

| Sigma Category | Reason |
|---|---|
| `file_event` | No FileIO write/create ETW provider |
| `file_delete` | No FileIO delete ETW provider |
| `file_access` | ETW file READ exists but no path-based rule filtering |
| `process_access` | No `OpenProcess` ETW (except LSASS open) |
| `pipe_created` | No named pipe creation ETW provider |
| `driver_load` | No kernel driver load ETW provider |
| `registry_delete` | Only RegSetValue (opcode 10) captured â€” not RegDeleteValue |
| `create_stream_hash` | No Alternate Data Stream monitoring |
| `process_tampering` | No process hollowing/doppelgÃ¤nging detection |

---

## 9. Conversion Coverage Summary

From analysis of 2,383 Sigma rules in the `windows/` ruleset:

| Status | Rules | % | Description |
|---|---|---|---|
| âœ… Converted | ~1,715 | 72% | Successfully converted by `sigma_to_myedr.py` |
| âš ï¸ Partial loss | ~400 | 17% | Converted but missing fields like `OriginalFileName`, `IntegrityLevel` |
| âŒ Unsupported | ~668 | 28% | Category not supported in MiniEDR v45 |

### Why rules are skipped (top reasons)
| Reason | Count | Explanation |
|---|---|---|
| `unsupported_category` | 325 | Category like `file_event`, `process_access` not in MiniEDR |
| `unsupported_category:file_event` | 165 | Specifically file write/create rules |
| `no_matching_fields` | 72 | Rule only uses fields MiniEDR can't match (`OriginalFileName`, `Hashes`, etc.) |
| `unsupported_category:process_access` | 23 | LSASS dump detection via access masks |
| `informational` | 10 | Low-signal rules â€” skipped by default |
| `status:deprecated` | varies | Outdated rules |

---

## Quick Reference Card

```
SIGMA FIELD          â†’  MINIEDR FIELD         EVENT TYPE
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Image                â†’  child_image           processCreate
ParentImage          â†’  parent_image          processCreate
CommandLine          â†’  cmdline_contains      processCreate
CurrentDirectory     â†’  child_path            processCreate
TargetObject         â†’  registry              regValueSet
Details              â†’  registry              regValueSet
ScriptBlockText      â†’  script_contains       powershellScript
QueryName            â†’  domain                dnsQuery
Image (dns)          â†’  dns_process           dnsQuery
DestinationIp        â†’  dest_ip               networkConnect
DestinationHostname  â†’  dest_ip               networkConnect
DestinationPort      â†’  dest_port             networkConnect
SourceImage          â†’  parent_image          remoteThread
TargetImage          â†’  child_image           remoteThread
ImageLoaded          â†’  image_file            imageLoad
Image (imgload)      â†’  image_process         imageLoad
Destination          â†’  query_contains        wmiActivity

SIGMA MODIFIER       â†’  MINIEDR EQUIVALENT
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
|contains            â†’  substring match (default behaviour)
|endswith            â†’  substring match (converter strips path)
|startswith          â†’  substring match
|contains|all        â†’  multiple values joined with AND
|contains|windash    â†’  converted as plain contains
|re                  â†’  âŒ not supported (skipped)
|cidr                â†’  âŒ not supported (skipped)
|base64offset        â†’  âŒ not supported (skipped)

SIGMA CONDITION      â†’  MINIEDR EQUIVALENT
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
selection            â†’  all fields in one BRule
and                  â†’  multiple fields in same BRule
or                   â†’  separate | in field value
not filter           â†’  âŒ filters dropped (not converted)
1 of selection_*     â†’  separate BRule per selection block
```
