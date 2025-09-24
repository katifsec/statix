#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
import math
import hashlib
from collections import Counter, defaultdict, OrderedDict

# ---------- Banner ----------
def print_banner():
    banner = r"""
    ╔══════════════════════════════════════╗
                                                                                             
   d888888o. 8888888 8888888888   .8.    8888888 8888888888  8 8888 `8.`8888.      ,8' 
 .`8888:' `88.     8 8888        .888.         8 8888        8 8888  `8.`8888.    ,8'  
 8.`8888.   Y8     8 8888       :88888.        8 8888        8 8888   `8.`8888.  ,8'   
 `8.`8888.         8 8888      . `88888.       8 8888        8 8888    `8.`8888.,8'    
  `8.`8888.        8 8888     .8. `88888.      8 8888        8 8888     `8.`88888'     
   `8.`8888.       8 8888    .8`8. `88888.     8 8888        8 8888     .88.`8888.     
    `8.`8888.      8 8888   .8' `8. `88888.    8 8888        8 8888    .8'`8.`8888.    
8b   `8.`8888.     8 8888  .8'   `8. `88888.   8 8888        8 8888   .8'  `8.`8888.   
`8b.  ;8.`8888     8 8888 .888888888. `88888.  8 8888        8 8888  .8'    `8.`8888.  
 `Y8888P ,88P'     8 8888.8'       `8. `88888. 8 8888        8 8888 .8'      `8.`8888. 
    ╚══════════════════════════════════════╝
           Statix  -->  Static Analysis Tool
           Creator --> Katifsec 
           Version --> 1.0
           
    """
    print(banner)

# libs (required)
try:
    import lief
except Exception:
    print("ERROR: install 'lief' (pip install lief)")
    raise

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_ARCH_ARM, CS_ARCH_ARM64
except Exception:
    print("ERROR: install 'capstone' (pip install capstone)")
    raise

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
except Exception:
    print("ERROR: install 'rich' (pip install rich)")
    raise

HAS_R2 = True
try:
    import r2pipe
except Exception:
    HAS_R2 = False

console = Console()

# ---------- regexes ----------
RE_IP = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
RE_URL = re.compile(r'\bhttps?://[^\s\'"<>]{6,200}\b', re.IGNORECASE)
RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
RE_BASE64 = re.compile(rb'(?:[A-Za-z0-9+/]{40,}={0,2})')
PRINTABLE_ASCII = re.compile(rb'[\x20-\x7e]{4,}')
RE_UTF16LE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
RE_UTF16BE = re.compile(rb'(?:\x00[\x20-\x7e]){4,}')
RE_RAWBLOB = re.compile(rb'[\x01-\xff]{8,}')  # long raw sequences (we'll filter)
RE_PATHS = re.compile(rb'([a-zA-Z]:\\[^\s\'"<>]{2,200})')  # windows paths
RE_REG = re.compile(rb'HKEY_[A-Z_\\]+')  # simple registry key matches

# suspicious import keywords (network, persistence, injection, stealth)
SUSPICIOUS_IMPORT_KEYWORDS = [
    'Internet', 'WinInet', 'WSA', 'connect', 'socket', 'recv', 'send', 'CreateRemoteThread',
    'VirtualAlloc', 'WriteProcessMemory', 'LoadLibrary', 'GetProcAddress', 'RegSetValue',
    'RegCreateKey', 'SetWindowsHookEx', 'CreateService', 'OpenService', 'StartService',
    'CreateProcess', 'ShellExecute', 'MessageBox', 'NtCreateFile', 'NtWriteVirtualMemory',
    'GetProcAddress','VirtualProtect', 'InternetOpen', 'InternetOpenUrl', 'InternetReadFile'
]

# ---------- helpers ----------
def file_hashes(path):
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                b = f.read(8192)
                if not b:
                    break
                h_md5.update(b); h_sha1.update(b); h_sha256.update(b)
    except Exception:
        return {}
    return {'md5': h_md5.hexdigest(), 'sha1': h_sha1.hexdigest(), 'sha256': h_sha256.hexdigest()}

def entropy(data: bytes):
    if not data:
        return 0.0
    freq = Counter(data)
    ent = 0.0
    length = len(data)
    for _, c in freq.items():
        p = c / length
        ent -= p * math.log2(p)
    return ent

def sliding_entropy(data: bytes, window=256, step=128):
    out = []
    if not data:
        return out
    i = 0
    while i + window <= len(data):
        out.append((i, round(entropy(data[i:i+window]), 3)))
        i += step
    return out

# ---------- string extraction and sanity ----------
def try_decode_bytes(raw: bytes):
    # Try utf-8, latin1 fallbacks
    try:
        return raw.decode('utf-8')
    except Exception:
        try:
            return raw.decode('latin1')
        except Exception:
            return raw.decode('latin1', errors='replace')

def sanitize_string(s: str):
    # drop too many control chars, trim
    if s is None:
        return ""
    s = s.strip()
    # remove long runs of odd unicode replacement chars
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]+', ' ', s)
    # collapse whitespace
    s = re.sub(r'\s{2,}', ' ', s)
    return s

def is_plausible_string(s: str, min_len=4):
    if not s or len(s) < min_len:
        return False
    cnt_non_print = sum(1 for ch in s if ord(ch) < 32 or ord(ch) > 126)
    if cnt_non_print / len(s) > 0.25:
        return False
    # avoid gibberish: require at least 1 letter or digit
    if not re.search(r'[A-Za-z0-9]', s):
        return False
    return True

def extract_strings_from_bytes(data: bytes, min_len=4):
    """
    Returns dict with ascii, utf16le, utf16be, rawblobs, paths, regs.
    ASCII/utf16 returns Counter of decoded strings.
    """
    ascii_list = [m.group() for m in PRINTABLE_ASCII.finditer(data)]
    ascii_decoded = [sanitize_string(try_decode_bytes(x)) for x in ascii_list]
    ascii_filtered = [s for s in ascii_decoded if is_plausible_string(s, min_len)]

    utf16le_list = [m.group() for m in RE_UTF16LE.finditer(data)]
    utf16le_decoded = [sanitize_string(try_decode_bytes(x)) for x in utf16le_list]
    utf16le_filtered = [s for s in utf16le_decoded if is_plausible_string(s, min_len)]

    utf16be_list = [m.group() for m in RE_UTF16BE.finditer(data)]
    utf16be_decoded = [sanitize_string(try_decode_bytes(x)) for x in utf16be_list]
    utf16be_filtered = [s for s in utf16be_decoded if is_plausible_string(s, min_len)]

    rawblobs = []
    for m in RE_RAWBLOB.finditer(data):
        b = m.group()
        # only keep if mixed non-printable and printable (likely encoded blobs) and not huge noise
        if len(b) >= 8 and len(b) <= 4096:
            rawblobs.append(b.hex())

    paths = [try_decode_bytes(m.group()) for m in RE_PATHS.finditer(data)]
    regs = [try_decode_bytes(m.group()) for m in RE_REG.finditer(data)]

    return Counter(ascii_filtered), Counter(utf16le_filtered), Counter(utf16be_filtered), rawblobs, paths, regs

# ---------- LIEF helpers ---------- 
def lief_parse(path):
    try:
        return lief.parse(path)
    except Exception as e:
        console.print(f"[red]LIEF parse failed:[/red] {e}")
        return None

def header_info(binobj, path):
    info = {'path': path}
    if binobj is None:
        return info
    fmt = getattr(binobj, 'format', None)
    info['format'] = fmt.name if fmt else 'unknown'
    try:
        info['arch'] = getattr(binobj.header, 'machine_type', getattr(binobj.header, 'cpu_type', None)).name
    except Exception:
        info['arch'] = 'unknown'
    try:
        info['bits'] = getattr(binobj.header, 'identity_class', None).name
    except Exception:
        info['bits'] = 'unknown'
    if info['format'] == 'PE':
        try:
            info['entrypoint'] = hex(binobj.entrypoint)
            ts = getattr(binobj.header, 'time_date_stamp', None)
            if ts:
                info['timestamp'] = ts
            info['subsystem'] = getattr(binobj.header, 'subsystem', None).name if hasattr(binobj.header, 'subsystem') else None
        except Exception:
            pass
    if info['format'] == 'ELF':
        try:
            info['entrypoint'] = hex(binobj.entrypoint)
        except:
            pass
    return info

def sections_info(binobj):
    out = []
    if not binobj:
        return out
    for s in binobj.sections:
        vaddr = getattr(s, 'virtual_address', None) or getattr(s, 'address', None) or 0
        vsz = getattr(s, 'virtual_size', None) or getattr(s, 'size', None) or 0
        raw_size = getattr(s, 'size', None) or len(getattr(s, 'content', []))
        try:
            content = bytes(s.content) if hasattr(s, 'content') else b''
        except Exception:
            content = b''
        out.append({'name': getattr(s, 'name', None), 'vaddr': int(vaddr) if vaddr else 0,
                    'vaddr_str': hex(vaddr) if vaddr else None, 'vsize': vsz, 'size': raw_size,
                    'entropy': round(entropy(content), 3), 'content_bytes': content})
    return out

def imports_exports(binobj):
    imports = defaultdict(list)
    exports = []
    if not binobj:
        return dict(imports), exports
    try:
        for lib in getattr(binobj, 'imports', []) or []:
            libname = getattr(lib, 'name', None) or str(lib)
            for ent in getattr(lib, 'entries', []) or []:
                try:
                    name = ent.name if getattr(ent, 'name', None) else (f"ord:{ent.ordinal}" if getattr(ent, 'ordinal', None) else str(ent))
                except:
                    name = str(ent)
                imports[libname].append(name)
    except Exception:
        pass
    try:
        if hasattr(binobj, 'exported_functions'):
            for e in binobj.exported_functions:
                exports.append(str(e))
    except Exception:
        pass
    try:
        for sym in getattr(binobj, 'symbols', []) or []:
            if getattr(sym, 'name', None):
                exports.append(getattr(sym, 'name', None))
    except Exception:
        pass
    return dict(imports), exports

# ---------- capstone ----------
def choose_cs_arch(binobj):
    if binobj is None:
        return (CS_ARCH_X86, CS_MODE_64)
    try:
        arch_field = getattr(binobj.header, 'machine_type', getattr(binobj.header, 'cpu_type', None)).name.lower()
    except Exception:
        arch_field = ''
    if any(x in arch_field for x in ('x86_64', 'amd64', 'x64')):
        return (CS_ARCH_X86, CS_MODE_64)
    if any(x in arch_field for x in ('i386', 'i686', 'x86')):
        return (CS_ARCH_X86, CS_MODE_32)
    if 'arm64' in arch_field or 'aarch64' in arch_field:
        return (CS_ARCH_ARM64, CS_MODE_64)
    if 'arm' in arch_field:
        return (CS_ARCH_ARM, CS_MODE_32)
    return (CS_ARCH_X86, CS_MODE_64)

def disasm_bytes(bytes_data, base, arch_mode):
    arch, mode = arch_mode
    try:
        cs = Cs(arch, mode)
    except Exception:
        return []
    cs.skipdata = True
    insns = []
    try:
        for i in cs.disasm(bytes_data, base):
            insns.append((i.address, i.mnemonic, i.op_str, i.size))
    except Exception:
        pass
    return insns

def heuristics_function_starts(insns):
    starts = set()
    for i in range(max(0, len(insns) - 1)):
        a, m, op, _ = insns[i]
        a2, m2, op2, _ = insns[i + 1]
        if m == 'push' and ('rbp' in op or 'ebp' in op):
            if m2 == 'mov' and (('rbp' in op2 and 'rsp' in op2) or ('ebp' in op2 and 'esp' in op2)):
                starts.add(a)
            else:
                starts.add(a)
    for a, m, op, _ in insns:
        if m == 'call' and op.startswith('0x'):
            try:
                starts.add(int(op, 16))
            except:
                pass
    return sorted(starts)

# ---------- radare2 ----------
def r2_funcs(path, deep=True):
    if not HAS_R2:
        return []
    try:
        r2 = r2pipe.open(path, flags=['-2'])
        r2.cmd('e scr.color=false')
        r2.cmd('aa' if deep else 'af')
        funcs = r2.cmdj('aflj') or []
        out = []
        for f in funcs:
            out.append({'name': f.get('name'), 'offset': f.get('offset'), 'size': f.get('size'), 'nrefs': f.get('nrefs', 0)})
        r2.quit()
        return out
    except Exception as e:
        console.print(f"[yellow]r2pipe error:[/yellow] {e}")
        return []

# ---------- interesting items ----------
def find_interesting_strings(data_bytes):
    # decode with latin1 to avoid crashes
    txt = data_bytes.decode('latin1', errors='ignore')
    ips = RE_IP.findall(txt)
    urls = RE_URL.findall(txt)
    emails = RE_EMAIL.findall(txt)
    base64s = [m.group().decode('latin1') for m in RE_BASE64.finditer(data_bytes)]
    # filter IP plausibility (0-255)
    ips2 = []
    for ip in ips:
        parts = ip.split('.')
        ok = True
        for p in parts:
            try:
                v = int(p)
                if v < 0 or v > 255:
                    ok = False
            except:
                ok = False
        if ok:
            ips2.append(ip)
    return {'ips': list(OrderedDict.fromkeys(ips2)),
            'urls': list(OrderedDict.fromkeys(urls)),
            'emails': list(OrderedDict.fromkeys(emails)),
            'base64': base64s}

def detect_packer_or_stub(sections, data_bytes):
    names = [s['name'] or '' for s in sections]
    if any('upx' in (n.lower() if n else '') for n in names):
        return 'UPX'
    if b'UPX!' in data_bytes[:200000]:
        return 'UPX'
    for s in sections:
        if s.get('entropy', 0) > 7.5 and s.get('vsize', 0) > 2000:
            return 'Possible custom packer/high-entropy'
    return None

def find_suspicious_imports(imports_map):
    hits = []
    for lib, funcs in imports_map.items():
        for f in funcs:
            for kw in SUSPICIOUS_IMPORT_KEYWORDS:
                if kw.lower() in str(f).lower():
                    hits.append((lib, f))
    return hits

# ---------- printing ----------
def print_header(info, hashes, packer):
    t = Table.grid()
    t.add_column(ratio=1); t.add_column(ratio=3)
    t.add_row("[bold cyan]Format[/bold cyan]", str(info.get('format')))
    t.add_row("[bold cyan]Arch[/bold cyan]", str(info.get('arch')))
    t.add_row("[bold cyan]Bits[/bold cyan]", str(info.get('bits')))
    if info.get('entrypoint'): t.add_row("[bold cyan]Entry[/bold cyan]", str(info.get('entrypoint')))
    if info.get('timestamp'): t.add_row("[bold cyan]PE Timestamp[/bold cyan]", str(info.get('timestamp')))
    if info.get('subsystem'): t.add_row("[bold cyan]Subsystem[/bold cyan]", str(info.get('subsystem')))
    t.add_row("[bold cyan]MD5[/bold cyan]", hashes.get('md5',''))
    t.add_row("[bold cyan]SHA256[/bold cyan]", hashes.get('sha256',''))
    if packer: t.add_row("[bold red]Packer[/bold red]", f"[red]{packer}[/red]")
    console.print(Panel(t, title="[bold yellow]File Fingerprint & Metadata[/bold yellow]"))

def print_sections(sections):
    tbl = Table(title="[magenta]Sections[/magenta]", box=box.SIMPLE)
    tbl.add_column("Name"); tbl.add_column("Vaddr"); tbl.add_column("Vsize", justify="right"); tbl.add_column("Size", justify="right"); tbl.add_column("Entropy", justify="right"); tbl.add_column("Strings", justify="right")
    for s in sections:
        ent = f"{s.get('entropy'):.3f}" if s.get('entropy') is not None else ""
        tbl.add_row(str(s.get('name') or ''), hex(s.get('vaddr') or 0), str(s.get('vsize') or ''), str(s.get('size') or ''), ent, str(len(s.get('content_strings',[]))))
    console.print(tbl)

def print_imports(imports_map, suspicious_hits):
    tbl = Table(title="[green]Imports Summary[/green]")
    tbl.add_column("Library"); tbl.add_column("Count", justify="right")
    for lib, funcs in sorted(imports_map.items(), key=lambda x:-len(x[1])):
        tbl.add_row(lib, str(len(funcs)))
    console.print(tbl)
    if suspicious_hits:
        s = Table(title="[red]Suspicious imports detected[/red]")
        s.add_column("Library"); s.add_column("Function")
        for lib,f in suspicious_hits:
            s.add_row(f"[red]{lib}[/red]", f"[red]{f}[/red]")
        console.print(s)
    for lib, funcs in sorted(imports_map.items(), key=lambda x:-len(x[1]))[:6]:
        console.print(Panel("\n".join(funcs[:200]), title=f"[blue]{lib} (first 200 funcs)[/blue]", expand=False))

def print_exports(exports):
    if not exports:
        return
    t = Table(title="[red]Exports[/red]")
    t.add_column("Export")
    for e in exports:
        t.add_row(str(e))
    console.print(t)

def print_strings_summary(section_strings, interesting_map, top_n=30):
    # section_strings: dict section_name -> (ascii_cnt, u16_cnt, paths, regs, rawblobs)
    for sec, data in section_strings.items():
        ascii_cnt, u16_cnt, paths, regs, rawblobs = data
        t = Table(title=f"[white]Top strings in {sec} (ascii | utf16)[/white]", show_lines=False)
        t.add_column("ASCII"); t.add_column("count", justify="right"); t.add_column("UTF16LE"); t.add_column("count", justify="right")
        a = ascii_cnt.most_common(top_n); u = u16_cnt.most_common(top_n)
        rows = max(len(a), len(u))
        for i in range(rows):
            ai = a[i][0] if i < len(a) else ""; ac = str(a[i][1]) if i < len(a) else ""
            ui = u[i][0] if i < len(u) else ""; uc = str(u[i][1]) if i < len(u) else ""
            t.add_row(ai, ac, ui, uc)
        console.print(t)
        if paths:
            console.print(Panel("\n".join(paths[:50]), title=f"[blue]{sec} paths[/blue]", expand=False))
        if regs:
            console.print(Panel("\n".join(regs[:50]), title=f"[blue]{sec} registry[/blue]", expand=False))
        if rawblobs:
            console.print(Panel(f"{len(rawblobs)} raw blobs (hex)", title=f"[blue]{sec} raw blobs[/blue]", expand=False))

    # global IOI summary
    if interesting_map['ips'] or interesting_map['urls'] or interesting_map['emails'] or interesting_map['base64']:
        console.print(Panel("[red]Interesting network/IOI items (IPs/URLs/Emails/Base64 blobs)[/red]", title="[bold red]IOI[/bold red]"))
        if interesting_map['ips']:
            console.print("[bold red]IPs:[/bold red] " + ", ".join(set(interesting_map['ips'])))
        if interesting_map['urls']:
            console.print("[bold red]URLs:[/bold red]")
            for u in interesting_map['urls']:
                console.print(Text(u, style="red underline"))
        if interesting_map['emails']:
            console.print("[bold red]Emails:[/bold red] " + ", ".join(set(interesting_map['emails'])))
        if interesting_map['base64']:
            console.print(f"[bold red]Base64-blobs count:[/bold red] {len(interesting_map['base64'])}")

def print_functions_table(combined_funcs, limit=500):
    t = Table(title="[cyan]Functions (combined)[/cyan]", box=box.MINIMAL)
    t.add_column("Src", style="bold")
    t.add_column("Addr")
    t.add_column("Size", justify="right")
    t.add_column("Name/Note")
    shown = 0
    for f in combined_funcs:
        if shown >= limit: break
        src = f.get('source') or ''
        addr = f.get('addr_str') or ''
        size = str(f.get('size') or '')
        name = f.get('name') or ''
        if f.get('suspicious'):
            name = f"[red]{name}[/red]"
        t.add_row(src, addr, size, name)
        shown += 1
    console.print(t)

def print_heuristics(heur_list, chunk_size=50):
    if not heur_list:
        return
    # heur_list are ints / addresses
    for i in range(0, len(heur_list), chunk_size):
        tbl = Table(title="[cyan]Capstone Heuristics Function Starts[/cyan]" + ("" if i == 0 else " (cont.)"), box=box.MINIMAL)
        tbl.add_column("Address", style="bold")
        tbl.add_column("Note")
        for addr in heur_list[i:i+chunk_size]:
            tbl.add_row(hex(addr), "heuristic")
        console.print(tbl)

# ---------- combine/analyze ----------
def analyze(path, use_r2=False, r2_fast=False, no_disasm=False):
    result = {'path': path}
    hashes = file_hashes(path)
    result['hashes'] = hashes

    binobj = lief_parse(path)
    info = header_info(binobj, path)
    result['info'] = info

    try:
        with open(path, 'rb') as fh:
            data = fh.read()
    except Exception as e:
        console.print(f"[red]Read error:[/red] {e}")
        data = b''

    # sections and per-section strings
    secs = sections_info(binobj)
    section_strings = {}
    for s in secs:
        content = s.get('content_bytes', b'') or b''
        ascii_cnt, u16_cnt, u16be_cnt, rawblobs, paths, regs = extract_strings_from_bytes(content)
        # store per-section for printing and mapping
        section_strings[s.get('name') or 'unknown'] = (ascii_cnt, u16_cnt, paths, regs, rawblobs)
        # keep a quick list of strings on the section for count purposes
        s['content_strings'] = ascii_cnt + u16_cnt
    result['sections'] = secs
    result['section_strings'] = {k: {'ascii_top': v[0].most_common(100), 'utf16_top': v[1].most_common(100), 'paths': v[2], 'regs': v[3], 'rawblobs_count': len(v[4])} for k, v in section_strings.items()}

    # sliding entropy for whole file and sections
    result['sliding_entropy'] = sliding_entropy(data, window=512, step=256)
    for s in secs:
        try:
            s['entropy_map'] = sliding_entropy(s.get('content_bytes', b'') or b'', window=256, step=128)
        except Exception:
            s['entropy_map'] = []

    # packer detection
    packer = detect_packer_or_stub(secs, data)
    result['packer'] = packer

    # imports/exports
    imports_map, exports = imports_exports(binobj)
    result['imports'] = imports_map; result['exports'] = exports

    # suspicious imports
    susp_imports = find_suspicious_imports(imports_map)
    result['susp_imports'] = susp_imports

    # global strings (whole file)
    ascii_cnt_all, u16_cnt_all, u16be_cnt_all, rawblobs_all, paths_all, regs_all = extract_strings_from_bytes(data)
    result['strings'] = {'ascii_top': ascii_cnt_all.most_common(200), 'utf16_top': u16_cnt_all.most_common(200), 'paths_top': list(OrderedDict.fromkeys(paths_all))[:200], 'regs_top': list(OrderedDict.fromkeys(regs_all))[:200], 'rawblobs_count': len(rawblobs_all)}

    # interesting IOI
    interesting = find_interesting_strings(data)
    result['interesting'] = interesting

    # radare2
    r2_list = []
    if use_r2:
        r2_list = r2_funcs(path, deep=not r2_fast)
    result['r2'] = r2_list

    # disasm heuristics
    cap_addrs = []
    heur_insns = []
    if not no_disasm and binobj is not None:
        arch_mode = choose_cs_arch(binobj)
        code_secs = []
        for s in getattr(binobj, 'sections', []):
            n = (s.name or '').lower()
            if '.text' in n or 'code' in n or 'upx' in n:
                code_secs.append(s)
        if not code_secs and binobj is not None:
            code_secs = sorted(binobj.sections, key=lambda x: getattr(x, 'virtual_size', getattr(x, 'size', 0)), reverse=True)[:1]
        all_insns = []
        for s in code_secs:
            try:
                base = getattr(s, 'virtual_address', 0) or 0
                content = bytes(s.content) if hasattr(s, 'content') else b''
                insns = disasm_bytes(content, base, arch_mode)
                all_insns.extend(insns)
            except Exception:
                pass
        heur_insns = all_insns
        cap_addrs = heuristics_function_starts(all_insns)

    result['heur_addrs'] = cap_addrs

    # lief funcs/symbols
    lief_funcs = []
    try:
        if binobj is not None:
            if hasattr(binobj, 'exported_functions'):
                for e in binobj.exported_functions:
                    lief_funcs.append({'source': 'lief.export', 'addr': None, 'addr_str': None, 'size': None, 'name': str(e)})
            if hasattr(binobj, 'symbols'):
                for s in binobj.symbols:
                    if getattr(s, 'name', None):
                        val = getattr(s, 'value', None)
                        addr_int = val if isinstance(val, int) else None
                        addr_str = hex(val) if val else None
                        lief_funcs.append({'source': 'lief.sym', 'addr': addr_int, 'addr_str': addr_str, 'size': getattr(s, 'size', None), 'name': getattr(s, 'name', None)})
    except Exception:
        pass
    result['lief_funcs'] = lief_funcs

    # combine functions dedupe by address then name and estimate size for heuristics
    combined = []
    seen = set()
    # r2 first
    for f in r2_list:
        addr = f.get('offset')
        addr_str = hex(addr) if isinstance(addr, int) else str(addr)
        combined.append({'source': 'r2', 'addr': addr, 'addr_str': addr_str, 'size': f.get('size'), 'name': f.get('name')})
        if isinstance(addr, int):
            seen.add(addr)
    # lief
    for f in lief_funcs:
        a = f.get('addr')
        a_int = None
        try:
            if isinstance(a, str) and a.startswith('0x'):
                a_int = int(a, 16)
            elif isinstance(a, int):
                a_int = a
        except:
            a_int = None
        if a_int and a_int in seen:
            continue
        combined.append(f)
        if a_int:
            seen.add(a_int)
    # capstone heuristics (only add if not seen)
    for a in cap_addrs:
        if a in seen:
            continue
        combined.append({'source': 'heur', 'addr': a, 'addr_str': hex(a), 'size': None, 'name': f'heur_{hex(a)}'})
        seen.add(a)

    # convert addr_str to int helper
    def addr_to_int(x):
        a = x.get('addr')
        if isinstance(a, int):
            return a
        try:
            return int(str(x.get('addr_str')), 16)
        except Exception:
            return None

    # sort by address
    combined_sorted = sorted(combined, key=lambda x: (addr_to_int(x) or 2**60))
    # estimate sizes for heuristic entries by distance to next function
    for i, f in enumerate(combined_sorted):
        if f.get('size') is None:
            start = addr_to_int(f) or 0
            next_addr = addr_to_int(combined_sorted[i + 1]) if i + 1 < len(combined_sorted) else None
            if next_addr:
                f['size'] = max(0, next_addr - start)
            else:
                f['size'] = None

    # Build function VA ranges for mapping strings to functions
    func_ranges = []
    for i, f in enumerate(combined_sorted):
        start = addr_to_int(f)
        if start is None:
            continue
        # end = next start or start+estimated size or large sentinel
        if i + 1 < len(combined_sorted):
            end = addr_to_int(combined_sorted[i + 1]) or (start + (f.get('size') or 0))
        else:
            end = start + (f.get('size') or 0) + 0x1000
        if end <= start:
            end = start + (f.get('size') or 0) + 0x100
        func_ranges.append((start, end, f))

    # Map strings (with virtual addresses where possible) to functions
    # We extracted section strings; scan each section: for each ascii match we can compute vaddr = section.vaddr + offset of match
    # Build a quick index: for each section, find offset of string bytes and convert to VA, then map
    mapped_string_count = 0
    all_strings = []  # dicts with vaddr(if available), str
    for s in secs:
        sec_name = s.get('name') or 'unknown'
        sec_vaddr = s.get('vaddr') or 0
        content = s.get('content_bytes') or b''
        if not content:
            continue
        # find ASCII matches positions
        for m in PRINTABLE_ASCII.finditer(content):
            raw = m.group()
            try:
                dec = try_decode_bytes(raw)
            except:
                dec = raw.decode('latin1', errors='ignore')
            dec = sanitize_string(dec)
            if not is_plausible_string(dec):
                continue
            off = m.start()
            vaddr = sec_vaddr + off
            all_strings.append({'vaddr': vaddr, 'vaddr_str': hex(vaddr), 'str': dec, 'section': sec_name})
    # now map those strings to functions by range
    for sdict in all_strings:
        va = sdict.get('vaddr')
        if va is None:
            continue
        for start, end, f in func_ranges:
            if start <= va < end:
                f.setdefault('strings', []).append(sdict['str'])
                mapped_string_count += 1
                break

    # Tag suspicious functions: if they reference IOIs or suspicious imports
    suspicious_keywords = set([kw.lower() for kw in SUSPICIOUS_IMPORT_KEYWORDS])
    for f in combined_sorted:
        tags = []
        name = (f.get('name') or '').lower()
        # name matches
        if any(kw in name for kw in suspicious_keywords):
            tags.append('suspicious_import_name')
        # imports -> if function name references import names (simple heuristic)
        for lib, funcs in imports_map.items():
            for imp in funcs:
                if f.get('name') and imp and imp.lower() in (f.get('name') or '').lower():
                    tags.append('xref_import')
        # strings referencing URLs or IPs inside function
        if f.get('strings'):
            for ss in f['strings']:
                if RE_URL.search(ss) or RE_IP.search(ss) or RE_EMAIL.search(ss):
                    tags.append('references_ioc')
        if tags:
            f['suspicious'] = True
            f['tags'] = list(set(tags))
        else:
            f['suspicious'] = False
            f['tags'] = []

    result['combined_funcs'] = combined_sorted
    result['mapped_string_count'] = mapped_string_count
    result['all_strings_count'] = len(all_strings)

    # save some extras for JSON / printing
    result['section_strings_raw'] = {k: {'ascii': v[0].most_common(200), 'utf16': v[1].most_common(200), 'paths': v[2], 'regs': v[3], 'rawblobs': v[4][:50]} for k, v in section_strings.items()}
    result['global_strings_preview'] = {'ascii_top': ascii_cnt_all.most_common(200), 'utf16_top': u16_cnt_all.most_common(200)}

    # PRINT results - friendly console
    print_header(info, hashes, packer)
    print_sections(secs)
    print_imports(imports_map, susp_imports)
    print_exports(exports)
    print_strings_summary(section_strings, interesting)
    print_functions_table(combined_sorted, limit=1000)
    print_heuristics(cap_addrs)

    return result

# ---------- CLI ----------
def main():
    print_banner()
    p = argparse.ArgumentParser(description="statix - fingerprint & static OSINT analyzer ")
    p.add_argument("binary", help="path to binary (.exe .dll .elf .so)")
    p.add_argument("--use-r2", action='store_true', help="use radare2 for functions (optional, needs r2 installed)")
    p.add_argument("--r2-fast", action='store_true', help="use faster r2 analysis (af) instead of aa")
    p.add_argument("--no-disasm", action='store_true', help="skip capstone disasm heuristics")
    p.add_argument("--json", help="save report as JSON")
    args = p.parse_args()

    if not os.path.exists(args.binary):
        console.print(f"[red]File not found:[/red] {args.binary}")
        sys.exit(2)

    res = analyze(args.binary, use_r2=args.use_r2, r2_fast=args.r2_fast, no_disasm=args.no_disasm)
    if args.json:
        try:
            with open(args.json, 'w', encoding='utf-8') as fh:
                json.dump(res, fh, indent=2, ensure_ascii=False)
            console.print(f"[green]Wrote JSON: {args.json}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to write JSON: {e}[/red]")

if __name__ == "__main__":
    main()
