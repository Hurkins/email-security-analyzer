import magic
import os
import io
import re
import yara
import fitz
import humanize
import json
import hashlib
import datetime
import tempfile
from pathlib import Path
from oletools.olevba import VBA_Parser
import zipfile
from oletools.oleid import OleID
import traceback


#  checking if the extension and the raw bytes are contradicting
MIME_TO_EXTENSIONS = {
    "image/jpeg":       {".jpg", ".jpeg"},
    "image/png":        {".png"},
    "image/gif":        {".gif"},
    "image/webp":       {".webp"},
    "application/pdf":  {".pdf"},
    "text/plain":       {".txt"},
    "text/rtf":           {".rtf"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/msword": {".doc"},
    "application/vnd.ms-excel": {".xls"},
    "application/zip":  {".zip", ".docx", ".xlsx", ".pptx"},
    "text/html":        {".html", ".htm"},
    "application/x-ole-storage": {".doc", ".xls", ".ppt"},
}

SUPPORTED_MIMES = set(MIME_TO_EXTENSIONS.keys())
# suspicious extensions in zip files
SUSPICIOUS_EXTENSIONS = {
    # executables — critical
    ".exe":  ("Windows executable",          50),
    ".dll":  ("Windows library",             50),
    ".scr":  ("Windows screensaver/EXE",     50),
    ".com":  ("Windows command executable",  45),
    ".bat":  ("Windows batch script",        40),
    ".cmd":  ("Windows command script",      40),
    ".msi":  ("Windows installer",           40),
    ".ps1":  ("PowerShell script",           45),
    ".vbs":  ("VBScript",                    45),
    ".js":   ("JavaScript",                  35),
    ".jar":  ("Java archive/executable",     45),
    ".elf":  ("Linux executable",            45),

    # scripts
    ".sh":   ("Shell script",                35),
    ".py":   ("Python script",               25),
    ".rb":   ("Ruby script",                 25),
    ".pl":   ("Perl script",                 30),
    ".php":  ("PHP script",                  35),

    # office with macros
    ".doc":  ("Word document OLE",           25),
    ".xls":  ("Excel OLE",                   25),
    ".xlsm": ("Excel with macros",           40),
    ".docm": ("Word with macros",            40),
    ".pptm": ("PowerPoint with macros",      40),

    # other
    ".lnk":  ("Windows shortcut",            45),
    ".iso":  ("Disk image",                  35),
    ".img":  ("Disk image",                  35),
    ".hta":  ("HTML application executable", 50),
    ".wsf":  ("Windows Script File",         45),
    ".url":  ("Internet shortcut",           40),
    ".one":  ("OneNote file — Emotet delivery 2023+", 45),
    ".pdf":  ("pdf file",                    30),
}

# ── result builder ────────────────────────────────────────────────────────────

def build_result(filepath: str) -> dict:
    return {
        "file":      filepath,
        "mime":      None,
        "extension": None,
        "SHA-256": None,
        "saved_path": None,
        "status":    "unknown",
        "checks": {
            "extension_match": None,
            "polyglot":        None,
            "content":         {},
        },
        "findings":  [],
        "score":     0,
    }

# ── helpers ───────────────────────────────────────────────────────────────────

def load_yara_rules(path: str):
    filepaths = {}
    try:
        if os.path.isdir(path):
            for filename in os.listdir(path):
                if filename.endswith(".yar"):
                    namespace = filename.replace(".yar", "")
                    filepaths[namespace] = os.path.join(path,filename)
            return yara.compile(filepaths=filepaths)
        return yara.compile(filepath=path)
    except Exception as e:
        return RuntimeError(f"failed to load YARA rules from {path}: {e}")
glot_yara_rules = load_yara_rules("rules/custom_rules/polyglot/polyglot.yar")
pdf_yara_rules  = load_yara_rules("rules/custom_rules/pdf/malicious_pdf.yar")
maldoc_rules    = load_yara_rules("rules/community_rules/maldocs/")
cve_rules       = load_yara_rules("rules/community_rules/cve_rules")
rtf_rules       = load_yara_rules("rules/custom_rules/RTF")

# ── check 1: mime vs extension ────────────────────────────────────────────────

def extension_rawbytes(result: dict, file_bytes: bytes ):
    filename = result["file"]
    ext = os.path.splitext(filename)[-1].lower()
    mime = magic.from_buffer(file_bytes[:2048], mime=True)

    result["mime"] = mime
    result["extension"] = ext

    if mime not in SUPPORTED_MIMES:
        result["findings"].append(
            f"extension mismatch: {ext} does not match detected type {mime}"
        )
        result["score"] += 90
        result["status"] = "suspicious"
        result["checks"]["extension_match"] = False
        return result
    if ext not in MIME_TO_EXTENSIONS[mime]:
        result["findings"].append(
            f"extension mismatch: {ext} does not match detected type {mime}"
        )
        result["score"] += 90
        result["status"] = "suspicious"
        result["checks"]["extension_match"] = False
    else :
        result["checks"]["extension_match"] = True
    return result

# ── check 2: polyglot ─────────────────────────────────────────────────────────

def polyglot_check(result: dict, file_bytes: bytes) -> dict:
    matches = glot_yara_rules.match(data=file_bytes)

    if matches:
        for m in matches:
            finding = f"polyglot detected: {m.rule}"
            result["findings"].append(finding)

            for s in m.strings:
                result["findings"].append(
                    f" → {s.identifier} at offset {s.instances[0].offset}"
                )
        result["score"] += 50
        result["status"] = "malicious"
        result["checks"]["polyglot"] = True
    else:
        result["checks"]["polyglot"] = False

    return result
# ── CVE analysis ──────────────────────────────────────────────────────────────

def analyse_cve(result: dict, file_bytes: bytes) -> dict:
    try:

        matches = cve_rules.match(data=file_bytes)

        if matches:
            for m in matches:
                result["findings"].append(f"rule name: {m.rule}")
                result["findings"].append(f"rule tag : {', '.join(m.tags)}")
                score = int(m.meta.get("score", 50))
                result["score"] += score
                description = m.meta.get("description", "")
                result["findings"].append(f"rule description: {description}")
    except Exception as e:
        result["findings"].append(f"error from CVE analysis: {e}")

    return result


# ── pdf analysis ──────────────────────────────────────────────────────────────

def analyse_pdf(result:dict, file_bytes: bytes) -> dict:
    content = {}
    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")

        content["pages"] = len(doc)
        content["metadata"] = doc.metadata
        catalog_xref = doc.pdf_catalog()

        catalog = doc.xref_object(catalog_xref, compressed=False)



        # checking with yara rules
        matches = pdf_yara_rules.match(data=file_bytes)
        if matches:
            for m in matches:
               result["findings"].append(f"malicious detected: {m.rule}")


               for s in m.strings:
                    result["findings"].append(
                        f"→ {s.identifier} at offset {s.instances[0].offset}"
                    )
            result["score"] += 50
            result["status"] = "malicious"



        # name encoding
        def decode_pdf_name(name):
            return re.sub(r'#([0-9a-fA-F]{2})',
                            lambda m: chr(int(m.group(1),16)), name)


        # javascript
        for xref in range(1, doc.xref_length()):
            obj = doc.xref_object(xref, compressed=False)
            obj_decode = decode_pdf_name(obj)
            if "/JavaScript" in obj or "/JS" in obj:
                result["findings"].append(f"javascript found in object {xref}e")
                result["score"] += 35
                if doc.xref_is_stream(xref):
                    stream = doc.xref_stream(xref)
                    content[f"js_object_{xref}"] = stream.decode("utf-8", errors="ignore")

            elif "/JavaScript" in obj_decode or "/JS" in  obj_decode:
                result["findings"].append(f"javascript found in object {xref}e")
                result["score"] += 35

        # suspicious_keys

        suspicious_keys = [
            ("/OpenAction", "auto-executes on open",           30),
            ("/AA",         "page-level action triggers",      25),
            ("/AcroForm",   "form with possible JS",           20),
            ("/XFA",        "XFA form independent JS engine",  30),
            ("/ObjStm",     "compressed object stream",        20),
            ("/EmbeddedFile","embedded file present",          45),
            ("/RichMedia",  "rich media exploit vector",       25),
            ("/Launch",     "launch action present",           50),
        ]

        for key, description, score in suspicious_keys:
            if key in catalog:
                result["findings"].append(f"{key}:{description}")
                result["score"] += score

        embed_count = doc.embfile_count()
        if embed_count:
            content["embedded_files"] = embed_count
            result["findings"].append(f"{embed_count} embedded file(s) found")
            result["score"] += 45

        # links
        links = []
        for page_num in range(len(doc)):
            for link in doc[page_num].get_links():
                if link.get("uri"):
                    links.append(link["uri"])

        if links:
            content["links"] = links
            for link in links:
                result["findings"].append(f"external link: {link}")

        doc.close()

    except Exception as e:
        result["findings"].append(f"pdf analysis error: {e}")

    result["checks"]["content"] = content
    return result


def yara_check(result: dict, file_bytess: bytes):
    matches = maldoc_rules.match(data=file_bytess)

    if matches:
        for m in matches:
            result["findings"].append(f"office rules: {m.rule}")
            for s in m.strings:
                result["findings"].append(
                    f"{s.identifier} at offset {s.instances[0].offset}"
                )
    return result


# ── office files analysis ────────────────────────────────────────────────────────────
def analyse_office(result: dict, mime, file_bytes: bytes) -> dict:
    content = {}

    temp =  tempfile.NamedTemporaryFile(
        suffix=next(iter(MIME_TO_EXTENSIONS.get(mime, ".doc"))),
        delete=False
    )
    try:
        tmp.write(file_bytes)
        tmp.flush()
        tmp.close()
        tmp_path = tmp.name
        oid = OleID(tmp_path)
        indicators = oid.check()

        yara_check(result, file_bytes)

        for indicator in indicators:
            if indicator.value and str(indicator.risk).upper() in ("HIGH", "MEDIUM"):
                result["findings"].append(f"found indicators: {indicator.value} <> {indicator.risk}")
                result["score"] += 35

        vba = VBA_Parser(tmp_path)
        if vba.detect_vba_macros():
            content["has_macros"] = True
            result["status"] = "malicious"
            for kw_type, keyword, description in vba.analyze_macros():
                if kw_type == "AutoExec":
                    result["findings"].append(f"auto-exec macro: {keyword}")
                    result["score"] += 40
                elif kw_type == "Suspicious":
                    result["findings"].append(f"suspicious macro keyword: {keyword}")
                    result["score"] += 15
                elif kw_type == "IOC":
                    result["findings"].append(f"IOC in macro: {keyword}")
                    result["score"] += 25

    except Exception as e:
        result["findings"].append(f"office analysis error: {e}")
    finally:
        os.unlink(tmp_path)
    result["checks"]["content"] = content

    return result

# ── rtf analysis ────────────────────────────────────────────────────────────────────
def analyse_rtf(result: dict, file_bytes: bytes):
    try:
        matches = rtf_rules.match(data=file_bytes)
        if matches:
            for m in matches:
                result["findings"].append(f"rtf rule: {m.rule}")
                for s in m.strings:
                    result["findings"].append(
                        f"{s.identifier} at offset {s.instances[0].offset}"
                    )
    except Exception as e:
        result["findings"].append(f"RTF analysis Error: {e}")
    return result

# ── zip analysis ────────────────────────────────────────────────────────────────────

def analyse_zip(result: dict, file_bytes: bytes):
    content = {}
    total_comp = 0
    total_size = 0
    RATIO_THRESHHOLD = 0.01
    SUSPICIOUS_SIZE = 50 * 1024 * 1024
    CRITICAL_SIZE   = 1024 * 1024 * 1024
    try:
        z = zipfile.ZipFile(io.BytesIO(file_bytes))
        content["files"] = []
        for info in z.infolist():
            try:

                if info.flag_bits & 0x1 == 0:
                    compress_size = info.compress_size
                    file_size      = info.file_size
                    total_comp += compress_size
                    total_size += file_size
                    if file_size == 0 and compress_size == 0:
                        continue
                    if file_size == 0 and compress_size > 0:
                        result["findings"].append(f"Suspicious: {info.filename}")
                    if file_size > 0:
                        ratio = info.compress_size / info.file_size
                        if ratio < RATIO_THRESHHOLD:
                            result["findings"].append(f"ratio exceeds threshhold: {info.filename} ratio: {ratio}")
                        content["files"].append({
                        "name": info.filename,
                        "ratio": ratio,
                        "flag byte": info.flag_bits,
                        "compress type": info.compress_type
                        })
                elif info.flag_bits & 0x1 == 1:
                    result["findings"].append(f"encrypted: bit {info.flag_bits}")
                if  ".." in info.filename:
                    result["findings"].append(f"Path traversal detected on file: {info.filename}")


                stem,ext = os.path.splitext(info.filename)
                ext = ext.lower()
                stem = stem.lower()
                if ext in SUSPICIOUS_EXTENSIONS:
                    description, score = SUSPICIOUS_EXTENSIONS[ext]
                    result["findings"].append(f"found {description}: file name ({info.filename})")
                    result["score"] += score
                    double_extension = os.path.splitext(stem)[-1].lower()
                    if double_extension:
                        result["findings"].append("double extensions detected")
                        result["score"] += 45
                bytess = z.read(info.filename)
                mime  = magic.from_buffer(bytess[:2048], mime=True)
                if mime == "application/pdf":
                    polyglot_check(result, bytess)
                    # analyse_cve(result, bytess)
                    analyse_pdf(result, bytess)
                if mime == "text/rtf":
                    polyglot_check(result, bytess)
                    analyse_rtf(result, bytess)
                if mime in ("application/msword",
                    "application/x-ole-storage",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "application/vnd.ms-excel"):
                    polyglot_check(result, bytess)
                    yara_check(result, bytess)
                    analyse_cve(result, bytess)
            except Exception as e:
                tb = e.__traceback__
                details = traceback.extract_tb(tb)[-1]
                line_number = details.lineno
                result["findings"].append(f"Error >> {info.filename}:  => {e} line number {line_number}")
    except zipfile.BadZipFile:
        result["findings"].append("invalid or corrupted ZIP")
    except RuntimeError:
        # password protected - can't open
        result["findings"].append("encrypted ZIP - cannot inspect contents")
        result["score"] += 30
        traceback.print_exc()

    content["total_uncompressed"] = humanize.naturalsize(total_size)
    content["total_compressed"] = humanize.naturalsize(total_comp)
    if total_size == 0:
        result["findings"].append("empty file")
        content["uncompressed ratio"] = "N/A"
    else:
        full_ratio = total_comp / total_size
        content["uncompressed ratio"] = f"{full_ratio:.2f}"
    result["checks"]["content"] = content
    return result


# ── router ────────────────────────────────────────────────────────────────────

def route_content_analysis(result: dict, file_bytes: bytes, filepath: str) -> dict:
    mime = result["mime"]
    if mime == "application/pdf":
        return analyse_pdf(result, file_bytes)

    if mime in ("application/msword",
                "application/x-ole-storage",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/vnd.ms-excel"):
            result = analyse_office(result, mime, file_bytes)
            result = analyse_cve(result, file_bytes)


    if mime == "application/zip":
        result = analyse_zip(result, file_bytes)
        result = analyse_cve(result, file_bytes)
    if mime == "text/rtf":
        result = analyse_rtf(result, file_bytes)
        result = analyse_cve(result, file_bytes)

    return result

# ── score -> status ────────────────────────────────────────────────────────────

def resolve_status(result: dict):
    score = result["score"]

    if score == 0:
        result["status"] = "clean"
    elif score <= 20:
        result["status"] = "low"
    elif score <= 50:
        result["status"] = "medium"
    elif score <= 90:
        result["status"] = "high"
    else:
        result["status"] = "critical"

    return result


# ── handling malicious files ─────────────────────────────────────────────────────

# def quarantine(result: dict, filepath: str, file_bytes: bytes):
#     content = {}
#     content["saved path"] = []
#     try:
#         severity = result['status']
#         sha      = result['SHA-256']
#         now = datetime.datetime.now().strftime("%Y-%m-%d")


#         quarantine_path = "quarantine"
#         os.makedirs(quarantine_path, exist_ok=True)


#         path_by_date    = f"quarantine/{now}"
#         os.makedirs(path_by_date, exist_ok=True)


#         path_by_severity = f"{path_by_date}/{severity}"
#         os.makedirs(path_by_severity, exist_ok=True)


#         filename = os.path.basename(filepath)
#         stem, ext = os.path.splitext(filename)
#         ext = ext.lower()
#         stem= stem.lower()

#         name = f"{stem}-{sha[:8]}"
#         file_dir = f"{path_by_severity}/{name}"
#         os.makedirs(file_dir, exist_ok=True)
#         file_name = f"{stem}-{sha[:8]}{ext}"
#         path = os.path.join(file_dir, file_name)

#         report_path = os.path.join(file_dir, f"{stem}-{sha[:8]}-report.json")

#         with tempfile.NamedTemporaryFile(prefix='temp_report',suffix='.json', delete=False,dir='quarantine') as temp_report:
#             temp_report.write(json.dumps(data, indent=2).encode('utf-8'))
#             temp_report.flush()
#             temp_dir = temp_report.name
#         s.rename(temp_dir, report_path)


#         with open(path, "wb") as fp:
#             fp.write(file_bytes)
#         content["saved path"].append(f"file saved to {path}")

#         result["checks"]["content"] = content
#         result["saved_path"] = f"file saved to {path}"
#     except Exception as e:
#         tb = e.__traceback__
#         details = traceback.extract_tb(tb)[-1]
#         line_number = details.lineno
#         result["findings"].append(f"qurantine Error: {e} line number {line_number}")

#     return result
# ── called from pipeline ────────────────────────────────────────────────────────

def analyze_bytes(filename: str, file_bytes:bytes):
    result = build_result(filename)
    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    result["SHA-256"] = hasher.hexdigest()
    result = extension_rawbytes(result, file_bytes)
    result = polyglot_check(result, file_bytes)
    result = route_content_analysis(result, file_bytes, filename)
    result = resolve_status(result)
    # result = quarantine(result, filename, file_bytes)

    return result

# ── CLI controller ──────────────────────────────────────────────────────────────

def controller(filepath: str) -> dict:
    result = build_result(filepath)
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as fp:
            file_bytes = fp.read()
            hasher.update(file_bytes)
            result["SHA-256"] = hasher.hexdigest()
    except FileNotFoundError:
        result["findings"].append(f"file not found: {filepath}")
        result["status"] = "error"
        return result
    return analyze_bytes(filepath, file_bytes)


# ── display ─────────────────────────────────────────────────────────────────
def display(result: dict):
    print(f"\n{'='*55}")
    print(f"  file      : {result['file']}")
    print(f"  mime      : {result['mime']}")
    print(f"  extension : {result['extension']}")
    print(f"  score     : {result['score']}")
    print(f"  status    : {result['status'].upper()}")
    print(f"  hash      : {result['SHA-256']}")
    print(f"{'='*55}")

    if result["findings"]:
        print(f"\n  findings:")
        for f in result["findings"]:
            print(f"    → {f}")

    checks = result["checks"]
    print(f"\n  checks:")
    print(f"    extension match : {checks['extension_match']}")
    print(f"    polyglot        : {checks['polyglot']}")

    if checks["content"]:
        print(f"    content         :")
        for k, v in checks["content"].items():
            print(f"      {k}: {v}")

    print(f"{'='*55}\n")


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "test.pdf"
    result = controller(path)
    display(result)