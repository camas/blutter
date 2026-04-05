# Unified Ghidra import script for blutter JSON output
# Reads ghidra.json and performs all imports in one pass:
# 1. Create functions with names
# 2. Create PP overlay with labels
# 3. Set PP register constant
# 4. Create class structs with field names
# 5. Type allocator return values
# 6. Create DartThread struct
# 7. Add EOL comments from analysis
# 8. Rename Dart runtime registers in decompiler

import os
import json
import re
from java.math import BigInteger
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    StructureDataType, DWordDataType, QWordDataType,
    PointerDataType, CategoryPath, DataTypeConflictHandler
)
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import HighFunctionDBUtil

# ---- Load JSON ----
script_dir = os.path.dirname(getSourceFile().getAbsolutePath())
json_path = os.path.join(script_dir, "..", "..", "dumps", "blutter-out", "ghidra.json")
if not os.path.exists(json_path):
    json_path = str(askFile("Select ghidra.json", "Open"))

print("Loading %s..." % json_path)
with open(json_path) as f:
    data = json.load(f)

pool_base = data["pool_base"]
print("Pool base: 0x%x" % pool_base)
print("Functions: %d, Stubs: %d, Pool entries: %d, Classes: %d, Comments: %d, Thread offsets: %d" % (
    len(data["functions"]), len(data["stubs"]), len(data["pool_entries"]),
    len(data["classes"]), len(data["comments"]), len(data["thread_offsets"])))

listing = currentProgram.getListing()
mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()
dtm = currentProgram.getDataTypeManager()
sym_table = currentProgram.getSymbolTable()
lang = currentProgram.getLanguage()
ctx = currentProgram.getProgramContext()

# ---- Step 1: Create functions ----
print("\n=== Step 1: Creating functions ===")

# Combine all entries, stubs first
all_fns = []
for entry in data["stubs"]:
    all_fns.append(entry)
for entry in data["functions"]:
    all_fns.append(entry)

# Also build a name lookup for step 1b (post-analysis rename)
name_by_addr = {}
for entry in all_fns:
    name_by_addr[entry["addr"]] = entry["name"]

fn_count = 0
fn_renamed = 0
fn_failed = 0
fn_skipped = 0
fn_errors = []

for entry in all_fns:
    addr = entry["addr"]
    end = entry["end"]
    name = entry["name"]
    if end <= addr:
        fn_skipped += 1
        continue
    a = toAddr(addr)
    e = toAddr(end - 1)
    try:
        listing.clearCodeUnits(a, e, False)
    except Exception as ex:
        if len(fn_errors) < 5:
            fn_errors.append("clear 0x%x: %s" % (addr, ex))
    try:
        disassemble(a)
    except Exception as ex:
        if len(fn_errors) < 5:
            fn_errors.append("disasm 0x%x: %s" % (addr, ex))
    fn = None
    try:
        fn = createFunction(a, name)
    except Exception as ex:
        if len(fn_errors) < 5:
            fn_errors.append("create 0x%x '%s': %s" % (addr, name, ex))
    if not fn:
        fn = fm.getFunctionAt(a)
        if fn:
            try:
                fn.setName(name, SourceType.USER_DEFINED)
                fn_renamed += 1
            except Exception as ex:
                if len(fn_errors) < 5:
                    fn_errors.append("rename 0x%x '%s': %s" % (addr, name, ex))
                fn = None
    if fn:
        fn_count += 1
    else:
        fn_failed += 1
    if (fn_count + fn_failed) % 5000 == 0 and (fn_count + fn_failed) > 0:
        print("  %d created, %d renamed, %d failed..." % (fn_count - fn_renamed, fn_renamed, fn_failed))

print("  Total: %d ok (%d created, %d renamed), %d failed, %d skipped" % (
    fn_count, fn_count - fn_renamed, fn_renamed, fn_failed, fn_skipped))
if fn_errors:
    print("  First errors:")
    for err in fn_errors:
        print("    %s" % err)

# ---- Step 2: PP overlay ----
print("\n=== Step 2: Creating PP overlay ===")
max_offset = max(e["offset"] for e in data["pool_entries"]) if data["pool_entries"] else 0
block_size = max_offset + 8
block_name = "DartObjectPool"
block_addr = toAddr(pool_base)

existing_block = mem.getBlock(block_name)
if existing_block:
    # Remove old symbols
    sym_iter = sym_table.getSymbolIterator(existing_block.getStart(), True)
    while sym_iter.hasNext():
        sym = sym_iter.next()
        if sym.getAddress().compareTo(existing_block.getEnd()) > 0:
            break
        sym.delete()
    mem.removeBlock(existing_block, monitor)

block = mem.createUninitializedBlock(block_name, block_addr, block_size, True)
block.setRead(True)
block.setWrite(False)
block.setExecute(False)

pp_count = 0
for entry in data["pool_entries"]:
    offset = entry["offset"]
    etype = entry["type"]
    entry_addr = block_addr.add(offset)

    # Build label name
    if etype == "string":
        val = entry.get("value", "")
        safe = re.sub(r'[^a-zA-Z0-9_]', '', val[:40].replace(" ", "_").replace("/", "_").replace(".", "_"))
        label = "PP_Str_%s" % safe if safe else "PP_Str_empty_%04x" % offset
    elif etype == "stub":
        label = "PP_Stub_%s" % re.sub(r'[^a-zA-Z0-9_]', '_', entry.get("name", "")[:60])
    elif etype == "field":
        label = "PP_Field_%s" % re.sub(r'[^a-zA-Z0-9_]', '_', entry.get("desc", "field")[:60])
    elif etype == "object":
        desc = entry.get("desc", "")
        label = "PP_Obj_%s" % re.sub(r'[^a-zA-Z0-9_]', '_', desc[:60])
    else:
        label = "PP_%s_%04x" % (etype, offset)

    if len(label) > 120:
        label = label[:120]

    sym_table.createLabel(entry_addr, label, SourceType.USER_DEFINED)

    # Add comment with full description
    desc = entry.get("value", entry.get("name", entry.get("desc", "")))
    if desc:
        cu = listing.getCodeUnitAt(entry_addr)
        if cu:
            cu.setComment(CodeUnit.EOL_COMMENT, str(desc))

    pp_count += 1

print("  %d pool entries labeled" % pp_count)

# ---- Step 3: Set PP constant ----
print("\n=== Step 3: Setting PP register constant ===")
reg_x27 = lang.getRegister("x27")
pp_val = BigInteger.valueOf(pool_base)
pp_set = 0
functions = fm.getFunctions(True)
while functions.hasNext():
    func = functions.next()
    body = func.getBody()
    try:
        ctx.setValue(reg_x27, body.getMinAddress(), body.getMaxAddress(), pp_val)
        pp_set += 1
    except:
        pass
print("  Set PP=0x%x for %d functions" % (pool_base, pp_set))

# ---- Step 4: Class structs ----
print("\n=== Step 4: Creating class structs ===")
dart_category = CategoryPath("/DartAOT/Classes")
dword = DWordDataType()
qword = QWordDataType()

txid = dtm.startTransaction("Import Dart classes")
class_count = 0
class_map = {}  # name -> struct data type

try:
    for cls in data["classes"]:
        name = cls["name"]
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        if not safe_name:
            continue

        fields = cls.get("fields", [])
        size = cls.get("size", 8)

        # Calculate struct size from fields or class size
        if fields:
            max_field_off = max(f["offset"] for f in fields)
            struct_size = max(max_field_off + 4, 8)
        else:
            # Use tagged size (size - 1 for tag) but minimum 8
            struct_size = max(size - 1, 8) if size > 0 else 8

        # Remove existing
        existing = dtm.getDataType(dart_category, safe_name)
        if existing:
            dtm.remove(existing, None)

        struct = StructureDataType(dart_category, safe_name, struct_size)

        for field in fields:
            off = field["offset"]
            fname = field.get("name", "field_%x" % off)
            if off < 0 or off >= struct_size:
                continue
            try:
                struct.replaceAtOffset(off, dword, 4, fname, field.get("type", ""))
            except:
                pass

        dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)
        class_map[name] = struct
        class_count += 1

    dtm.endTransaction(txid, True)
except Exception as e:
    dtm.endTransaction(txid, False)
    print("  Error: %s" % e)

print("  %d class structs created" % class_count)

# ---- Step 5: Type allocators ----
print("\n=== Step 5: Typing allocator return values ===")
alloc_count = 0
functions = fm.getFunctions(True)
while functions.hasNext():
    func = functions.next()
    name = func.getName()
    m = re.match(r'Allocate(\w+?)Stub', name)
    if not m:
        continue
    cls_name = m.group(1)
    struct_dt = class_map.get(cls_name)
    if not struct_dt:
        # Try lookup in dtm
        safe = re.sub(r'[^a-zA-Z0-9_]', '_', cls_name)
        struct_dt = dtm.getDataType(dart_category, safe)
    if struct_dt:
        try:
            func.setReturnType(PointerDataType(struct_dt), SourceType.USER_DEFINED)
            alloc_count += 1
        except:
            pass
print("  %d allocators typed" % alloc_count)

# ---- Step 6: DartThread struct ----
print("\n=== Step 6: Creating DartThread struct ===")
thr_category = CategoryPath("/DartAOT")
thread_offsets = data["thread_offsets"]
if thread_offsets:
    max_thr_off = max(t["offset"] for t in thread_offsets)
    thr_size = max_thr_off + 8

    existing = dtm.getDataType(thr_category, "DartThread")
    if existing:
        dtm.remove(existing, None)

    txid = dtm.startTransaction("Add DartThread")
    try:
        thr = StructureDataType(thr_category, "DartThread", thr_size)
        for t in thread_offsets:
            off = t["offset"]
            name = t["name"]
            try:
                thr.replaceAtOffset(off, qword, 8, name, "")
            except:
                pass
        dtm.addDataType(thr, None)
        dtm.endTransaction(txid, True)
        print("  DartThread: %d bytes, %d fields" % (thr_size, len(thread_offsets)))
    except Exception as e:
        dtm.endTransaction(txid, False)
        print("  Error: %s" % e)

# ---- Step 7: Comments ----
print("\n=== Step 7: Adding comments ===")
comment_count = 0
for entry in data["comments"]:
    addr = toAddr(entry["addr"])
    text = entry["text"]
    cu = listing.getCodeUnitAt(addr)
    if cu:
        cu.setComment(CodeUnit.EOL_COMMENT, text)
        comment_count += 1
    if comment_count % 200000 == 0 and comment_count > 0:
        print("  %d comments..." % comment_count)
print("  %d comments added" % comment_count)

# ---- Step 8: Rename registers ----
print("\n=== Step 8: Renaming Dart registers ===")
RENAMES = {
    "unaff_x15": "dart_sp",
    "unaff_x26": "THR",
    "unaff_x27": "PP",
    "unaff_x28": "HEAP",
    "unaff_w22": "NULL_REG",
    "unaff_x29": "FP",
    "unaff_x30": "LR",
    "in_x15": "dart_sp",
    "in_x26": "THR",
    "in_x27": "PP",
    "in_x28": "HEAP",
}

decomp = DecompInterface()
decomp.openProgram(currentProgram)
rename_count = 0
fn_processed = 0
total_fns = fm.getFunctionCount()

functions = fm.getFunctions(True)
while functions.hasNext():
    func = functions.next()
    fn_processed += 1
    if fn_processed % 5000 == 0:
        print("  %d/%d functions, %d renames..." % (fn_processed, total_fns, rename_count))

    result = decomp.decompileFunction(func, 5, monitor)
    if result is None or not result.decompileCompleted():
        continue
    high_func = result.getHighFunction()
    if high_func is None:
        continue

    for sym in high_func.getLocalSymbolMap().getSymbols():
        name = sym.getName()
        if name in RENAMES:
            try:
                HighFunctionDBUtil.updateDBVariable(sym, RENAMES[name], None, SourceType.USER_DEFINED)
                rename_count += 1
            except:
                pass

decomp.dispose()
print("  %d renames applied" % rename_count)

# ---- Step 9: Fix any remaining unnamed functions ----
print("\n=== Step 9: Fixing unnamed functions ===")
fix_count = 0
for entry in all_fns:
    addr = entry["addr"]
    name = entry["name"]
    a = toAddr(addr)
    fn = fm.getFunctionAt(a)
    if fn and fn.getName().startswith("FUN_"):
        try:
            fn.setName(name, SourceType.USER_DEFINED)
            fix_count += 1
        except:
            pass
    elif not fn:
        # Try creating at this point (post-analysis)
        try:
            fn = createFunction(a, name)
            if fn:
                fix_count += 1
            else:
                fn = fm.getFunctionContaining(a)
                if fn and fn.getEntryPoint() != a:
                    # Address is inside another function - need to split or create label
                    sym_table.createLabel(a, name, SourceType.USER_DEFINED)
                    fix_count += 1
        except:
            pass
print("  Fixed %d functions" % fix_count)

print("\n=== Done ===")
