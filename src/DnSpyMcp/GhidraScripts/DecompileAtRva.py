#
# Deprecated in Ghidra 12 headless: `.py` runs via PyGhidra provider which requires PyGhidra.
# Keep for reference; DnSpyMcp uses `DecompileAtRva.java` to avoid external Python dependencies.

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def parse_rva(text):
    t = (text or "").strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 10)

def main():
    args = getScriptArgs()
    if args is None or len(args) < 2:
        print("Usage: DecompileAtRva.py <rva> <outputPath> [name]")
        return

    rva = parse_rva(args[0])
    out_path = args[1]
    disp_name = args[2] if len(args) >= 3 else ""

    base = currentProgram.getImageBase()
    addr = base.add(rva)

    fm = currentProgram.getFunctionManager()
    func = fm.getFunctionAt(addr)
    if func is None:
        try:
            func = createFunction(addr, None)
        except:
            func = fm.getFunctionAt(addr)

    if func is None:
        raise Exception("Unable to locate/create function at %s (RVA=0x%x)" % (addr, rva))

    # Decompile
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    res = ifc.decompileFunction(func, 60, monitor)

    if not res.decompileCompleted():
        raise Exception("Decompile failed: " + str(res.getErrorMessage()))

    cfunc = res.getDecompiledFunction()
    text = cfunc.getC()

    header = []
    header.append("// Ghidra decompile output")
    if disp_name:
        header.append("// Name: " + disp_name)
    header.append("// RVA: 0x%X" % rva)
    header.append("// Address: " + str(addr))
    header.append("")

    try:
        fh = open(out_path, "w")
        fh.write("\n".join(header))
        fh.write(text)
        fh.close()
    except:
        # Fallback: attempt java file write
        from java.io import FileWriter, BufferedWriter
        bw = BufferedWriter(FileWriter(out_path))
        bw.write("\n".join(header))
        bw.write(text)
        bw.close()

    print("Wrote decompile to: " + out_path)

main()
