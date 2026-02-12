// Decompile a function at (imageBase + RVA) and write to a file.
//
// Args:
//   0: rva (decimal or hex string, e.g. "7972768" or "0x79A7A0")
//   1: output file path
//   2: (optional) display name for header/comments

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileAtRva extends ghidra.app.script.GhidraScript {

	private static long parseRva(String text) {
		if (text == null) {
			throw new IllegalArgumentException("rva is required");
		}
		String t = text.trim();
		if (t.startsWith("0x") || t.startsWith("0X")) {
			return Long.parseLong(t.substring(2), 16);
		}
		return Long.parseLong(t, 10);
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args == null || args.length < 2) {
			println("Usage: DecompileAtRva <rva> <outputPath> [name]");
			return;
		}

		long rva = parseRva(args[0]);
		String outPath = args[1];
		String dispName = args.length >= 3 ? args[2] : "";

		Address base = currentProgram.getImageBase();
		Address addr = base.add(rva);

		FunctionManager fm = currentProgram.getFunctionManager();
		Function func = fm.getFunctionAt(addr);
		if (func == null) {
			try {
				func = createFunction(addr, null);
			} catch (Exception e) {
				func = fm.getFunctionAt(addr);
			}
		}
		if (func == null) {
			throw new RuntimeException("Unable to locate/create function at " + addr + " (RVA=0x" + Long.toHexString(rva) + ")");
		}

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(currentProgram);
		ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
		DecompileResults res = ifc.decompileFunction(func, 60, mon);

		if (!res.decompileCompleted()) {
			throw new RuntimeException("Decompile failed: " + res.getErrorMessage());
		}

		String c = res.getDecompiledFunction().getC();

		StringBuilder header = new StringBuilder();
		header.append("// Ghidra decompile output\n");
		if (!dispName.isEmpty()) {
			header.append("// Name: ").append(dispName).append("\n");
		}
		header.append("// RVA: 0x").append(Long.toHexString(rva).toUpperCase()).append("\n");
		header.append("// Address: ").append(addr.toString()).append("\n\n");

		File outFile = new File(outPath);
		File parent = outFile.getParentFile();
		if (parent != null) {
			parent.mkdirs();
		}

		try (BufferedWriter bw = new BufferedWriter(new FileWriter(outFile, StandardCharsets.UTF_8))) {
			bw.write(header.toString());
			bw.write(c);
		}

		println("Wrote decompile to: " + outFile.getAbsolutePath());
	}
}

