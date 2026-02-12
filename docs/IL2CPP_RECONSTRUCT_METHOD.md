# IL2CPP Readable Reconstruction Tool

This repository now includes a new MCP tool:

- `il2cpp_reconstruct_method`

It is a one-call workflow for building a readable method report from IL2CPP dump output.

## What It Does

Given `outputDir` + `methodName`, it performs:

1. Find method match in `script.json` and resolve RVA.
2. Infer type name from matched script method (before `$$`).
3. Try reading the type definition from `DummyDll/*.dll`.
4. Optionally run Ghidra native decompile (if `gameAssemblyPath` or `gameDir` is provided).
5. Write a markdown report to:
   - `<outputDir>\readable_reports\<matched_method>.md`

## Inputs

Required:

- `outputDir`: IL2CPP dump directory (must contain `script.json`)
- `methodName`: case-insensitive keyword for script method name

Optional:

- `gameAssemblyPath`: path to `GameAssembly.dll`
- `gameDir`: game root path (used to auto-detect `GameAssembly.dll`)
- `ghidraRoot`: custom Ghidra root
- `javaHome`: custom JAVA_HOME (JDK 21)
- `timeoutSeconds`: Ghidra timeout (default `900`)

## Outputs

Tool text output includes:

- matched method name
- signature (if available)
- RVA
- DummyDll source dll path (if found)
- native pseudocode output path or skip/failure reason
- final report path

Generated report includes:

- method metadata
- C# type structure snippet from DummyDll
- native pseudocode snippet from Ghidra (if available)
- notes about reconstruction limits

## Example MCP Call

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "il2cpp_reconstruct_method",
    "arguments": {
      "outputDir": "F:\\dsnpyForClaude\\tools\\Il2CppDumper\\output\\KotamaAcademyCitadel_20260115_223118",
      "methodName": "Keyboard$$SetCurrentBtn"
    }
  }
}
```

If `gameAssemblyPath` / `gameDir` is not provided, the tool still produces a report with method mapping + DummyDll structure and marks native decompile as skipped.
