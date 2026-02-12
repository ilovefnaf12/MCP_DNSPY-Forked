# IL2CPP Semantic Lift Tool

New MCP tool:

- `il2cpp_semantic_lift_method`

This tool improves native pseudocode readability by mapping self-pointer offsets to field names from DummyDll metadata.

## Purpose

Raw Ghidra pseudocode often looks like:

- `param_1 + 0x50`
- `param_1 + 0x90`

`il2cpp_semantic_lift_method` transforms these into direct field expressions like:

- `self.JumpOnPress`

This is not source recovery, but it is usually enough to reason about method behavior much faster.

## Inputs

Required:

- `outputDir`
- `methodName`

Optional:

- `gameAssemblyPath`
- `gameDir`
- `ghidraRoot`
- `javaHome`
- `timeoutSeconds`

## Behavior

1. Match method in `script.json`.
2. Infer owner type from method name (`Type$$Method`).
3. Read owner type from `DummyDll` and parse `[FieldOffset]` attributes.
4. Load native pseudocode file from:
   - `<outputDir>\native_decompile\<matched>.c`
5. If missing and `gameAssemblyPath` / `gameDir` provided, auto-decompile via Ghidra.
6. Rewrite:
   - replace primary decompiled function name (`FUN_xxx`) with method name from script.json `Signature`
   - replace called decompiled function names (`FUN_xxx`, `func_0x...`) with script metadata names when call address can be mapped back to script.json RVA
   - replace `param_N` with parameter names from script.json `Signature` when available
   - for instance methods, `param_1` becomes `self` (mapped from `__this`)
   - replace de-referenced `self + 0xXX` expressions with `self.<Field>` when offset is known.
7. Apply strict local rename rules (accuracy-first):
   - only rename locals that are single-assignment direct aliases of `self.<Field>`
   - skip ambiguous or multi-assignment locals
8. Write report:
   - `<outputDir>\readable_reports\<matched>.lifted.md`

## Output Summary

Tool response includes:

- matched method
- RVA
- number of parsed field symbols
- number of referenced field symbols in lifted pseudocode
- whether function name replacement was applied
- number of called function renames applied
- number of parameter renames applied
- number of strict local renames applied
- report path
- lifted code preview

## Example

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "il2cpp_semantic_lift_method",
    "arguments": {
      "outputDir": "F:\\dsnpyForClaude\\tools\\Il2CppDumper\\output\\SHINOBI_AOV_20260212_172702",
      "methodName": "PlayerContext$$ResetRequests",
      "gameDir": "E:\\SteamLibrary\\steamapps\\common\\SHINOBI_AOV"
    }
  }
}
```
