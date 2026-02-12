# IL2CPP Semantic Bundle Tool

New MCP tool:

- `il2cpp_semantic_bundle_method`

This tool is designed for model-side analysis workflows. It emits a structured JSON bundle with provenance and effect summaries, instead of only human-readable markdown.

## Purpose

When analyzing IL2CPP logic, a lifted code block is useful but not enough.  
This tool produces a machine-oriented semantic package so downstream reasoning can use explicit fields instead of parsing free-form text.

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

1. Resolve method from `script.json`.
2. Infer owner type and parse DummyDll `[FieldOffset]`.
3. Ensure native pseudocode exists (decompile on-demand if needed).
4. Apply symbol lifting:
   - function name from signature
   - parameter names from signature
   - called function name replacements from address->RVA->script metadata
   - self-field replacements from known offsets
   - strict local aliases (`self.<Field>` single-assignment only)
5. Build structured summaries:
   - `effects`: reads/writes/calls/guards
   - `unresolved`: unresolved call tokens / self offsets / param placeholders
   - `callGraph`: shallow root+callee graph with signature/RVA where available
6. Write bundle:
   - `<outputDir>\readable_reports\<matched>.bundle.json`

## Output Highlights

The bundle JSON includes:

- method metadata (matched name, signature, RVA, inferred type)
- full provenance of each replacement category
- effect summaries for quick analysis
- unresolved items with explicit lists
- lifted code text as one field (`liftedCode`)

## Example

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "il2cpp_semantic_bundle_method",
    "arguments": {
      "outputDir": "F:\\dsnpyForClaude\\tools\\Il2CppDumper\\output\\SHINOBI_AOV_20260212_172702",
      "methodName": "BonusStageController$$ChargeBeamImp",
      "gameDir": "E:\\SteamLibrary\\steamapps\\common\\SHINOBI_AOV"
    }
  }
}
```
