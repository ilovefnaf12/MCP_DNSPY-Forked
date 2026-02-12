using System.Text;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using DnSpyMcp.Models;

namespace DnSpyMcp;

public class McpServer
{
    private readonly DecompilerService _decompiler;
    private readonly Il2CppService _il2Cpp;
    private readonly GhidraService _ghidra;
    private readonly JsonSerializerOptions _jsonOptions;
    private StdioFraming _stdioFraming = StdioFraming.Unknown;

    private enum StdioFraming
    {
        Unknown = 0,
        ContentLength = 1,
        JsonLine = 2
    }

    private static readonly List<ToolDefinition> Tools = new()
    {
        new ToolDefinition
        {
            Name = "list_types",
            Description = "List all types (classes, structs, enums, etc.) in a .NET DLL assembly",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "dllPath": {
                        "type": "string",
                        "description": "Path to the DLL file"
                    },
                    "namespace": {
                        "type": "string",
                        "description": "Optional: Filter by namespace prefix"
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Optional: Regex pattern to filter type names"
                    }
                },
                "required": ["dllPath"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "decompile_type",
            Description = "Decompile a specific type (class, struct, interface, etc.) to C# source code",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "dllPath": {
                        "type": "string",
                        "description": "Path to the DLL file"
                    },
                    "typeName": {
                        "type": "string",
                        "description": "Full type name including namespace (e.g., 'UnityEngine.GameObject')"
                    }
                },
                "required": ["dllPath", "typeName"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "decompile_method",
            Description = "Decompile a specific method from a type to C# source code",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "dllPath": {
                        "type": "string",
                        "description": "Path to the DLL file"
                    },
                    "typeName": {
                        "type": "string",
                        "description": "Full type name including namespace"
                    },
                    "methodName": {
                        "type": "string",
                        "description": "Method name to decompile"
                    }
                },
                "required": ["dllPath", "typeName", "methodName"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "search_code",
            Description = "Search for types, methods, properties, or fields by keyword in a DLL",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "dllPath": {
                        "type": "string",
                        "description": "Path to the DLL file"
                    },
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to search for"
                    },
                    "maxResults": {
                        "type": "integer",
                        "description": "Maximum number of results (default: 20)"
                    }
                },
                "required": ["dllPath", "keyword"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "export_assembly",
            Description = "Export entire DLL as a decompiled C# project",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "dllPath": {
                        "type": "string",
                        "description": "Path to the DLL file"
                    },
                    "outputDir": {
                        "type": "string",
                        "description": "Output directory for the decompiled project"
                    }
                },
                "required": ["dllPath", "outputDir"]
            }
            """)
        },
        // IL2CPP Tools
        new ToolDefinition
        {
            Name = "il2cpp_dump",
            Description = "Dump IL2CPP game to extract type information. Use this for Unity games compiled with IL2CPP (has GameAssembly.dll instead of Assembly-CSharp.dll)",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "gameDir": {
                        "type": "string",
                        "description": "Game directory containing GameAssembly.dll, or path to GameAssembly.dll directly"
                    },
                    "metadataPath": {
                        "type": "string",
                        "description": "Optional: Path to global-metadata.dat (auto-detected if not provided)"
                    }
                },
                "required": ["gameDir"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "il2cpp_search",
            Description = "Search in IL2CPP dump output for types, methods, or fields",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "outputDir": {
                        "type": "string",
                        "description": "IL2CPP dump output directory (from il2cpp_dump)"
                    },
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to search for"
                    }
                },
                "required": ["outputDir", "keyword"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "il2cpp_read_type",
            Description = "Read type definition from IL2CPP dump (shows structure but not implementation)",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "dummyDllPath": {
                        "type": "string",
                        "description": "Path to DummyDll from IL2CPP dump output"
                    },
                    "typeName": {
                        "type": "string",
                        "description": "Type name to read"
                    }
                },
                "required": ["dummyDllPath", "typeName"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "il2cpp_get_method_address",
            Description = "Get the memory address of a method from IL2CPP dump (useful for hooking/modding)",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "outputDir": {
                        "type": "string",
                        "description": "IL2CPP dump output directory"
                    },
                    "methodName": {
                        "type": "string",
                        "description": "Method name to find"
                    }
                },
                "required": ["outputDir", "methodName"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "il2cpp_native_decompile",
            Description = "Decompile IL2CPP native method to pseudocode using Ghidra headless (requires Ghidra installed locally).",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "outputDir": {
                        "type": "string",
                        "description": "IL2CPP dump output directory (from il2cpp_dump) that contains script.json"
                    },
                    "methodName": {
                        "type": "string",
                        "description": "Method name keyword to match against script.json ScriptMethod.Name (case-insensitive substring)"
                    },
                    "gameAssemblyPath": {
                        "type": "string",
                        "description": "Path to GameAssembly.dll (if omitted, can be inferred from gameDir)"
                    },
                    "gameDir": {
                        "type": "string",
                        "description": "Game directory used to auto-detect GameAssembly.dll when gameAssemblyPath is not provided"
                    },
                    "ghidraRoot": {
                        "type": "string",
                        "description": "Optional: Ghidra install root directory that contains analyzeHeadless.bat somewhere under it"
                    },
                    "javaHome": {
                        "type": "string",
                        "description": "Optional: JAVA_HOME to use for Ghidra headless; if set, DnSpyMcp will prepend <JAVA_HOME>\\\\bin to PATH for the child process."
                    },
                    "timeoutSeconds": {
                        "type": "integer",
                        "description": "Timeout for Ghidra headless analysis/decompile (default: 900)"
                    }
                },
                "required": ["outputDir", "methodName"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "il2cpp_reconstruct_method",
            Description = "Build a readable IL2CPP method report by combining script.json symbol mapping, DummyDll type structure, and optional native pseudocode from Ghidra.",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "outputDir": {
                        "type": "string",
                        "description": "IL2CPP dump output directory (from il2cpp_dump) that contains script.json and optionally DummyDll"
                    },
                    "methodName": {
                        "type": "string",
                        "description": "Method name keyword to match against script.json ScriptMethod.Name (case-insensitive substring)"
                    },
                    "gameAssemblyPath": {
                        "type": "string",
                        "description": "Optional: Path to GameAssembly.dll for native pseudocode decompile"
                    },
                    "gameDir": {
                        "type": "string",
                        "description": "Optional: Game directory used to auto-detect GameAssembly.dll when gameAssemblyPath is not provided"
                    },
                    "ghidraRoot": {
                        "type": "string",
                        "description": "Optional: Ghidra install root directory that contains analyzeHeadless.bat somewhere under it"
                    },
                    "javaHome": {
                        "type": "string",
                        "description": "Optional: JAVA_HOME to use for Ghidra headless"
                    },
                    "timeoutSeconds": {
                        "type": "integer",
                        "description": "Optional: Timeout for Ghidra headless native decompile (default: 900)"
                    }
                },
                "required": ["outputDir", "methodName"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "il2cpp_semantic_lift_method",
            Description = "Generate lifted pseudocode by mapping native self-pointer offsets to DummyDll field names and writing an annotated report.",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "outputDir": {
                        "type": "string",
                        "description": "IL2CPP dump output directory (from il2cpp_dump) that contains script.json and DummyDll"
                    },
                    "methodName": {
                        "type": "string",
                        "description": "Method name keyword to match against script.json ScriptMethod.Name (case-insensitive substring)"
                    },
                    "gameAssemblyPath": {
                        "type": "string",
                        "description": "Optional: Path to GameAssembly.dll if native pseudocode file does not already exist"
                    },
                    "gameDir": {
                        "type": "string",
                        "description": "Optional: Game directory used to auto-detect GameAssembly.dll when gameAssemblyPath is not provided"
                    },
                    "ghidraRoot": {
                        "type": "string",
                        "description": "Optional: Ghidra install root directory"
                    },
                    "javaHome": {
                        "type": "string",
                        "description": "Optional: JAVA_HOME to use for Ghidra headless"
                    },
                    "timeoutSeconds": {
                        "type": "integer",
                        "description": "Optional: Timeout for Ghidra native decompile when fallback decompile is needed (default: 900)"
                    }
                },
                "required": ["outputDir", "methodName"]
            }
            """)
        },
        new ToolDefinition
        {
            Name = "il2cpp_semantic_bundle_method",
            Description = "Generate a machine-oriented semantic bundle (JSON) with provenance, effects summary, unresolved items, and shallow call graph for one IL2CPP method.",
            InputSchema = JsonSerializer.Deserialize<JsonElement>("""
            {
                "type": "object",
                "properties": {
                    "outputDir": {
                        "type": "string",
                        "description": "IL2CPP dump output directory (from il2cpp_dump) that contains script.json and DummyDll"
                    },
                    "methodName": {
                        "type": "string",
                        "description": "Method name keyword to match against script.json ScriptMethod.Name (case-insensitive substring)"
                    },
                    "gameAssemblyPath": {
                        "type": "string",
                        "description": "Optional: Path to GameAssembly.dll if native pseudocode file does not already exist"
                    },
                    "gameDir": {
                        "type": "string",
                        "description": "Optional: Game directory used to auto-detect GameAssembly.dll when gameAssemblyPath is not provided"
                    },
                    "ghidraRoot": {
                        "type": "string",
                        "description": "Optional: Ghidra install root directory"
                    },
                    "javaHome": {
                        "type": "string",
                        "description": "Optional: JAVA_HOME to use for Ghidra headless"
                    },
                    "timeoutSeconds": {
                        "type": "integer",
                        "description": "Optional: Timeout for Ghidra native decompile when fallback decompile is needed (default: 900)"
                    }
                },
                "required": ["outputDir", "methodName"]
            }
            """)
        }
    };

    public McpServer()
    {
        _decompiler = new DecompilerService();
        _il2Cpp = new Il2CppService();
        _ghidra = new GhidraService();
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        };
    }

    public async Task RunAsync(Stream input, Stream output, CancellationToken cancellationToken = default)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var payload = await ReadMessageAsync(input, cancellationToken);
                if (payload == null) break;

                var request = JsonSerializer.Deserialize<JsonRpcRequest>(payload, _jsonOptions);
                if (request == null) continue;

                var response = await HandleRequestAsync(request);

                if (response != null)
                {
                    var responseJson = JsonSerializer.Serialize(response, _jsonOptions);
                    await SendMessageAsync(output, responseJson, _stdioFraming, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                var errorResponse = new JsonRpcResponse
                {
                    Error = new JsonRpcError
                    {
                        Code = -32700,
                        Message = $"Parse error: {ex.Message}"
                    }
                };
                var errorJson = JsonSerializer.Serialize(errorResponse, _jsonOptions);
                await SendMessageAsync(output, errorJson, _stdioFraming, cancellationToken);
            }
        }
    }

    private async Task<string?> ReadMessageAsync(Stream input, CancellationToken cancellationToken)
    {
        while (true)
        {
            if (_stdioFraming == StdioFraming.JsonLine)
            {
                var lineBytes = await ReadLineBytesAsync(input, cancellationToken);
                if (lineBytes == null) return null;
                if (lineBytes.Length == 0) continue;
                return Encoding.UTF8.GetString(lineBytes);
            }

            // Unknown or Content-Length framing: read the first line and decide.
            var firstLineBytes = await ReadLineBytesAsync(input, cancellationToken);
            if (firstLineBytes == null) return null;
            if (firstLineBytes.Length == 0) continue;

            var firstNonWs = FirstNonWhitespaceByte(firstLineBytes);
            if (firstNonWs == (byte)'{' || firstNonWs == (byte)'[')
            {
                _stdioFraming = StdioFraming.JsonLine;
                return Encoding.UTF8.GetString(firstLineBytes);
            }

            _stdioFraming = StdioFraming.ContentLength;
            int? contentLength = null;

            string? headerLine = Encoding.ASCII.GetString(firstLineBytes);
            while (true)
            {
                if (headerLine == null) return null;
                if (headerLine.Length == 0) break;

                const string ContentLengthPrefix = "Content-Length:";
                if (headerLine.StartsWith(ContentLengthPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    var lengthText = headerLine.Substring(ContentLengthPrefix.Length).Trim();
                    if (!int.TryParse(lengthText, out var length) || length < 0)
                    {
                        throw new InvalidDataException($"Invalid Content-Length header: {headerLine}");
                    }
                    contentLength = length;
                }

                headerLine = await ReadAsciiLineAsync(input, cancellationToken);
            }

            if (contentLength is null)
            {
                throw new InvalidDataException("Missing Content-Length header");
            }

            var buffer = new byte[contentLength.Value];
            await ReadExactlyAsync(input, buffer, 0, buffer.Length, cancellationToken);
            return Encoding.UTF8.GetString(buffer);
        }
    }

    private static async Task SendMessageAsync(Stream output, string json, StdioFraming framing, CancellationToken cancellationToken)
    {
        if (framing == StdioFraming.JsonLine)
        {
            var payload = Encoding.UTF8.GetBytes(json + "\n");
            await output.WriteAsync(payload, 0, payload.Length, cancellationToken);
            await output.FlushAsync(cancellationToken);
            return;
        }

        var body = Encoding.UTF8.GetBytes(json);
        var header = Encoding.ASCII.GetBytes($"Content-Length: {body.Length}\r\n\r\n");

        await output.WriteAsync(header, 0, header.Length, cancellationToken);
        await output.WriteAsync(body, 0, body.Length, cancellationToken);
        await output.FlushAsync(cancellationToken);
    }

    private static async Task<string?> ReadAsciiLineAsync(Stream input, CancellationToken cancellationToken)
    {
        var line = await ReadLineBytesAsync(input, cancellationToken);
        if (line == null) return null;
        return Encoding.ASCII.GetString(line);
    }

    private static async Task<byte[]?> ReadLineBytesAsync(Stream input, CancellationToken cancellationToken)
    {
        var bytes = new List<byte>(256);
        var one = new byte[1];

        while (true)
        {
            var read = await input.ReadAsync(one, 0, 1, cancellationToken);
            if (read == 0)
            {
                if (bytes.Count == 0) return null;
                TrimTrailingCarriageReturn(bytes);
                return bytes.ToArray();
            }

            var b = one[0];
            if (b == (byte)'\n')
            {
                TrimTrailingCarriageReturn(bytes);
                return bytes.ToArray();
            }

            bytes.Add(b);
        }
    }

    private static byte FirstNonWhitespaceByte(byte[] bytes)
    {
        foreach (var b in bytes)
        {
            if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
                continue;
            return b;
        }
        return 0;
    }

    private static void TrimTrailingCarriageReturn(List<byte> bytes)
    {
        if (bytes.Count > 0 && bytes[^1] == (byte)'\r')
        {
            bytes.RemoveAt(bytes.Count - 1);
        }
    }

    private static async Task ReadExactlyAsync(Stream input, byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        var readTotal = 0;
        while (readTotal < count)
        {
            var read = await input.ReadAsync(buffer, offset + readTotal, count - readTotal, cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException($"Unexpected end of stream while reading {count} bytes (got {readTotal}).");
            }
            readTotal += read;
        }
    }

    private async Task<JsonRpcResponse?> HandleRequestAsync(JsonRpcRequest request)
    {
        return request.Method switch
        {
            "initialize" => HandleInitialize(request),
            // Notifications, no response.
            "initialized" => null,
            "notifications/initialized" => null,
            "tools/list" => HandleToolsList(request),
            "tools/call" => await HandleToolCallAsync(request),
            "notifications/cancelled" => null,
            "ping" => HandlePing(request),
            _ => request.Id == null
                ? null
                : new JsonRpcResponse
                {
                    Id = request.Id,
                    Error = new JsonRpcError
                    {
                        Code = -32601,
                        Message = $"Method not found: {request.Method}"
                    }
                }
        };
    }

    private JsonRpcResponse HandlePing(JsonRpcRequest request)
    {
        return new JsonRpcResponse
        {
            Id = request.Id,
            Result = new { }
        };
    }

    private JsonRpcResponse HandleInitialize(JsonRpcRequest request)
    {
        var clientProtocolVersion = TryGetProtocolVersion(request.Params);
        return new JsonRpcResponse
        {
            Id = request.Id,
            Result = new InitializeResult
            {
                ProtocolVersion = string.IsNullOrWhiteSpace(clientProtocolVersion) ? "2024-11-05" : clientProtocolVersion!,
                Capabilities = new ServerCapabilities
                {
                    Tools = new ToolsCapability { ListChanged = false }
                },
                ServerInfo = new ServerInfo
                {
                    Name = "dnspy-mcp",
                    Version = "1.0.0"
                }
            }
        };
    }

    private string? TryGetProtocolVersion(JsonElement? paramsElement)
    {
        if (paramsElement == null) return null;
        try
        {
            var init = JsonSerializer.Deserialize<InitializeParams>(paramsElement.Value.GetRawText(), _jsonOptions);
            return init?.ProtocolVersion;
        }
        catch
        {
            return null;
        }
    }

    private JsonRpcResponse HandleToolsList(JsonRpcRequest request)
    {
        return new JsonRpcResponse
        {
            Id = request.Id,
            Result = new ToolsListResult { Tools = Tools }
        };
    }

    private async Task<JsonRpcResponse> HandleToolCallAsync(JsonRpcRequest request)
    {
        if (request.Params == null)
        {
            return new JsonRpcResponse
            {
                Id = request.Id,
                Error = new JsonRpcError
                {
                    Code = -32602,
                    Message = "Invalid params"
                }
            };
        }

        var callParams = JsonSerializer.Deserialize<ToolCallParams>(request.Params.Value.GetRawText(), _jsonOptions);
        if (callParams == null)
        {
            return new JsonRpcResponse
            {
                Id = request.Id,
                Error = new JsonRpcError
                {
                    Code = -32602,
                    Message = "Invalid tool call params"
                }
            };
        }

        try
        {
            var result = await ExecuteToolAsync(callParams);
            return new JsonRpcResponse
            {
                Id = request.Id,
                Result = result
            };
        }
        catch (Exception ex)
        {
            return new JsonRpcResponse
            {
                Id = request.Id,
                Result = new ToolCallResult
                {
                    IsError = true,
                    Content = new List<ContentBlock>
                    {
                        new() { Type = "text", Text = $"Error: {ex.Message}" }
                    }
                }
            };
        }
    }

    private async Task<ToolCallResult> ExecuteToolAsync(ToolCallParams callParams)
    {
        var args = callParams.Arguments?.GetRawText() ?? "{}";

        return callParams.Name switch
        {
            "list_types" => await Task.Run(() => ExecuteListTypes(args)),
            "decompile_type" => await Task.Run(() => ExecuteDecompileType(args)),
            "decompile_method" => await Task.Run(() => ExecuteDecompileMethod(args)),
            "search_code" => await Task.Run(() => ExecuteSearchCode(args)),
            "export_assembly" => await Task.Run(() => ExecuteExportAssembly(args)),
            // IL2CPP tools
            "il2cpp_dump" => await Task.Run(() => ExecuteIl2CppDump(args)),
            "il2cpp_search" => await Task.Run(() => ExecuteIl2CppSearch(args)),
            "il2cpp_read_type" => await Task.Run(() => ExecuteIl2CppReadType(args)),
            "il2cpp_get_method_address" => await Task.Run(() => ExecuteIl2CppGetMethodAddress(args)),
            "il2cpp_native_decompile" => await Task.Run(() => ExecuteIl2CppNativeDecompile(args)),
            "il2cpp_reconstruct_method" => await Task.Run(() => ExecuteIl2CppReconstructMethod(args)),
            "il2cpp_semantic_lift_method" => await Task.Run(() => ExecuteIl2CppSemanticLiftMethod(args)),
            "il2cpp_semantic_bundle_method" => await Task.Run(() => ExecuteIl2CppSemanticBundleMethod(args)),
            _ => new ToolCallResult
            {
                IsError = true,
                Content = new List<ContentBlock>
                {
                    new() { Type = "text", Text = $"Unknown tool: {callParams.Name}" }
                }
            }
        };
    }

    private ToolCallResult ExecuteListTypes(string argsJson)
    {
        var input = JsonSerializer.Deserialize<ListTypesInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrEmpty(input.DllPath))
        {
            return ErrorResult("dllPath is required");
        }

        var types = _decompiler.ListTypes(input.DllPath, input.Namespace, input.Pattern);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Found {types.Count} types in {Path.GetFileName(input.DllPath)}:");
        sb.AppendLine();

        var byNamespace = types.GroupBy(t => t.Namespace);
        foreach (var ns in byNamespace.OrderBy(g => g.Key))
        {
            sb.AppendLine($"## {(string.IsNullOrEmpty(ns.Key) ? "(global)" : ns.Key)}");
            foreach (var type in ns)
            {
                var visibility = type.IsPublic ? "public" : "internal";
                sb.AppendLine($"  - {type.Kind} {type.Name} ({visibility}) - {type.MethodCount} methods, {type.PropertyCount} properties");
            }
            sb.AppendLine();
        }

        return TextResult(sb.ToString());
    }

    private ToolCallResult ExecuteDecompileType(string argsJson)
    {
        var input = JsonSerializer.Deserialize<DecompileTypeInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrEmpty(input.DllPath) || string.IsNullOrEmpty(input.TypeName))
        {
            return ErrorResult("dllPath and typeName are required");
        }

        var result = _decompiler.DecompileType(input.DllPath, input.TypeName);

        if (!result.Success)
        {
            return ErrorResult(result.ErrorMessage ?? "Decompilation failed");
        }

        return TextResult($"```csharp\n{result.SourceCode}\n```");
    }

    private ToolCallResult ExecuteDecompileMethod(string argsJson)
    {
        var input = JsonSerializer.Deserialize<DecompileMethodInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrEmpty(input.DllPath) ||
            string.IsNullOrEmpty(input.TypeName) || string.IsNullOrEmpty(input.MethodName))
        {
            return ErrorResult("dllPath, typeName, and methodName are required");
        }

        var result = _decompiler.DecompileMethod(input.DllPath, input.TypeName, input.MethodName);

        if (!result.Success)
        {
            return ErrorResult(result.ErrorMessage ?? "Decompilation failed");
        }

        return TextResult($"```csharp\n{result.SourceCode}\n```");
    }

    private ToolCallResult ExecuteSearchCode(string argsJson)
    {
        var input = JsonSerializer.Deserialize<SearchCodeInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrEmpty(input.DllPath) || string.IsNullOrEmpty(input.Keyword))
        {
            return ErrorResult("dllPath and keyword are required");
        }

        var results = _decompiler.SearchCode(input.DllPath, input.Keyword, input.MaxResults);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Search results for '{input.Keyword}' ({results.Count} matches):");
        sb.AppendLine();

        foreach (var item in results)
        {
            sb.AppendLine($"- [{item.MemberKind}] {item.TypeName}");
            if (!string.IsNullOrEmpty(item.MemberName))
            {
                sb.AppendLine($"  Member: {item.MemberName}");
            }
            sb.AppendLine($"  Context: {item.MatchContext}");
            sb.AppendLine();
        }

        return TextResult(sb.ToString());
    }

    private ToolCallResult ExecuteExportAssembly(string argsJson)
    {
        var input = JsonSerializer.Deserialize<ExportAssemblyInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrEmpty(input.DllPath) || string.IsNullOrEmpty(input.OutputDir))
        {
            return ErrorResult("dllPath and outputDir are required");
        }

        var result = _decompiler.ExportAssembly(input.DllPath, input.OutputDir);

        if (!result.Success)
        {
            return ErrorResult(result.ErrorMessage ?? "Export failed");
        }

        return TextResult($"Successfully exported assembly to {result.OutputPath}\n\nGenerated {result.FileCount} C# files.");
    }

    #region IL2CPP Tools

    private ToolCallResult ExecuteIl2CppDump(string argsJson)
    {
        var input = JsonSerializer.Deserialize<Il2CppDumpInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrEmpty(input.GameDir))
        {
            return ErrorResult("gameDir is required");
        }

        string gameAssembly;
        string metadata;

        // Check if gameDir is directly a GameAssembly.dll path
        if (File.Exists(input.GameDir) && input.GameDir.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            gameAssembly = input.GameDir;
            // Try to find metadata relative to the dll
            var gameDir = Path.GetDirectoryName(gameAssembly) ?? "";
            var (_, detectedMeta) = _il2Cpp.DetectIl2CppFiles(gameDir);
            metadata = input.MetadataPath ?? detectedMeta ?? "";
        }
        else
        {
            // It's a directory, auto-detect files
            var (detectedAssembly, detectedMeta) = _il2Cpp.DetectIl2CppFiles(input.GameDir);
            gameAssembly = detectedAssembly ?? "";
            metadata = input.MetadataPath ?? detectedMeta ?? "";
        }

        if (string.IsNullOrEmpty(gameAssembly))
        {
            return ErrorResult($"Could not find GameAssembly.dll in {input.GameDir}. Please provide the path directly.");
        }

        if (string.IsNullOrEmpty(metadata))
        {
            return ErrorResult($"Could not find global-metadata.dat. Please provide metadataPath parameter.");
        }

        var result = _il2Cpp.DumpIl2Cpp(gameAssembly, metadata);

        if (!result.Success)
        {
            return ErrorResult(result.ErrorMessage ?? "IL2CPP dump failed");
        }

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("IL2CPP dump completed successfully!");
        sb.AppendLine();
        sb.AppendLine($"Output directory: {result.OutputDir}");
        if (result.DummyDllDir != null)
        {
            sb.AppendLine($"DummyDll directory: {result.DummyDllDir}");
        }
        sb.AppendLine();
        sb.AppendLine("Generated files:");
        foreach (var file in result.GeneratedFiles.Take(20))
        {
            sb.AppendLine($"  - {file}");
        }
        if (result.GeneratedFiles.Count > 20)
        {
            sb.AppendLine($"  ... and {result.GeneratedFiles.Count - 20} more files");
        }

        return TextResult(sb.ToString());
    }

    private ToolCallResult ExecuteIl2CppSearch(string argsJson)
    {
        var input = JsonSerializer.Deserialize<Il2CppSearchInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrEmpty(input.OutputDir) || string.IsNullOrEmpty(input.Keyword))
        {
            return ErrorResult("outputDir and keyword are required");
        }

        var results = _il2Cpp.SearchInDump(input.OutputDir, input.Keyword);

        if (results.Count == 0)
        {
            return TextResult($"No matches found for '{input.Keyword}'");
        }

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Search results for '{input.Keyword}' ({results.Count} matches):");
        sb.AppendLine();
        sb.AppendLine("```csharp");
        foreach (var result in results)
        {
            sb.AppendLine(result);
            sb.AppendLine();
        }
        sb.AppendLine("```");

        return TextResult(sb.ToString());
    }

    private ToolCallResult ExecuteIl2CppReadType(string argsJson)
    {
        var input = JsonSerializer.Deserialize<Il2CppReadTypeInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrEmpty(input.DummyDllPath) || string.IsNullOrEmpty(input.TypeName))
        {
            return ErrorResult("dummyDllPath and typeName are required");
        }

        // Use the existing decompiler to read the dummy DLL
        var result = _decompiler.DecompileType(input.DummyDllPath, input.TypeName);

        if (!result.Success)
        {
            return ErrorResult(result.ErrorMessage ?? "Failed to read type from DummyDll");
        }

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("// Note: This is from IL2CPP DummyDll - method bodies are not available");
        sb.AppendLine("// Use il2cpp_get_method_address to get memory addresses for hooking");
        sb.AppendLine();
        sb.AppendLine("```csharp");
        sb.AppendLine(result.SourceCode);
        sb.AppendLine("```");

        return TextResult(sb.ToString());
    }

    private ToolCallResult ExecuteIl2CppGetMethodAddress(string argsJson)
    {
        var input = JsonSerializer.Deserialize<Il2CppMethodAddressInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrEmpty(input.OutputDir) || string.IsNullOrEmpty(input.MethodName))
        {
            return ErrorResult("outputDir and methodName are required");
        }

        var methodInfo = _il2Cpp.GetMethodInfo(input.OutputDir, input.MethodName);

        if (methodInfo == null)
        {
            return TextResult($"Method '{input.MethodName}' not found in script.json. Try searching with il2cpp_search first.");
        }

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Method info for '{input.MethodName}':");
        sb.AppendLine();
        foreach (var (key, value) in methodInfo)
        {
            sb.AppendLine($"  {key}: {value}");
        }

        return TextResult(sb.ToString());
    }

    private sealed class Il2CppNativeDecompileInput
    {
        public string OutputDir { get; set; } = string.Empty;
        public string MethodName { get; set; } = string.Empty;
        public string? GameAssemblyPath { get; set; }
        public string? GameDir { get; set; }
        public string? GhidraRoot { get; set; }
        public string? JavaHome { get; set; }
        public int? TimeoutSeconds { get; set; }
    }

    private ToolCallResult ExecuteIl2CppNativeDecompile(string argsJson)
    {
        var input = JsonSerializer.Deserialize<Il2CppNativeDecompileInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrWhiteSpace(input.OutputDir) || string.IsNullOrWhiteSpace(input.MethodName))
        {
            return ErrorResult("outputDir and methodName are required");
        }

        var outputDir = input.OutputDir;
        if (!Directory.Exists(outputDir))
        {
            return ErrorResult($"outputDir not found: {outputDir}");
        }

        var gameAssemblyPath = ResolveGameAssemblyPath(input.GameAssemblyPath, input.GameDir);

        if (string.IsNullOrWhiteSpace(gameAssemblyPath))
        {
            return ErrorResult("gameAssemblyPath is required (or provide gameDir so it can be auto-detected)");
        }

        if (!_il2Cpp.TryFindMethodRva(outputDir, input.MethodName, out var rva, out var matchedName, out var signature))
        {
            return TextResult($"Method '{input.MethodName}' not found in script.json. Try a shorter keyword (e.g. 'Keyboard$$SetCurrentBtn').");
        }

        var safeName = SanitizeForFileName(matchedName ?? input.MethodName);

        var outFile = Path.Combine(outputDir, "native_decompile", safeName + ".c");
        var timeout = input.TimeoutSeconds ?? 900;

        var result = _ghidra.DecompileAtRva(
            gameAssemblyPath,
            rva,
            outFile,
            displayName: matchedName,
            ghidraRootOverride: input.GhidraRoot,
            javaHomeOverride: input.JavaHome,
            timeoutSeconds: timeout);

        if (!result.Success)
        {
            var err = new StringBuilder();
            err.AppendLine("Native decompile failed.");
            err.AppendLine();
            err.AppendLine(result.ErrorMessage ?? "Unknown error");
            if (!string.IsNullOrWhiteSpace(result.AnalyzeHeadlessPath))
            {
                err.AppendLine($"analyzeHeadless: {result.AnalyzeHeadlessPath}");
            }
            if (!string.IsNullOrWhiteSpace(result.ProjectDir))
            {
                err.AppendLine($"projectDir: {result.ProjectDir}");
            }
            return ErrorResult(err.ToString());
        }

        string snippet = string.Empty;
        try
        {
            snippet = File.ReadAllText(outFile);
            const int maxChars = 6000;
            if (snippet.Length > maxChars)
            {
                snippet = snippet.Substring(0, maxChars) + "\n/* ... truncated ... */\n";
            }
        }
        catch
        {
            // ignore
        }

        var sb = new StringBuilder();
        sb.AppendLine("IL2CPP native decompile completed.");
        sb.AppendLine();
        sb.AppendLine($"Matched: {matchedName}");
        if (!string.IsNullOrWhiteSpace(signature))
        {
            sb.AppendLine($"Signature: {signature}");
        }
        sb.AppendLine($"RVA: 0x{rva:X} ({rva})");
        sb.AppendLine($"Output: {outFile}");
        sb.AppendLine();
        if (!string.IsNullOrWhiteSpace(snippet))
        {
            sb.AppendLine("```c");
            sb.AppendLine(snippet);
            sb.AppendLine("```");
        }

        return TextResult(sb.ToString());
    }

    private ToolCallResult ExecuteIl2CppReconstructMethod(string argsJson)
    {
        var input = JsonSerializer.Deserialize<Il2CppReconstructMethodInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrWhiteSpace(input.OutputDir) || string.IsNullOrWhiteSpace(input.MethodName))
        {
            return ErrorResult("outputDir and methodName are required");
        }

        var outputDir = input.OutputDir;
        if (!Directory.Exists(outputDir))
        {
            return ErrorResult($"outputDir not found: {outputDir}");
        }

        if (!_il2Cpp.TryFindMethodRva(outputDir, input.MethodName, out var rva, out var matchedName, out var signature))
        {
            return TextResult($"Method '{input.MethodName}' not found in script.json. Try a shorter keyword (e.g. 'Keyboard$$SetCurrentBtn').");
        }

        var resolvedName = matchedName ?? input.MethodName;
        var inferredTypeName = InferTypeNameFromScriptMethod(resolvedName);

        string? dummyDllPath = null;
        string? typeCode = null;
        string? typeError = null;
        if (string.IsNullOrWhiteSpace(inferredTypeName))
        {
            typeError = "Could not infer type name from matched method name.";
        }
        else
        {
            var candidates = EnumerateTypeNameCandidates(inferredTypeName);
            if (!TryReadTypeFromDummyDll(outputDir, candidates, out dummyDllPath, out typeCode, out var readTypeError))
            {
                typeError = readTypeError;
            }
        }

        var nativeOutFile = Path.Combine(outputDir, "native_decompile", SanitizeForFileName(resolvedName) + ".c");
        string? nativeSnippet = null;
        string? nativeError = null;
        var gameAssemblyPath = ResolveGameAssemblyPath(input.GameAssemblyPath, input.GameDir);

        if (!string.IsNullOrWhiteSpace(gameAssemblyPath))
        {
            var timeout = input.TimeoutSeconds ?? 900;
            var decompileResult = _ghidra.DecompileAtRva(
                gameAssemblyPath,
                rva,
                nativeOutFile,
                displayName: matchedName,
                ghidraRootOverride: input.GhidraRoot,
                javaHomeOverride: input.JavaHome,
                timeoutSeconds: timeout);

            if (decompileResult.Success)
            {
                nativeSnippet = ReadFileSnippet(nativeOutFile, 6000, "/* ... truncated ... */");
            }
            else
            {
                var errSb = new StringBuilder();
                errSb.AppendLine(decompileResult.ErrorMessage ?? "Unknown native decompile error");
                if (!string.IsNullOrWhiteSpace(decompileResult.AnalyzeHeadlessPath))
                {
                    errSb.AppendLine($"analyzeHeadless: {decompileResult.AnalyzeHeadlessPath}");
                }
                if (!string.IsNullOrWhiteSpace(decompileResult.ProjectDir))
                {
                    errSb.AppendLine($"projectDir: {decompileResult.ProjectDir}");
                }
                nativeError = errSb.ToString().Trim();
            }
        }
        else
        {
            nativeError = "Skipped native pseudocode: gameAssemblyPath missing. Provide gameAssemblyPath or gameDir.";
        }

        var reportDir = Path.Combine(outputDir, "readable_reports");
        Directory.CreateDirectory(reportDir);
        var reportPath = Path.Combine(reportDir, SanitizeForFileName(resolvedName) + ".md");

        var report = new StringBuilder();
        report.AppendLine("# IL2CPP Readable Method Report");
        report.AppendLine();
        report.AppendLine($"- Method keyword: `{input.MethodName}`");
        report.AppendLine($"- Matched method: `{resolvedName}`");
        if (!string.IsNullOrWhiteSpace(signature))
        {
            report.AppendLine($"- Signature: `{signature}`");
        }
        report.AppendLine($"- RVA: `0x{rva:X}` ({rva})");
        if (!string.IsNullOrWhiteSpace(inferredTypeName))
        {
            report.AppendLine($"- Inferred type: `{inferredTypeName}`");
        }
        report.AppendLine();

        report.AppendLine("## Type Structure (DummyDll)");
        if (!string.IsNullOrWhiteSpace(typeCode))
        {
            report.AppendLine($"Source DLL: `{dummyDllPath}`");
            report.AppendLine();
            report.AppendLine("```csharp");
            report.AppendLine(TruncateText(typeCode, 8000, "// ... truncated ..."));
            report.AppendLine("```");
        }
        else
        {
            report.AppendLine(typeError ?? "Type structure unavailable.");
        }
        report.AppendLine();

        report.AppendLine("## Native Pseudocode (Ghidra)");
        if (!string.IsNullOrWhiteSpace(nativeSnippet))
        {
            report.AppendLine($"Output file: `{nativeOutFile}`");
            report.AppendLine();
            report.AppendLine("```c");
            report.AppendLine(nativeSnippet);
            report.AppendLine("```");
        }
        else
        {
            report.AppendLine(nativeError ?? "Native pseudocode unavailable.");
        }
        report.AppendLine();

        report.AppendLine("## Notes");
        report.AppendLine("- DummyDll code shows type and signatures, but IL2CPP method bodies are native.");
        report.AppendLine("- Native pseudocode is best-effort and may need manual semantic cleanup.");

        File.WriteAllText(reportPath, report.ToString(), Encoding.UTF8);

        var result = new StringBuilder();
        result.AppendLine("IL2CPP readable reconstruction completed.");
        result.AppendLine();
        result.AppendLine($"Matched: {resolvedName}");
        if (!string.IsNullOrWhiteSpace(signature))
        {
            result.AppendLine($"Signature: {signature}");
        }
        result.AppendLine($"RVA: 0x{rva:X} ({rva})");
        if (!string.IsNullOrWhiteSpace(dummyDllPath))
        {
            result.AppendLine($"DummyDll source: {dummyDllPath}");
        }
        if (!string.IsNullOrWhiteSpace(nativeSnippet))
        {
            result.AppendLine($"Native pseudocode: {nativeOutFile}");
        }
        else
        {
            result.AppendLine($"Native pseudocode: {nativeError}");
        }
        result.AppendLine($"Report: {reportPath}");

        return TextResult(result.ToString());
    }

    private sealed class FieldOffsetSymbol
    {
        public int Offset { get; init; }
        public string FieldName { get; init; } = string.Empty;
        public string FieldType { get; init; } = string.Empty;
    }

    private sealed class LocalRenameInfo
    {
        public string OldName { get; init; } = string.Empty;
        public string NewName { get; init; } = string.Empty;
        public string SourceField { get; init; } = string.Empty;
        public string Confidence { get; init; } = "high";
        public string Rule { get; init; } = string.Empty;
    }

    private sealed class ParameterRenameInfo
    {
        public string OldName { get; init; } = string.Empty;
        public string NewName { get; init; } = string.Empty;
        public string Source { get; init; } = "signature";
    }

    private sealed class FunctionRenameInfo
    {
        public string OldName { get; init; } = string.Empty;
        public string NewName { get; init; } = string.Empty;
        public string Source { get; init; } = "signature";
    }

    private sealed class CalledFunctionRenameInfo
    {
        public string OldName { get; init; } = string.Empty;
        public string NewName { get; init; } = string.Empty;
        public long Rva { get; init; }
        public string Source { get; init; } = "script.json Signature";
    }

    private sealed class SemanticEffectSummary
    {
        public List<string> Reads { get; init; } = new();
        public List<string> Writes { get; init; } = new();
        public List<string> Calls { get; init; } = new();
        public List<string> Guards { get; init; } = new();
    }

    private sealed class SemanticUnresolvedSummary
    {
        public List<string> CallTokens { get; init; } = new();
        public List<string> SelfOffsets { get; init; } = new();
        public List<string> ParamPlaceholders { get; init; } = new();
    }

    private sealed class SemanticBundleCallNode
    {
        public string Name { get; init; } = string.Empty;
        public long? Rva { get; init; }
        public string? Signature { get; init; }
    }

    private ToolCallResult ExecuteIl2CppSemanticLiftMethod(string argsJson)
    {
        var input = JsonSerializer.Deserialize<Il2CppSemanticLiftMethodInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrWhiteSpace(input.OutputDir) || string.IsNullOrWhiteSpace(input.MethodName))
        {
            return ErrorResult("outputDir and methodName are required");
        }

        var outputDir = input.OutputDir;
        if (!Directory.Exists(outputDir))
        {
            return ErrorResult($"outputDir not found: {outputDir}");
        }

        if (!_il2Cpp.TryFindMethodRva(outputDir, input.MethodName, out var rva, out var matchedName, out var signature))
        {
            return ErrorResult($"Method '{input.MethodName}' not found in script.json.");
        }

        var resolvedName = matchedName ?? input.MethodName;
        var inferredTypeName = InferTypeNameFromScriptMethod(resolvedName);
        if (string.IsNullOrWhiteSpace(inferredTypeName))
        {
            return ErrorResult($"Cannot infer owner type from matched method: {resolvedName}");
        }

        var candidates = EnumerateTypeNameCandidates(inferredTypeName);
        if (!TryReadTypeFromDummyDll(outputDir, candidates, out var dummyDllPath, out var typeCode, out var typeError) ||
            string.IsNullOrWhiteSpace(typeCode))
        {
            return ErrorResult(typeError);
        }

        var fieldSymbols = ExtractFieldOffsetSymbols(typeCode);
        var fieldMap = fieldSymbols
            .GroupBy(s => s.Offset)
            .ToDictionary(g => g.Key, g => g.First());

        var nativeOutFile = Path.Combine(outputDir, "native_decompile", SanitizeForFileName(resolvedName) + ".c");
        if (!File.Exists(nativeOutFile))
        {
            var gameAssemblyPath = ResolveGameAssemblyPath(input.GameAssemblyPath, input.GameDir);
            if (string.IsNullOrWhiteSpace(gameAssemblyPath))
            {
                return ErrorResult(
                    $"Native pseudocode file not found: {nativeOutFile}. " +
                    "Provide gameAssemblyPath/gameDir so the tool can decompile it automatically.");
            }

            var timeout = input.TimeoutSeconds ?? 900;
            var decompile = _ghidra.DecompileAtRva(
                gameAssemblyPath,
                rva,
                nativeOutFile,
                displayName: matchedName,
                ghidraRootOverride: input.GhidraRoot,
                javaHomeOverride: input.JavaHome,
                timeoutSeconds: timeout);

            if (!decompile.Success)
            {
                var errSb = new StringBuilder();
                errSb.AppendLine("Native decompile failed while preparing semantic lift.");
                errSb.AppendLine(decompile.ErrorMessage ?? "Unknown error");
                if (!string.IsNullOrWhiteSpace(decompile.AnalyzeHeadlessPath))
                {
                    errSb.AppendLine($"analyzeHeadless: {decompile.AnalyzeHeadlessPath}");
                }
                if (!string.IsNullOrWhiteSpace(decompile.ProjectDir))
                {
                    errSb.AppendLine($"projectDir: {decompile.ProjectDir}");
                }
                return ErrorResult(errSb.ToString());
            }
        }

        if (!File.Exists(nativeOutFile))
        {
            return ErrorResult($"Native pseudocode file not found: {nativeOutFile}");
        }

        var nativeCode = File.ReadAllText(nativeOutFile);
        var signatureRenamedCode = ApplyParameterNamesFromSignature(nativeCode, signature, out var paramRenames);
        var callRenamedCode = ApplyCalledFunctionNamesFromScript(
            signatureRenamedCode,
            outputDir,
            rva,
            out var calledFunctionRenames);
        var functionRenamedCode = ApplyPrimaryFunctionNameFromSignature(
            callRenamedCode,
            signature,
            resolvedName,
            out var functionRename);
        var liftedCode = LiftNativePseudocode(functionRenamedCode, fieldMap, out var usedSymbols);
        var liftedAndRenamedCode = ApplyStrictLocalRenames(liftedCode, out var renameInfos);

        var reportDir = Path.Combine(outputDir, "readable_reports");
        Directory.CreateDirectory(reportDir);
        var reportPath = Path.Combine(reportDir, SanitizeForFileName(resolvedName) + ".lifted.md");

        var report = new StringBuilder();
        report.AppendLine("# IL2CPP Semantic Lift Report");
        report.AppendLine();
        report.AppendLine($"- Method keyword: `{input.MethodName}`");
        report.AppendLine($"- Matched method: `{resolvedName}`");
        if (!string.IsNullOrWhiteSpace(signature))
        {
            report.AppendLine($"- Signature: `{signature}`");
        }
        report.AppendLine($"- RVA: `0x{rva:X}` ({rva})");
        report.AppendLine($"- Inferred type: `{inferredTypeName}`");
        report.AppendLine($"- DummyDll source: `{dummyDllPath}`");
        report.AppendLine($"- Native source: `{nativeOutFile}`");
        report.AppendLine();

        report.AppendLine("## Field Offset Map");
        if (fieldSymbols.Count == 0)
        {
            report.AppendLine("No [FieldOffset] symbols were parsed from the owner type.");
        }
        else
        {
            foreach (var symbol in fieldSymbols.OrderBy(s => s.Offset))
            {
                report.AppendLine($"- `0x{symbol.Offset:X}` -> `{symbol.FieldName}` : `{symbol.FieldType}`");
            }
        }
        report.AppendLine();

        report.AppendLine("## Referenced Symbols In Lifted Code");
        if (usedSymbols.Count == 0)
        {
            report.AppendLine("No self-offset expressions were matched to known fields.");
        }
        else
        {
            foreach (var symbol in usedSymbols.OrderBy(s => s.Offset))
            {
                report.AppendLine($"- `0x{symbol.Offset:X}` -> `self.{symbol.FieldName}`");
            }
        }
        report.AppendLine();

        report.AppendLine("## Parameter Renames (From Signature)");
        if (paramRenames.Count == 0)
        {
            report.AppendLine("No parameter placeholders were renamed.");
        }
        else
        {
            foreach (var rename in paramRenames)
            {
                report.AppendLine($"- `{rename.OldName}` -> `{rename.NewName}` (source: `{rename.Source}`)");
            }
        }
        report.AppendLine();

        report.AppendLine("## Function Name Rename (From Signature)");
        if (functionRename == null)
        {
            report.AppendLine("No function name replacement was applied.");
        }
        else
        {
            report.AppendLine(
                $"- `{functionRename.OldName}` -> `{functionRename.NewName}` (source: `{functionRename.Source}`)");
        }
        report.AppendLine();

        report.AppendLine("## Called Function Renames (From Script Metadata)");
        if (calledFunctionRenames.Count == 0)
        {
            report.AppendLine("No called `FUN_xxx` or `func_0x...` tokens were replaced.");
        }
        else
        {
            foreach (var rename in calledFunctionRenames
                .OrderBy(r => r.Rva)
                .ThenBy(r => r.OldName, StringComparer.Ordinal))
            {
                report.AppendLine(
                    $"- `{rename.OldName}` -> `{rename.NewName}` (RVA: `0x{rename.Rva:X}`, source: `{rename.Source}`)");
            }
        }
        report.AppendLine();

        report.AppendLine("## Local Renames (Strict)");
        report.AppendLine("Only applied when a local variable is a single-assignment direct alias of `self.<Field>`.");
        if (renameInfos.Count == 0)
        {
            report.AppendLine("No strict local aliases were eligible for renaming.");
        }
        else
        {
            foreach (var rename in renameInfos)
            {
                report.AppendLine(
                    $"- `{rename.OldName}` -> `{rename.NewName}` " +
                    $"(source: `self.{rename.SourceField}`, confidence: `{rename.Confidence}`, rule: `{rename.Rule}`)");
            }
        }
        report.AppendLine();

        report.AppendLine("## Lifted Pseudocode");
        report.AppendLine("```c");
        report.AppendLine(TruncateText(liftedAndRenamedCode, 12000, "/* ... truncated ... */"));
        report.AppendLine("```");

        File.WriteAllText(reportPath, report.ToString(), Encoding.UTF8);

        var result = new StringBuilder();
        result.AppendLine("IL2CPP semantic lift completed.");
        result.AppendLine();
        result.AppendLine($"Matched: {resolvedName}");
        result.AppendLine($"RVA: 0x{rva:X} ({rva})");
        result.AppendLine($"Field symbols parsed: {fieldSymbols.Count}");
        result.AppendLine($"Field symbols referenced in code: {usedSymbols.Count}");
        result.AppendLine($"Parameter renames applied: {paramRenames.Count}");
        result.AppendLine($"Function name replaced: {(functionRename != null ? "yes" : "no")}");
        result.AppendLine($"Called function renames applied: {calledFunctionRenames.Count}");
        result.AppendLine($"Strict local renames applied: {renameInfos.Count}");
        result.AppendLine($"Report: {reportPath}");
        result.AppendLine();
        result.AppendLine("Preview:");
        result.AppendLine("```c");
        result.AppendLine(TruncateText(liftedAndRenamedCode, 2500, "/* ... truncated ... */"));
        result.AppendLine("```");

        return TextResult(result.ToString());
    }

    private ToolCallResult ExecuteIl2CppSemanticBundleMethod(string argsJson)
    {
        var input = JsonSerializer.Deserialize<Il2CppSemanticBundleMethodInput>(argsJson, _jsonOptions);
        if (input == null || string.IsNullOrWhiteSpace(input.OutputDir) || string.IsNullOrWhiteSpace(input.MethodName))
        {
            return ErrorResult("outputDir and methodName are required");
        }

        var outputDir = input.OutputDir;
        if (!Directory.Exists(outputDir))
        {
            return ErrorResult($"outputDir not found: {outputDir}");
        }

        if (!_il2Cpp.TryFindMethodRva(outputDir, input.MethodName, out var rva, out var matchedName, out var signature))
        {
            return ErrorResult($"Method '{input.MethodName}' not found in script.json.");
        }

        var resolvedName = matchedName ?? input.MethodName;
        var inferredTypeName = InferTypeNameFromScriptMethod(resolvedName);
        if (string.IsNullOrWhiteSpace(inferredTypeName))
        {
            return ErrorResult($"Cannot infer owner type from matched method: {resolvedName}");
        }

        var candidates = EnumerateTypeNameCandidates(inferredTypeName);
        if (!TryReadTypeFromDummyDll(outputDir, candidates, out var dummyDllPath, out var typeCode, out var typeError) ||
            string.IsNullOrWhiteSpace(typeCode))
        {
            return ErrorResult(typeError);
        }

        var fieldSymbols = ExtractFieldOffsetSymbols(typeCode);
        var fieldMap = fieldSymbols
            .GroupBy(s => s.Offset)
            .ToDictionary(g => g.Key, g => g.First());

        var safeName = SanitizeForFileName(resolvedName);
        var nativeOutFile = Path.Combine(outputDir, "native_decompile", safeName + ".c");
        if (!File.Exists(nativeOutFile))
        {
            var gameAssemblyPath = ResolveGameAssemblyPath(input.GameAssemblyPath, input.GameDir);
            if (string.IsNullOrWhiteSpace(gameAssemblyPath))
            {
                return ErrorResult(
                    $"Native pseudocode file not found: {nativeOutFile}. " +
                    "Provide gameAssemblyPath/gameDir so the tool can decompile it automatically.");
            }

            var timeout = input.TimeoutSeconds ?? 900;
            var decompile = _ghidra.DecompileAtRva(
                gameAssemblyPath,
                rva,
                nativeOutFile,
                displayName: matchedName,
                ghidraRootOverride: input.GhidraRoot,
                javaHomeOverride: input.JavaHome,
                timeoutSeconds: timeout);

            if (!decompile.Success)
            {
                var errSb = new StringBuilder();
                errSb.AppendLine("Native decompile failed while preparing semantic bundle.");
                errSb.AppendLine(decompile.ErrorMessage ?? "Unknown error");
                if (!string.IsNullOrWhiteSpace(decompile.AnalyzeHeadlessPath))
                {
                    errSb.AppendLine($"analyzeHeadless: {decompile.AnalyzeHeadlessPath}");
                }
                if (!string.IsNullOrWhiteSpace(decompile.ProjectDir))
                {
                    errSb.AppendLine($"projectDir: {decompile.ProjectDir}");
                }
                return ErrorResult(errSb.ToString());
            }
        }

        if (!File.Exists(nativeOutFile))
        {
            return ErrorResult($"Native pseudocode file not found: {nativeOutFile}");
        }

        var nativeCode = File.ReadAllText(nativeOutFile);
        var signatureRenamedCode = ApplyParameterNamesFromSignature(nativeCode, signature, out var paramRenames);
        var callRenamedCode = ApplyCalledFunctionNamesFromScript(
            signatureRenamedCode,
            outputDir,
            rva,
            out var calledFunctionRenames);
        var functionRenamedCode = ApplyPrimaryFunctionNameFromSignature(
            callRenamedCode,
            signature,
            resolvedName,
            out var functionRename);
        var liftedCode = LiftNativePseudocode(functionRenamedCode, fieldMap, out var usedSymbols);
        var liftedAndRenamedCode = ApplyStrictLocalRenames(liftedCode, out var localRenames);

        var effects = BuildSemanticEffectsSummary(liftedAndRenamedCode, functionRename?.NewName);
        var unresolved = BuildSemanticUnresolvedSummary(liftedAndRenamedCode);

        var callMetadata = _il2Cpp.GetMethodMetadataByRva(outputDir, calledFunctionRenames.Select(r => r.Rva).Distinct());
        var callNodes = calledFunctionRenames
            .OrderBy(c => c.Rva)
            .Select(c =>
            {
                callMetadata.TryGetValue(c.Rva, out var meta);
                return new SemanticBundleCallNode
                {
                    Name = c.NewName,
                    Rva = c.Rva,
                    Signature = meta?.Signature
                };
            })
            .ToList();

        var reportDir = Path.Combine(outputDir, "readable_reports");
        Directory.CreateDirectory(reportDir);
        var bundlePath = Path.Combine(reportDir, safeName + ".bundle.json");

        var bundle = new
        {
            schemaVersion = "1.0",
            generatedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
            method = new
            {
                keyword = input.MethodName,
                matchedName = resolvedName,
                rva,
                rvaHex = $"0x{rva:X}",
                signature,
                inferredType = inferredTypeName,
                dummyDllPath,
                nativePath = nativeOutFile
            },
            provenance = new
            {
                fieldOffsets = fieldSymbols.Select(f => new
                {
                    offset = f.Offset,
                    offsetHex = $"0x{f.Offset:X}",
                    fieldName = f.FieldName,
                    fieldType = f.FieldType,
                    source = "DummyDll [FieldOffset]"
                }).ToList(),
                parameterRenames = paramRenames.Select(p => new
                {
                    oldName = p.OldName,
                    newName = p.NewName,
                    source = p.Source
                }).ToList(),
                functionRename = functionRename == null ? null : new
                {
                    oldName = functionRename.OldName,
                    newName = functionRename.NewName,
                    source = functionRename.Source
                },
                calledFunctionRenames = calledFunctionRenames.Select(c => new
                {
                    oldName = c.OldName,
                    newName = c.NewName,
                    rva = c.Rva,
                    rvaHex = $"0x{c.Rva:X}",
                    source = c.Source
                }).ToList(),
                localRenames = localRenames.Select(l => new
                {
                    oldName = l.OldName,
                    newName = l.NewName,
                    sourceField = l.SourceField,
                    confidence = l.Confidence,
                    rule = l.Rule
                }).ToList(),
                referencedSelfFields = usedSymbols.Select(s => new
                {
                    offset = s.Offset,
                    offsetHex = $"0x{s.Offset:X}",
                    fieldName = s.FieldName,
                    fieldType = s.FieldType
                }).ToList()
            },
            effects = new
            {
                reads = effects.Reads,
                writes = effects.Writes,
                calls = effects.Calls,
                guards = effects.Guards
            },
            unresolved = new
            {
                callTokens = unresolved.CallTokens,
                selfOffsets = unresolved.SelfOffsets,
                paramPlaceholders = unresolved.ParamPlaceholders
            },
            callGraph = new
            {
                root = new SemanticBundleCallNode
                {
                    Name = functionRename?.NewName ?? resolvedName.Replace("$$", "__", StringComparison.Ordinal),
                    Rva = rva,
                    Signature = signature
                },
                callees = callNodes
            },
            liftedCode = liftedAndRenamedCode
        };

        var bundleJson = JsonSerializer.Serialize(bundle, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        File.WriteAllText(bundlePath, bundleJson, Encoding.UTF8);

        var sb = new StringBuilder();
        sb.AppendLine("IL2CPP semantic bundle generated.");
        sb.AppendLine();
        sb.AppendLine($"Matched: {resolvedName}");
        sb.AppendLine($"RVA: 0x{rva:X} ({rva})");
        sb.AppendLine($"Bundle: {bundlePath}");
        sb.AppendLine($"Field symbols parsed: {fieldSymbols.Count}");
        sb.AppendLine($"Parameter renames: {paramRenames.Count}");
        sb.AppendLine($"Called function renames: {calledFunctionRenames.Count}");
        sb.AppendLine($"Unresolved call tokens: {unresolved.CallTokens.Count}");
        sb.AppendLine();
        sb.AppendLine("JSON Preview:");
        sb.AppendLine("```json");
        sb.AppendLine(TruncateText(bundleJson, 3500, "/* ... truncated ... */"));
        sb.AppendLine("```");

        return TextResult(sb.ToString());
    }

    private static List<FieldOffsetSymbol> ExtractFieldOffsetSymbols(string typeCode)
    {
        var result = new List<FieldOffsetSymbol>();
        if (string.IsNullOrWhiteSpace(typeCode))
        {
            return result;
        }

        var offsetRegex = new Regex(@"\[FieldOffset\(Offset\s*=\s*""0x([0-9A-Fa-f]+)""\)\]", RegexOptions.Compiled);
        var fieldRegex = new Regex(
            @"\b(?:public|private|protected|internal)\s+(.+?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
            RegexOptions.Compiled);

        var lines = typeCode.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
        for (var i = 0; i < lines.Length; i++)
        {
            var offsetMatch = offsetRegex.Match(lines[i]);
            if (!offsetMatch.Success)
            {
                continue;
            }

            if (!int.TryParse(offsetMatch.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var offset))
            {
                continue;
            }

            for (var j = i + 1; j < Math.Min(i + 8, lines.Length); j++)
            {
                var line = lines[j].Trim();
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("[", StringComparison.Ordinal))
                {
                    continue;
                }

                var fieldMatch = fieldRegex.Match(line);
                if (!fieldMatch.Success)
                {
                    continue;
                }

                var fieldType = fieldMatch.Groups[1].Value.Trim();
                var fieldName = fieldMatch.Groups[2].Value.Trim();
                result.Add(new FieldOffsetSymbol
                {
                    Offset = offset,
                    FieldName = fieldName,
                    FieldType = fieldType
                });
                break;
            }
        }

        return result
            .GroupBy(s => new { s.Offset, s.FieldName })
            .Select(g => g.First())
            .OrderBy(s => s.Offset)
            .ToList();
    }

    private sealed class ParsedSignatureParam
    {
        public string Name { get; init; } = string.Empty;
        public bool IsThis { get; init; }
        public bool IsMethodInfo { get; init; }
    }

    private static string ApplyParameterNamesFromSignature(
        string code,
        string? signature,
        out List<ParameterRenameInfo> renames)
    {
        renames = new List<ParameterRenameInfo>();
        if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(signature))
        {
            return code;
        }

        var parsedParams = ParseSignatureParameters(signature);
        if (parsedParams.Count == 0)
        {
            return code;
        }

        var availableParamIndices = Regex.Matches(code, @"\bparam_(\d+)\b", RegexOptions.CultureInvariant)
            .Cast<Match>()
            .Select(m => int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture))
            .Distinct()
            .OrderBy(i => i)
            .ToList();

        if (availableParamIndices.Count == 0)
        {
            return code;
        }

        var namePlan = new Dictionary<int, string>();
        var remainingIndices = new Queue<int>(availableParamIndices);

        if (parsedParams.Count > 0 && parsedParams[0].IsThis && remainingIndices.Count > 0 && remainingIndices.Peek() == 1)
        {
            namePlan[1] = "self";
            remainingIndices.Dequeue();
        }

        var signatureUserNames = parsedParams
            .Where(p => !p.IsThis && !p.IsMethodInfo)
            .Select(p => p.Name)
            .ToList();

        var knownIdentifiers = new HashSet<string>(
            Regex.Matches(code, @"\b[A-Za-z_][A-Za-z0-9_]*\b", RegexOptions.CultureInvariant)
                .Cast<Match>()
                .Select(m => m.Value),
            StringComparer.Ordinal);
        knownIdentifiers.Add("self");

        var userNameIndex = 0;
        while (remainingIndices.Count > 0 && userNameIndex < signatureUserNames.Count)
        {
            var idx = remainingIndices.Dequeue();
            var rawName = signatureUserNames[userNameIndex++];
            var safeName = SanitizeIdentifier(rawName);
            if (string.IsNullOrWhiteSpace(safeName))
            {
                continue;
            }

            var uniqueName = EnsureUniqueIdentifier(safeName, knownIdentifiers);
            knownIdentifiers.Add(uniqueName);
            namePlan[idx] = uniqueName;
        }

        if (namePlan.Count == 0)
        {
            return code;
        }

        var rewritten = code;
        foreach (var pair in namePlan.OrderBy(p => p.Key))
        {
            var oldName = $"param_{pair.Key}";
            var newName = pair.Value;
            if (string.Equals(oldName, newName, StringComparison.Ordinal))
            {
                continue;
            }

            if (!Regex.IsMatch(rewritten, $@"\b{Regex.Escape(oldName)}\b", RegexOptions.CultureInvariant))
            {
                continue;
            }

            rewritten = Regex.Replace(
                rewritten,
                $@"\b{Regex.Escape(oldName)}\b",
                newName,
                RegexOptions.CultureInvariant);

            renames.Add(new ParameterRenameInfo
            {
                OldName = oldName,
                NewName = newName,
                Source = "script.json Signature"
            });
        }

        return rewritten;
    }

    private static List<ParsedSignatureParam> ParseSignatureParameters(string signature)
    {
        var result = new List<ParsedSignatureParam>();
        if (string.IsNullOrWhiteSpace(signature))
        {
            return result;
        }

        var openParen = signature.IndexOf('(');
        var closeParen = signature.LastIndexOf(')');
        if (openParen < 0 || closeParen <= openParen)
        {
            return result;
        }

        var rawParams = signature.Substring(openParen + 1, closeParen - openParen - 1);
        if (string.IsNullOrWhiteSpace(rawParams))
        {
            return result;
        }

        var split = SplitTopLevelCsv(rawParams);
        foreach (var part in split)
        {
            var p = part.Trim();
            if (string.IsNullOrWhiteSpace(p) || p == "void")
            {
                continue;
            }

            var nameMatch = Regex.Match(p, @"([A-Za-z_][A-Za-z0-9_]*)\s*$", RegexOptions.CultureInvariant);
            if (!nameMatch.Success)
            {
                continue;
            }

            var name = nameMatch.Groups[1].Value;
            var isThis = string.Equals(name, "__this", StringComparison.Ordinal);
            var isMethodInfo = string.Equals(name, "method", StringComparison.Ordinal) &&
                p.Contains("MethodInfo", StringComparison.Ordinal);

            result.Add(new ParsedSignatureParam
            {
                Name = name,
                IsThis = isThis,
                IsMethodInfo = isMethodInfo
            });
        }

        return result;
    }

    private static string ApplyPrimaryFunctionNameFromSignature(
        string code,
        string? signature,
        string matchedMethodName,
        out FunctionRenameInfo? rename)
    {
        rename = null;
        if (string.IsNullOrWhiteSpace(code))
        {
            return code;
        }

        var targetName = ExtractFunctionNameFromSignature(signature);
        if (string.IsNullOrWhiteSpace(targetName))
        {
            targetName = BuildFallbackFunctionName(matchedMethodName);
        }

        targetName = SanitizeIdentifier(targetName);
        if (string.IsNullOrWhiteSpace(targetName))
        {
            return code;
        }

        var definitionRegex = new Regex(
            @"(?m)^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+(?<name>FUN_[0-9A-Fa-f]+)\s*\(",
            RegexOptions.CultureInvariant);

        var defMatch = definitionRegex.Match(code);
        if (!defMatch.Success)
        {
            return code;
        }

        var oldName = defMatch.Groups["name"].Value;
        if (string.IsNullOrWhiteSpace(oldName))
        {
            return code;
        }

        var knownIdentifiers = new HashSet<string>(
            Regex.Matches(code, @"\b[A-Za-z_][A-Za-z0-9_]*\b", RegexOptions.CultureInvariant)
                .Cast<Match>()
                .Select(m => m.Value),
            StringComparer.Ordinal);
        knownIdentifiers.Remove(oldName);

        var uniqueTargetName = EnsureUniqueIdentifier(targetName, knownIdentifiers);
        if (string.Equals(oldName, uniqueTargetName, StringComparison.Ordinal))
        {
            return code;
        }

        var rewritten = Regex.Replace(
            code,
            $@"\b{Regex.Escape(oldName)}\b",
            uniqueTargetName,
            RegexOptions.CultureInvariant);

        rename = new FunctionRenameInfo
        {
            OldName = oldName,
            NewName = uniqueTargetName,
            Source = "script.json Signature"
        };

        return rewritten;
    }

    private string ApplyCalledFunctionNamesFromScript(
        string code,
        string outputDir,
        long currentRva,
        out List<CalledFunctionRenameInfo> renames)
    {
        renames = new List<CalledFunctionRenameInfo>();
        if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(outputDir) || currentRva < 0)
        {
            return code;
        }

        var primaryMatch = Regex.Match(
            code,
            @"(?m)^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+(?<name>FUN_(?<hex>[0-9A-Fa-f]+))\s*\(",
            RegexOptions.CultureInvariant);
        if (!primaryMatch.Success)
        {
            return code;
        }

        var primaryOldName = primaryMatch.Groups["name"].Value;
        var primaryHex = primaryMatch.Groups["hex"].Value;
        if (!long.TryParse(primaryHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var primaryAbsAddress))
        {
            return code;
        }

        var imageBase = primaryAbsAddress - currentRva;
        if (imageBase < 0)
        {
            return code;
        }

        var callTokenMatches = Regex.Matches(
            code,
            @"\b(?<token>FUN_(?<funhex>[0-9A-Fa-f]+)|func_0x(?<funchex>[0-9A-Fa-f]+))\b",
            RegexOptions.CultureInvariant);
        if (callTokenMatches.Count == 0)
        {
            return code;
        }

        var tokenToRva = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (Match tokenMatch in callTokenMatches)
        {
            var token = tokenMatch.Groups["token"].Value;
            if (string.Equals(token, primaryOldName, StringComparison.Ordinal))
            {
                continue;
            }

            var hex = tokenMatch.Groups["funhex"].Success
                ? tokenMatch.Groups["funhex"].Value
                : tokenMatch.Groups["funchex"].Value;
            if (!long.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var absAddress))
            {
                continue;
            }

            var candidateRva = absAddress - imageBase;
            if (candidateRva < 0)
            {
                continue;
            }

            tokenToRva[token] = candidateRva;
        }

        if (tokenToRva.Count == 0)
        {
            return code;
        }

        var rvaToDisplay = _il2Cpp.GetMethodDisplayNamesByRva(outputDir, tokenToRva.Values.Distinct());
        if (rvaToDisplay.Count == 0)
        {
            return code;
        }

        var knownIdentifiers = new HashSet<string>(
            Regex.Matches(code, @"\b[A-Za-z_][A-Za-z0-9_]*\b", RegexOptions.CultureInvariant)
                .Cast<Match>()
                .Select(m => m.Value),
            StringComparer.Ordinal);

        var rewritePlan = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (oldToken, candidateRva) in tokenToRva.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            if (!rvaToDisplay.TryGetValue(candidateRva, out var displayName))
            {
                continue;
            }

            var safeName = SanitizeIdentifier(displayName);
            if (string.IsNullOrWhiteSpace(safeName))
            {
                continue;
            }

            var uniqueName = EnsureUniqueIdentifier(safeName, knownIdentifiers);
            knownIdentifiers.Add(uniqueName);
            rewritePlan[oldToken] = uniqueName;

            renames.Add(new CalledFunctionRenameInfo
            {
                OldName = oldToken,
                NewName = uniqueName,
                Rva = candidateRva,
                Source = "script.json Signature"
            });
        }

        if (rewritePlan.Count == 0)
        {
            return code;
        }

        var rewritten = code;
        foreach (var (oldToken, newName) in rewritePlan)
        {
            rewritten = Regex.Replace(
                rewritten,
                $@"\b{Regex.Escape(oldToken)}\b",
                newName,
                RegexOptions.CultureInvariant);
        }

        return rewritten;
    }

    private static SemanticEffectSummary BuildSemanticEffectsSummary(string code, string? primaryFunctionName)
    {
        var summary = new SemanticEffectSummary();
        if (string.IsNullOrWhiteSpace(code))
        {
            return summary;
        }

        var writeMatches = Regex.Matches(code, @"\bself\.(?<field>[A-Za-z_][A-Za-z0-9_]*)\s*=", RegexOptions.CultureInvariant);
        var writes = new HashSet<string>(writeMatches.Cast<Match>().Select(m => m.Groups["field"].Value), StringComparer.Ordinal);

        var readMatches = Regex.Matches(code, @"\bself\.(?<field>[A-Za-z_][A-Za-z0-9_]*)\b", RegexOptions.CultureInvariant);
        var reads = new HashSet<string>(readMatches.Cast<Match>().Select(m => m.Groups["field"].Value), StringComparer.Ordinal);

        foreach (var field in reads.OrderBy(s => s, StringComparer.Ordinal))
        {
            summary.Reads.Add($"self.{field}");
        }

        foreach (var field in writes.OrderBy(s => s, StringComparer.Ordinal))
        {
            summary.Writes.Add($"self.{field}");
        }

        var callMatches = Regex.Matches(code, @"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", RegexOptions.CultureInvariant);
        var calls = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match match in callMatches)
        {
            var name = match.Groups[1].Value;
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            if (string.Equals(name, primaryFunctionName, StringComparison.Ordinal))
            {
                continue;
            }

            if (IsControlKeyword(name))
            {
                continue;
            }

            calls.Add(name);
        }

        foreach (var call in calls.OrderBy(s => s, StringComparer.Ordinal))
        {
            summary.Calls.Add(call);
        }

        var guardMatches = Regex.Matches(code, @"\bif\s*\((?<cond>[^)]{1,140})\)", RegexOptions.CultureInvariant);
        foreach (Match match in guardMatches.Cast<Match>().Take(40))
        {
            var cond = match.Groups["cond"].Value.Trim();
            if (!string.IsNullOrWhiteSpace(cond))
            {
                summary.Guards.Add(cond);
            }
        }

        return summary;
    }

    private static SemanticUnresolvedSummary BuildSemanticUnresolvedSummary(string code)
    {
        var summary = new SemanticUnresolvedSummary();
        if (string.IsNullOrWhiteSpace(code))
        {
            return summary;
        }

        var callTokens = Regex.Matches(
            code,
            @"\b(FUN_[0-9A-Fa-f]+|func_0x[0-9A-Fa-f]+)\b",
            RegexOptions.CultureInvariant)
            .Cast<Match>()
            .Select(m => m.Value)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(s => s, StringComparer.Ordinal);
        summary.CallTokens.AddRange(callTokens);

        var offsets = Regex.Matches(code, @"self\s*\+\s*0x[0-9A-Fa-f]+", RegexOptions.CultureInvariant)
            .Cast<Match>()
            .Select(m => Regex.Replace(m.Value, @"\s+", string.Empty, RegexOptions.CultureInvariant))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(s => s, StringComparer.Ordinal);
        summary.SelfOffsets.AddRange(offsets);

        var placeholders = Regex.Matches(code, @"\bparam_\d+\b", RegexOptions.CultureInvariant)
            .Cast<Match>()
            .Select(m => m.Value)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(s => s, StringComparer.Ordinal);
        summary.ParamPlaceholders.AddRange(placeholders);

        return summary;
    }

    private static bool IsControlKeyword(string identifier)
    {
        return identifier switch
        {
            "if" or "for" or "while" or "switch" or "return" or "sizeof" => true,
            _ => false
        };
    }

    private static string ExtractFunctionNameFromSignature(string? signature)
    {
        if (string.IsNullOrWhiteSpace(signature))
        {
            return string.Empty;
        }

        var match = Regex.Match(
            signature,
            @"^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
            RegexOptions.CultureInvariant);
        if (!match.Success)
        {
            return string.Empty;
        }

        return match.Groups["name"].Value;
    }

    private static string BuildFallbackFunctionName(string matchedMethodName)
    {
        if (string.IsNullOrWhiteSpace(matchedMethodName))
        {
            return string.Empty;
        }

        var fallback = matchedMethodName.Replace("$$", "__", StringComparison.Ordinal);
        fallback = Regex.Replace(fallback, @"[^A-Za-z0-9_]", "_", RegexOptions.CultureInvariant);
        return fallback;
    }

    private static List<string> SplitTopLevelCsv(string input)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return result;
        }

        var sb = new StringBuilder();
        var angleDepth = 0;
        var parenDepth = 0;
        foreach (var ch in input)
        {
            switch (ch)
            {
                case '<':
                    angleDepth++;
                    sb.Append(ch);
                    break;
                case '>':
                    angleDepth = Math.Max(0, angleDepth - 1);
                    sb.Append(ch);
                    break;
                case '(':
                    parenDepth++;
                    sb.Append(ch);
                    break;
                case ')':
                    parenDepth = Math.Max(0, parenDepth - 1);
                    sb.Append(ch);
                    break;
                case ',' when angleDepth == 0 && parenDepth == 0:
                    result.Add(sb.ToString());
                    sb.Clear();
                    break;
                default:
                    sb.Append(ch);
                    break;
            }
        }

        if (sb.Length > 0)
        {
            result.Add(sb.ToString());
        }

        return result;
    }

    private static string SanitizeIdentifier(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        var cleaned = Regex.Replace(raw, @"[^A-Za-z0-9_]", string.Empty, RegexOptions.CultureInvariant);
        if (string.IsNullOrWhiteSpace(cleaned))
        {
            return string.Empty;
        }

        if (!Regex.IsMatch(cleaned, @"^[A-Za-z_]", RegexOptions.CultureInvariant))
        {
            cleaned = "_" + cleaned;
        }

        if (IsCStyleKeyword(cleaned))
        {
            cleaned += "_1";
        }

        return cleaned;
    }

    private static string LiftNativePseudocode(
        string nativeCode,
        IReadOnlyDictionary<int, FieldOffsetSymbol> fieldMap,
        out List<FieldOffsetSymbol> usedSymbols)
    {
        var usedOffsets = new HashSet<int>();
        if (string.IsNullOrWhiteSpace(nativeCode))
        {
            usedSymbols = new List<FieldOffsetSymbol>();
            return string.Empty;
        }

        var lifted = nativeCode;
        lifted = Regex.Replace(
            lifted,
            @"\*\([^)]*\)\(self\s*\+\s*0x([0-9A-Fa-f]+)\)",
            match =>
            {
                if (!int.TryParse(match.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var offset))
                {
                    return match.Value;
                }

                if (!fieldMap.TryGetValue(offset, out var symbol))
                {
                    return match.Value;
                }

                usedOffsets.Add(offset);
                return $"self.{symbol.FieldName}";
            },
            RegexOptions.CultureInvariant);

        usedSymbols = usedOffsets
            .OrderBy(o => o)
            .Where(fieldMap.ContainsKey)
            .Select(o => fieldMap[o])
            .ToList();

        return lifted;
    }

    private static string ApplyStrictLocalRenames(string liftedCode, out List<LocalRenameInfo> renameInfos)
    {
        renameInfos = new List<LocalRenameInfo>();
        if (string.IsNullOrWhiteSpace(liftedCode))
        {
            return string.Empty;
        }

        var aliasCandidates = new Dictionary<string, string>(StringComparer.Ordinal);
        var ambiguousVars = new HashSet<string>(StringComparer.Ordinal);

        var assignmentRegex = new Regex(
            @"^\s*(?<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<expr>.+?)\s*;\s*$",
            RegexOptions.Compiled | RegexOptions.Multiline);

        foreach (Match match in assignmentRegex.Matches(liftedCode))
        {
            var varName = match.Groups["var"].Value;
            var expr = match.Groups["expr"].Value;
            if (!TryExtractSingleSelfFieldAlias(expr, out var fieldName))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(varName) || string.IsNullOrWhiteSpace(fieldName))
            {
                continue;
            }

            if (aliasCandidates.TryGetValue(varName, out var existingField))
            {
                if (!string.Equals(existingField, fieldName, StringComparison.Ordinal))
                {
                    ambiguousVars.Add(varName);
                }
            }
            else
            {
                aliasCandidates[varName] = fieldName;
            }
        }

        if (aliasCandidates.Count == 0)
        {
            return liftedCode;
        }

        foreach (var ambiguous in ambiguousVars)
        {
            aliasCandidates.Remove(ambiguous);
        }

        if (aliasCandidates.Count == 0)
        {
            return liftedCode;
        }

        var knownIdentifiers = new HashSet<string>(
            Regex.Matches(liftedCode, @"\b[A-Za-z_][A-Za-z0-9_]*\b")
                .Cast<Match>()
                .Select(m => m.Value),
            StringComparer.Ordinal);

        var transformed = liftedCode;
        foreach (var (oldName, sourceField) in aliasCandidates.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            var assignmentCount = Regex.Matches(
                transformed,
                $@"\b{Regex.Escape(oldName)}\s*=(?!=)",
                RegexOptions.CultureInvariant).Count;

            // Strict requirement: only single-assignment aliases are renamed.
            if (assignmentCount != 1)
            {
                continue;
            }

            var newNameBase = BuildStrictAliasName(sourceField);
            var newName = EnsureUniqueIdentifier(newNameBase, knownIdentifiers);
            if (string.Equals(oldName, newName, StringComparison.Ordinal))
            {
                continue;
            }

            transformed = Regex.Replace(
                transformed,
                $@"\b{Regex.Escape(oldName)}\b",
                newName,
                RegexOptions.CultureInvariant);

            knownIdentifiers.Add(newName);
            renameInfos.Add(new LocalRenameInfo
            {
                OldName = oldName,
                NewName = newName,
                SourceField = sourceField,
                Confidence = "high",
                Rule = "single-assignment direct self.field alias"
            });
        }

        return transformed;
    }

    private static bool TryExtractSingleSelfFieldAlias(string expression, out string fieldName)
    {
        fieldName = string.Empty;
        if (string.IsNullOrWhiteSpace(expression))
        {
            return false;
        }

        var fieldMatches = Regex.Matches(
            expression,
            @"\bself\.(?<field>[A-Za-z_][A-Za-z0-9_]*)\b",
            RegexOptions.CultureInvariant);

        if (fieldMatches.Count != 1)
        {
            return false;
        }

        fieldName = fieldMatches[0].Groups["field"].Value;
        if (string.IsNullOrWhiteSpace(fieldName))
        {
            return false;
        }

        var normalized = expression.Trim();
        normalized = Regex.Replace(
            normalized,
            $@"\bself\.{Regex.Escape(fieldName)}\b",
            "__FIELD__",
            RegexOptions.CultureInvariant);

        // Remove one or more leading C-style casts.
        while (true)
        {
            var castMatch = Regex.Match(
                normalized,
                @"^\(\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s*\)\s*",
                RegexOptions.CultureInvariant);

            if (!castMatch.Success)
            {
                break;
            }

            normalized = normalized.Substring(castMatch.Length).Trim();
        }

        // Strip balanced outer parentheses.
        while (normalized.StartsWith('(') && normalized.EndsWith(')'))
        {
            var inner = normalized.Substring(1, normalized.Length - 2).Trim();
            if (!IsBalancedParentheses(inner))
            {
                break;
            }
            normalized = inner;
        }

        return string.Equals(normalized, "__FIELD__", StringComparison.Ordinal);
    }

    private static bool IsBalancedParentheses(string value)
    {
        var depth = 0;
        foreach (var ch in value)
        {
            if (ch == '(') depth++;
            if (ch == ')')
            {
                depth--;
                if (depth < 0)
                {
                    return false;
                }
            }
        }
        return depth == 0;
    }

    private static string BuildStrictAliasName(string sourceField)
    {
        if (string.IsNullOrWhiteSpace(sourceField))
        {
            return "fieldAliasLocal";
        }

        var cleaned = sourceField
            .Replace("<", string.Empty, StringComparison.Ordinal)
            .Replace(">", string.Empty, StringComparison.Ordinal)
            .Replace("k__BackingField", string.Empty, StringComparison.Ordinal);

        var parts = Regex.Split(cleaned, @"[^A-Za-z0-9]+")
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .ToList();

        if (parts.Count == 0)
        {
            return "fieldAliasLocal";
        }

        var first = parts[0];
        first = char.ToLowerInvariant(first[0]) + first.Substring(1);
        var sb = new StringBuilder(first);
        for (var i = 1; i < parts.Count; i++)
        {
            var p = parts[i];
            sb.Append(char.ToUpperInvariant(p[0]));
            if (p.Length > 1)
            {
                sb.Append(p.Substring(1));
            }
        }

        sb.Append("Local");
        var candidate = sb.ToString();

        if (!Regex.IsMatch(candidate, @"^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.CultureInvariant))
        {
            candidate = "fieldAliasLocal";
        }

        if (IsCStyleKeyword(candidate))
        {
            candidate += "_1";
        }

        return candidate;
    }

    private static string EnsureUniqueIdentifier(string preferredName, ISet<string> knownIdentifiers)
    {
        if (!knownIdentifiers.Contains(preferredName))
        {
            return preferredName;
        }

        var i = 2;
        while (true)
        {
            var candidate = preferredName + i.ToString(CultureInfo.InvariantCulture);
            if (!knownIdentifiers.Contains(candidate))
            {
                return candidate;
            }
            i++;
        }
    }

    private static bool IsCStyleKeyword(string identifier)
    {
        return identifier switch
        {
            "auto" or "break" or "case" or "char" or "const" or "continue" or "default" or
            "do" or "double" or "else" or "enum" or "extern" or "float" or "for" or "goto" or
            "if" or "inline" or "int" or "long" or "register" or "restrict" or "return" or
            "short" or "signed" or "sizeof" or "static" or "struct" or "switch" or "typedef" or
            "union" or "unsigned" or "void" or "volatile" or "while" or "_Bool" or "_Complex" or
            "_Imaginary" => true,
            _ => false
        };
    }

    private string ResolveGameAssemblyPath(string? gameAssemblyPath, string? gameDir)
    {
        if (!string.IsNullOrWhiteSpace(gameAssemblyPath))
        {
            return gameAssemblyPath;
        }

        if (!string.IsNullOrWhiteSpace(gameDir))
        {
            var detected = _il2Cpp.DetectIl2CppFiles(gameDir);
            return detected.gameAssembly ?? string.Empty;
        }

        return string.Empty;
    }

    private bool TryReadTypeFromDummyDll(
        string outputDir,
        IEnumerable<string> typeNameCandidates,
        out string? dllPath,
        out string? typeCode,
        out string error)
    {
        dllPath = null;
        typeCode = null;
        error = string.Empty;

        var dummyDir = Path.Combine(outputDir, "DummyDll");
        if (!Directory.Exists(dummyDir))
        {
            error = $"DummyDll directory not found: {dummyDir}";
            return false;
        }

        var dllFiles = Directory.GetFiles(dummyDir, "*.dll", SearchOption.TopDirectoryOnly)
            .OrderBy(path => path.EndsWith("Assembly-CSharp.dll", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(path => Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (dllFiles.Count == 0)
        {
            error = $"No DLL files found under DummyDll: {dummyDir}";
            return false;
        }

        var candidates = typeNameCandidates
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (candidates.Count == 0)
        {
            error = "No valid type candidates inferred from method name.";
            return false;
        }

        string? lastError = null;
        foreach (var candidate in candidates)
        {
            foreach (var dll in dllFiles)
            {
                var decompile = _decompiler.DecompileType(dll, candidate);
                if (decompile.Success)
                {
                    dllPath = dll;
                    typeCode = decompile.SourceCode;
                    return true;
                }

                lastError = decompile.ErrorMessage;
            }
        }

        error = lastError ?? $"Type not found in DummyDll for candidates: {string.Join(", ", candidates)}";
        return false;
    }

    private static IEnumerable<string> EnumerateTypeNameCandidates(string inferredTypeName)
    {
        var candidates = new List<string>();
        if (string.IsNullOrWhiteSpace(inferredTypeName))
        {
            return candidates;
        }

        candidates.Add(inferredTypeName);
        candidates.Add(inferredTypeName.Replace("/", "+"));
        candidates.Add(inferredTypeName.Replace("/", "."));
        candidates.Add(inferredTypeName.Replace("+", "."));

        var plusIndex = inferredTypeName.LastIndexOf('+');
        if (plusIndex >= 0 && plusIndex < inferredTypeName.Length - 1)
        {
            candidates.Add(inferredTypeName.Substring(plusIndex + 1));
        }

        var dotIndex = inferredTypeName.LastIndexOf('.');
        if (dotIndex >= 0 && dotIndex < inferredTypeName.Length - 1)
        {
            candidates.Add(inferredTypeName.Substring(dotIndex + 1));
        }

        return candidates;
    }

    private static string? InferTypeNameFromScriptMethod(string? scriptMethodName)
    {
        if (string.IsNullOrWhiteSpace(scriptMethodName))
        {
            return null;
        }

        var idx = scriptMethodName.IndexOf("$$", StringComparison.Ordinal);
        if (idx <= 0)
        {
            return null;
        }

        return scriptMethodName.Substring(0, idx).Replace("/", "+");
    }

    private static string ReadFileSnippet(string path, int maxChars, string truncationMarker)
    {
        if (!File.Exists(path))
        {
            return string.Empty;
        }

        var text = File.ReadAllText(path);
        return TruncateText(text, maxChars, truncationMarker);
    }

    private static string TruncateText(string text, int maxChars, string truncationMarker)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= maxChars)
        {
            return text;
        }

        return text.Substring(0, maxChars) + Environment.NewLine + truncationMarker + Environment.NewLine;
    }

    private static string SanitizeForFileName(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return "unknown_method";
        }

        var sb = new StringBuilder(raw.Length);
        foreach (var ch in raw)
        {
            sb.Append(ch switch
            {
                '/' or '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|' => '_',
                _ => ch
            });
        }
        return sb.ToString();
    }

    #endregion

    private static ToolCallResult TextResult(string text)
    {
        return new ToolCallResult
        {
            Content = new List<ContentBlock>
            {
                new() { Type = "text", Text = text }
            }
        };
    }

    private static ToolCallResult ErrorResult(string message)
    {
        return new ToolCallResult
        {
            IsError = true,
            Content = new List<ContentBlock>
            {
                new() { Type = "text", Text = message }
            }
        };
    }
}
