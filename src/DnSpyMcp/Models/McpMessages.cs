using System.Text.Json;
using System.Text.Json.Serialization;

namespace DnSpyMcp.Models;

#region JSON-RPC Base Messages

public class JsonRpcRequest
{
    [JsonPropertyName("jsonrpc")]
    public string JsonRpc { get; set; } = "2.0";

    [JsonPropertyName("id")]
    public JsonElement? Id { get; set; }

    [JsonPropertyName("method")]
    public string Method { get; set; } = "";

    [JsonPropertyName("params")]
    public JsonElement? Params { get; set; }
}

public class JsonRpcResponse
{
    [JsonPropertyName("jsonrpc")]
    public string JsonRpc { get; set; } = "2.0";

    [JsonPropertyName("id")]
    public JsonElement? Id { get; set; }

    [JsonPropertyName("result")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Result { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonRpcError? Error { get; set; }
}

public class JsonRpcError
{
    [JsonPropertyName("code")]
    public int Code { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("data")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Data { get; set; }
}

public class JsonRpcNotification
{
    [JsonPropertyName("jsonrpc")]
    public string JsonRpc { get; set; } = "2.0";

    [JsonPropertyName("method")]
    public string Method { get; set; } = "";

    [JsonPropertyName("params")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Params { get; set; }
}

#endregion

#region MCP Protocol Messages

public class InitializeParams
{
    [JsonPropertyName("protocolVersion")]
    public string ProtocolVersion { get; set; } = "";

    [JsonPropertyName("capabilities")]
    public ClientCapabilities Capabilities { get; set; } = new();

    [JsonPropertyName("clientInfo")]
    public ClientInfo ClientInfo { get; set; } = new();
}

public class ClientCapabilities
{
    [JsonPropertyName("roots")]
    public RootsCapability? Roots { get; set; }

    [JsonPropertyName("sampling")]
    public object? Sampling { get; set; }
}

public class RootsCapability
{
    [JsonPropertyName("listChanged")]
    public bool ListChanged { get; set; }
}

public class ClientInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "";
}

public class InitializeResult
{
    [JsonPropertyName("protocolVersion")]
    public string ProtocolVersion { get; set; } = "2024-11-05";

    [JsonPropertyName("capabilities")]
    public ServerCapabilities Capabilities { get; set; } = new();

    [JsonPropertyName("serverInfo")]
    public ServerInfo ServerInfo { get; set; } = new();
}

public class ServerCapabilities
{
    [JsonPropertyName("tools")]
    public ToolsCapability? Tools { get; set; }
}

public class ToolsCapability
{
    [JsonPropertyName("listChanged")]
    public bool ListChanged { get; set; }
}

public class ServerInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "";
}

public class ToolsListResult
{
    [JsonPropertyName("tools")]
    public List<ToolDefinition> Tools { get; set; } = new();
}

public class ToolDefinition
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    [JsonPropertyName("inputSchema")]
    public JsonElement InputSchema { get; set; }
}

public class ToolCallParams
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("arguments")]
    public JsonElement? Arguments { get; set; }
}

public class ToolCallResult
{
    [JsonPropertyName("content")]
    public List<ContentBlock> Content { get; set; } = new();

    [JsonPropertyName("isError")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool IsError { get; set; }
}

public class ContentBlock
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "text";

    [JsonPropertyName("text")]
    public string Text { get; set; } = "";
}

#endregion

#region Tool Input Models

public class ListTypesInput
{
    [JsonPropertyName("dllPath")]
    public string DllPath { get; set; } = "";

    [JsonPropertyName("namespace")]
    public string? Namespace { get; set; }

    [JsonPropertyName("pattern")]
    public string? Pattern { get; set; }
}

public class DecompileTypeInput
{
    [JsonPropertyName("dllPath")]
    public string DllPath { get; set; } = "";

    [JsonPropertyName("typeName")]
    public string TypeName { get; set; } = "";
}

public class DecompileMethodInput
{
    [JsonPropertyName("dllPath")]
    public string DllPath { get; set; } = "";

    [JsonPropertyName("typeName")]
    public string TypeName { get; set; } = "";

    [JsonPropertyName("methodName")]
    public string MethodName { get; set; } = "";
}

public class SearchCodeInput
{
    [JsonPropertyName("dllPath")]
    public string DllPath { get; set; } = "";

    [JsonPropertyName("keyword")]
    public string Keyword { get; set; } = "";

    [JsonPropertyName("maxResults")]
    public int MaxResults { get; set; } = 20;
}

public class ExportAssemblyInput
{
    [JsonPropertyName("dllPath")]
    public string DllPath { get; set; } = "";

    [JsonPropertyName("outputDir")]
    public string OutputDir { get; set; } = "";
}

#endregion

#region IL2CPP Tool Input Models

public class Il2CppDumpInput
{
    [JsonPropertyName("gameDir")]
    public string GameDir { get; set; } = "";

    [JsonPropertyName("metadataPath")]
    public string? MetadataPath { get; set; }
}

public class Il2CppSearchInput
{
    [JsonPropertyName("outputDir")]
    public string OutputDir { get; set; } = "";

    [JsonPropertyName("keyword")]
    public string Keyword { get; set; } = "";
}

public class Il2CppReadTypeInput
{
    [JsonPropertyName("dummyDllPath")]
    public string DummyDllPath { get; set; } = "";

    [JsonPropertyName("typeName")]
    public string TypeName { get; set; } = "";
}

public class Il2CppMethodAddressInput
{
    [JsonPropertyName("outputDir")]
    public string OutputDir { get; set; } = "";

    [JsonPropertyName("methodName")]
    public string MethodName { get; set; } = "";
}

public class Il2CppReconstructMethodInput
{
    [JsonPropertyName("outputDir")]
    public string OutputDir { get; set; } = "";

    [JsonPropertyName("methodName")]
    public string MethodName { get; set; } = "";

    [JsonPropertyName("gameAssemblyPath")]
    public string? GameAssemblyPath { get; set; }

    [JsonPropertyName("gameDir")]
    public string? GameDir { get; set; }

    [JsonPropertyName("ghidraRoot")]
    public string? GhidraRoot { get; set; }

    [JsonPropertyName("javaHome")]
    public string? JavaHome { get; set; }

    [JsonPropertyName("timeoutSeconds")]
    public int? TimeoutSeconds { get; set; }
}

public class Il2CppSemanticLiftMethodInput
{
    [JsonPropertyName("outputDir")]
    public string OutputDir { get; set; } = "";

    [JsonPropertyName("methodName")]
    public string MethodName { get; set; } = "";

    [JsonPropertyName("gameAssemblyPath")]
    public string? GameAssemblyPath { get; set; }

    [JsonPropertyName("gameDir")]
    public string? GameDir { get; set; }

    [JsonPropertyName("ghidraRoot")]
    public string? GhidraRoot { get; set; }

    [JsonPropertyName("javaHome")]
    public string? JavaHome { get; set; }

    [JsonPropertyName("timeoutSeconds")]
    public int? TimeoutSeconds { get; set; }
}

public class Il2CppSemanticBundleMethodInput
{
    [JsonPropertyName("outputDir")]
    public string OutputDir { get; set; } = "";

    [JsonPropertyName("methodName")]
    public string MethodName { get; set; } = "";

    [JsonPropertyName("gameAssemblyPath")]
    public string? GameAssemblyPath { get; set; }

    [JsonPropertyName("gameDir")]
    public string? GameDir { get; set; }

    [JsonPropertyName("ghidraRoot")]
    public string? GhidraRoot { get; set; }

    [JsonPropertyName("javaHome")]
    public string? JavaHome { get; set; }

    [JsonPropertyName("timeoutSeconds")]
    public int? TimeoutSeconds { get; set; }
}

#endregion
