namespace DnSpyMcp.Models;

public class TypeInfo
{
    public string FullName { get; set; } = "";
    public string Name { get; set; } = "";
    public string Namespace { get; set; } = "";
    public string Kind { get; set; } = ""; // Class, Struct, Interface, Enum, Delegate
    public bool IsPublic { get; set; }
    public int MethodCount { get; set; }
    public int PropertyCount { get; set; }
    public int FieldCount { get; set; }
}

public class MethodInfo
{
    public string Name { get; set; } = "";
    public string ReturnType { get; set; } = "";
    public List<string> Parameters { get; set; } = new();
    public bool IsPublic { get; set; }
    public bool IsStatic { get; set; }
}

public class SearchResult
{
    public string TypeName { get; set; } = "";
    public string? MemberName { get; set; }
    public string MemberKind { get; set; } = ""; // Type, Method, Property, Field
    public string MatchContext { get; set; } = "";
}

public class DecompileResult
{
    public bool Success { get; set; }
    public string? SourceCode { get; set; }
    public string? ErrorMessage { get; set; }
}

public class ExportResult
{
    public bool Success { get; set; }
    public string OutputPath { get; set; } = "";
    public int FileCount { get; set; }
    public string? ErrorMessage { get; set; }
}
