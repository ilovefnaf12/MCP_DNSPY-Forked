using System.Text;
using System.Text.RegularExpressions;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.ProjectDecompiler;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;
using DnSpyMcp.Models;

namespace DnSpyMcp;

public class DecompilerService : IDisposable
{
    private readonly Dictionary<string, CSharpDecompiler> _decompilerCache = new();
    private readonly object _lock = new();

    private CSharpDecompiler GetDecompiler(string dllPath)
    {
        var fullPath = Path.GetFullPath(dllPath);

        lock (_lock)
        {
            if (_decompilerCache.TryGetValue(fullPath, out var cached))
            {
                return cached;
            }

            if (!File.Exists(fullPath))
            {
                throw new FileNotFoundException($"DLL not found: {fullPath}");
            }

            var settings = new DecompilerSettings(LanguageVersion.Latest)
            {
                ThrowOnAssemblyResolveErrors = false,
                ShowXmlDocumentation = true,
            };

            var decompiler = new CSharpDecompiler(fullPath, settings);
            _decompilerCache[fullPath] = decompiler;
            return decompiler;
        }
    }

    public List<TypeInfo> ListTypes(string dllPath, string? namespaceFilter = null, string? pattern = null)
    {
        var decompiler = GetDecompiler(dllPath);
        var types = new List<TypeInfo>();

        Regex? regex = null;
        if (!string.IsNullOrEmpty(pattern))
        {
            regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
        }

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            // Skip compiler-generated types
            if (type.Name.StartsWith("<") || type.Name.Contains("__"))
                continue;

            // Filter by namespace
            if (!string.IsNullOrEmpty(namespaceFilter))
            {
                if (!type.Namespace.StartsWith(namespaceFilter, StringComparison.OrdinalIgnoreCase))
                    continue;
            }

            // Filter by pattern
            if (regex != null && !regex.IsMatch(type.Name))
                continue;

            var kind = type.Kind switch
            {
                TypeKind.Class => "Class",
                TypeKind.Struct => "Struct",
                TypeKind.Interface => "Interface",
                TypeKind.Enum => "Enum",
                TypeKind.Delegate => "Delegate",
                _ => "Unknown"
            };

            types.Add(new TypeInfo
            {
                FullName = type.FullName,
                Name = type.Name,
                Namespace = type.Namespace,
                Kind = kind,
                IsPublic = type.Accessibility == Accessibility.Public,
                MethodCount = type.Methods.Count(m => !m.IsAccessor),
                PropertyCount = type.Properties.Count(),
                FieldCount = type.Fields.Count()
            });
        }

        return types.OrderBy(t => t.Namespace).ThenBy(t => t.Name).ToList();
    }

    public DecompileResult DecompileType(string dllPath, string typeName)
    {
        try
        {
            var decompiler = GetDecompiler(dllPath);

            // Find the type
            var type = decompiler.TypeSystem.MainModule.TypeDefinitions
                .FirstOrDefault(t => t.FullName == typeName || t.Name == typeName);

            if (type == null)
            {
                // Try partial match
                type = decompiler.TypeSystem.MainModule.TypeDefinitions
                    .FirstOrDefault(t => t.FullName.EndsWith("." + typeName) || t.FullName.EndsWith("+" + typeName));
            }

            if (type == null)
            {
                return new DecompileResult
                {
                    Success = false,
                    ErrorMessage = $"Type not found: {typeName}"
                };
            }

            var code = decompiler.DecompileTypeAsString(type.FullTypeName);

            return new DecompileResult
            {
                Success = true,
                SourceCode = code
            };
        }
        catch (Exception ex)
        {
            return new DecompileResult
            {
                Success = false,
                ErrorMessage = $"Decompilation failed: {ex.Message}"
            };
        }
    }

    public DecompileResult DecompileMethod(string dllPath, string typeName, string methodName)
    {
        try
        {
            var decompiler = GetDecompiler(dllPath);

            // Find the type
            var type = decompiler.TypeSystem.MainModule.TypeDefinitions
                .FirstOrDefault(t => t.FullName == typeName || t.Name == typeName);

            if (type == null)
            {
                type = decompiler.TypeSystem.MainModule.TypeDefinitions
                    .FirstOrDefault(t => t.FullName.EndsWith("." + typeName) || t.FullName.EndsWith("+" + typeName));
            }

            if (type == null)
            {
                return new DecompileResult
                {
                    Success = false,
                    ErrorMessage = $"Type not found: {typeName}"
                };
            }

            // Find matching methods (there may be overloads)
            var methods = type.Methods
                .Where(m => m.Name == methodName || m.Name.StartsWith(methodName + "("))
                .ToList();

            if (methods.Count == 0)
            {
                return new DecompileResult
                {
                    Success = false,
                    ErrorMessage = $"Method not found: {methodName} in type {typeName}"
                };
            }

            var sb = new StringBuilder();
            foreach (var method in methods)
            {
                try
                {
                    var handle = (System.Reflection.Metadata.MethodDefinitionHandle)method.MetadataToken;
                    var code = decompiler.DecompileAsString(handle);
                    sb.AppendLine(code);
                    sb.AppendLine();
                }
                catch
                {
                    // Skip methods that fail to decompile individually
                }
            }

            if (sb.Length == 0)
            {
                // Fall back to decompiling the whole type
                var typeCode = decompiler.DecompileTypeAsString(type.FullTypeName);
                return new DecompileResult
                {
                    Success = true,
                    SourceCode = $"// Could not decompile method individually, showing full type:\n\n{typeCode}"
                };
            }

            return new DecompileResult
            {
                Success = true,
                SourceCode = sb.ToString()
            };
        }
        catch (Exception ex)
        {
            return new DecompileResult
            {
                Success = false,
                ErrorMessage = $"Decompilation failed: {ex.Message}"
            };
        }
    }

    public List<SearchResult> SearchCode(string dllPath, string keyword, int maxResults = 20)
    {
        var decompiler = GetDecompiler(dllPath);
        var results = new List<SearchResult>();
        var keywordLower = keyword.ToLowerInvariant();

        foreach (var type in decompiler.TypeSystem.MainModule.TypeDefinitions)
        {
            if (results.Count >= maxResults) break;

            // Skip compiler-generated types
            if (type.Name.StartsWith("<") || type.Name.Contains("__"))
                continue;

            // Search in type name
            if (type.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                results.Add(new SearchResult
                {
                    TypeName = type.FullName,
                    MemberKind = "Type",
                    MatchContext = $"Type name matches: {type.Name}"
                });
                if (results.Count >= maxResults) break;
            }

            // Search in methods
            foreach (var method in type.Methods)
            {
                if (results.Count >= maxResults) break;

                if (method.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(new SearchResult
                    {
                        TypeName = type.FullName,
                        MemberName = method.Name,
                        MemberKind = "Method",
                        MatchContext = $"Method: {method.Name}({string.Join(", ", method.Parameters.Select(p => p.Type.Name))})"
                    });
                }
            }

            // Search in properties
            foreach (var prop in type.Properties)
            {
                if (results.Count >= maxResults) break;

                if (prop.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(new SearchResult
                    {
                        TypeName = type.FullName,
                        MemberName = prop.Name,
                        MemberKind = "Property",
                        MatchContext = $"Property: {prop.ReturnType.Name} {prop.Name}"
                    });
                }
            }

            // Search in fields
            foreach (var field in type.Fields)
            {
                if (results.Count >= maxResults) break;

                if (field.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(new SearchResult
                    {
                        TypeName = type.FullName,
                        MemberName = field.Name,
                        MemberKind = "Field",
                        MatchContext = $"Field: {field.Type.Name} {field.Name}"
                    });
                }
            }
        }

        return results;
    }

    public ExportResult ExportAssembly(string dllPath, string outputDir)
    {
        try
        {
            var fullPath = Path.GetFullPath(dllPath);
            var fullOutputDir = Path.GetFullPath(outputDir);

            if (!File.Exists(fullPath))
            {
                return new ExportResult
                {
                    Success = false,
                    ErrorMessage = $"DLL not found: {fullPath}"
                };
            }

            // Create output directory
            Directory.CreateDirectory(fullOutputDir);

            using var module = new PEFile(fullPath);

            var settings = new DecompilerSettings(LanguageVersion.Latest)
            {
                ThrowOnAssemblyResolveErrors = false,
                ShowXmlDocumentation = true,
            };

            var projectDecompiler = new WholeProjectDecompiler(
                settings,
                new UniversalAssemblyResolver(fullPath, false, module.Metadata.DetectTargetFrameworkId()),
                null,  // No assembly reference classifier
                null   // No debug info provider
            );

            projectDecompiler.DecompileProject(module, fullOutputDir);

            // Count generated files
            var fileCount = Directory.GetFiles(fullOutputDir, "*.cs", SearchOption.AllDirectories).Length;

            return new ExportResult
            {
                Success = true,
                OutputPath = fullOutputDir,
                FileCount = fileCount
            };
        }
        catch (Exception ex)
        {
            return new ExportResult
            {
                Success = false,
                ErrorMessage = $"Export failed: {ex.Message}"
            };
        }
    }

    public void ClearCache()
    {
        lock (_lock)
        {
            _decompilerCache.Clear();
        }
    }

    public void Dispose()
    {
        ClearCache();
    }
}
