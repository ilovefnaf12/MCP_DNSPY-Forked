using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace DnSpyMcp;

public class Il2CppService
{
    private readonly string _il2CppDumperPath;
    private readonly string _outputBaseDir;
    private readonly string _il2CppDumperToolDir;
    private readonly string _il2CppDumperConfigPath;

    public Il2CppService()
    {
        // Il2CppDumper is in tools folder relative to the exe
        var exeDir = AppContext.BaseDirectory;

        // Try multiple possible locations
        var possiblePaths = new[]
        {
            Path.Combine(exeDir, "..", "..", "..", "tools", "Il2CppDumper", "Il2CppDumper.exe"),
            Path.Combine(exeDir, "tools", "Il2CppDumper", "Il2CppDumper.exe"),
            @"f:\dsnpyForClaude\tools\Il2CppDumper\Il2CppDumper.exe"
        };

        _il2CppDumperPath = possiblePaths.FirstOrDefault(File.Exists)
            ?? throw new FileNotFoundException("Il2CppDumper.exe not found");

        _il2CppDumperToolDir = Path.GetDirectoryName(_il2CppDumperPath)!
            ?? throw new DirectoryNotFoundException("Il2CppDumper directory not found");

        _il2CppDumperConfigPath = Path.Combine(_il2CppDumperToolDir, "config.json");

        _outputBaseDir = Path.Combine(_il2CppDumperToolDir, "output");
        Directory.CreateDirectory(_outputBaseDir);
    }

    public class DumpResult
    {
        public bool Success { get; set; }
        public string? OutputDir { get; set; }
        public string? DummyDllDir { get; set; }
        public string? ErrorMessage { get; set; }
        public List<string> GeneratedFiles { get; set; } = new();
    }

    /// <summary>
    /// Dump IL2CPP game using Il2CppDumper
    /// </summary>
    public DumpResult DumpIl2Cpp(string gameAssemblyPath, string metadataPath, string? outputName = null)
    {
        try
        {
            // Validate inputs
            if (!File.Exists(gameAssemblyPath))
            {
                return new DumpResult
                {
                    Success = false,
                    ErrorMessage = $"GameAssembly not found: {gameAssemblyPath}"
                };
            }

            if (!File.Exists(metadataPath))
            {
                return new DumpResult
                {
                    Success = false,
                    ErrorMessage = $"global-metadata.dat not found: {metadataPath}"
                };
            }

            // Create output directory
            var gameName = outputName ?? Path.GetFileNameWithoutExtension(
                Path.GetDirectoryName(gameAssemblyPath) ?? "unknown");
            var outputDir = Path.Combine(_outputBaseDir, gameName + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            Directory.CreateDirectory(outputDir);

            // Il2CppDumper writes outputs relative to its own executable directory (not the process working directory).
            // Stage a local copy + config.json inside outputDir so each dump is isolated and non-interactive.
            var stagedDumperPath = Path.Combine(outputDir, Path.GetFileName(_il2CppDumperPath));
            File.Copy(_il2CppDumperPath, stagedDumperPath, overwrite: true);
            WriteNonInteractiveConfig(outputDir);

            // Run Il2CppDumper
            var startInfo = new ProcessStartInfo
            {
                FileName = stagedDumperPath,
                Arguments = $"\"{gameAssemblyPath}\" \"{metadataPath}\"",
                WorkingDirectory = outputDir,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var process = new Process { StartInfo = startInfo };
            var output = new StringBuilder();
            var error = new StringBuilder();

            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null) output.AppendLine(e.Data);
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null) error.AppendLine(e.Data);
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            try
            {
                // Send empty lines to accept defaults, if the dumper prompts.
                process.StandardInput.WriteLine();
                process.StandardInput.WriteLine();
                process.StandardInput.WriteLine();
            }
            catch
            {
                // ignore stdin errors
            }

            // Wait with timeout (5 minutes max)
            if (!process.WaitForExit(300000))
            {
                process.Kill();
                return new DumpResult
                {
                    Success = false,
                    ErrorMessage = "Il2CppDumper timed out after 5 minutes"
                };
            }

            // Check results
            var dummyDllDir = Path.Combine(outputDir, "DummyDll");
            var generatedFiles = new List<string>();

            if (Directory.Exists(dummyDllDir))
            {
                generatedFiles.AddRange(Directory.GetFiles(dummyDllDir, "*.dll")
                    .Select(Path.GetFileName)!);
            }

            // Check for other output files
            var otherFiles = new[] { "dump.cs", "script.json", "stringliteral.json", "il2cpp.h" };
            foreach (var file in otherFiles)
            {
                if (File.Exists(Path.Combine(outputDir, file)))
                {
                    generatedFiles.Add(file);
                }
            }

            if (generatedFiles.Count == 0)
            {
                return new DumpResult
                {
                    Success = false,
                    ErrorMessage = $"Il2CppDumper produced no output.\nStdout: {output}\nStderr: {error}"
                };
            }

            return new DumpResult
            {
                Success = true,
                OutputDir = outputDir,
                DummyDllDir = Directory.Exists(dummyDllDir) ? dummyDllDir : null,
                GeneratedFiles = generatedFiles
            };
        }
        catch (Exception ex)
        {
            return new DumpResult
            {
                Success = false,
                ErrorMessage = $"Failed to run Il2CppDumper: {ex.Message}"
            };
        }
    }

    private void WriteNonInteractiveConfig(string outputDir)
    {
        var targetConfigPath = Path.Combine(outputDir, "config.json");

        try
        {
            JsonNode? configNode = null;
            if (File.Exists(_il2CppDumperConfigPath))
            {
                configNode = JsonNode.Parse(File.ReadAllText(_il2CppDumperConfigPath));
            }

            configNode ??= new JsonObject
            {
                ["DumpMethod"] = true,
                ["DumpField"] = true,
                ["DumpProperty"] = true,
                ["DumpAttribute"] = true,
                ["DumpFieldOffset"] = true,
                ["DumpMethodOffset"] = true,
                ["DumpTypeDefIndex"] = true,
                ["GenerateDummyDll"] = true,
                ["GenerateStruct"] = true,
                ["DummyDllAddToken"] = true,
                ["ForceIl2CppVersion"] = false,
                ["ForceVersion"] = 16,
                ["ForceDump"] = false,
                ["NoRedirectedPointer"] = false
            };

            if (configNode is JsonObject obj)
            {
                obj["RequireAnyKey"] = false;
            }

            File.WriteAllText(
                targetConfigPath,
                configNode.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
                Encoding.UTF8);
        }
        catch
        {
            var minimal = new JsonObject { ["RequireAnyKey"] = false };
            File.WriteAllText(
                targetConfigPath,
                minimal.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
                Encoding.UTF8);
        }
    }

    /// <summary>
    /// Auto-detect IL2CPP files in a game directory
    /// </summary>
    public (string? gameAssembly, string? metadata) DetectIl2CppFiles(string gameDir)
    {
        string? gameAssembly = null;
        string? metadata = null;

        // Common GameAssembly locations
        var assemblyPaths = new[]
        {
            Path.Combine(gameDir, "GameAssembly.dll"),
            Path.Combine(gameDir, "libil2cpp.so"),
            Path.Combine(gameDir, "UnityFramework.framework", "UnityFramework"),
        };

        gameAssembly = assemblyPaths.FirstOrDefault(File.Exists);

        // Common metadata locations
        var metadataPaths = new[]
        {
            Path.Combine(gameDir, "il2cpp_data", "Metadata", "global-metadata.dat"),
            Path.Combine(gameDir, $"{Path.GetFileName(gameDir)}_Data", "il2cpp_data", "Metadata", "global-metadata.dat"),
        };

        // Also search recursively for global-metadata.dat
        if (metadataPaths.All(p => !File.Exists(p)))
        {
            try
            {
                var found = Directory.GetFiles(gameDir, "global-metadata.dat", SearchOption.AllDirectories)
                    .FirstOrDefault();
                if (found != null)
                {
                    metadata = found;
                }
            }
            catch
            {
                // Ignore search errors
            }
        }
        else
        {
            metadata = metadataPaths.FirstOrDefault(File.Exists);
        }

        return (gameAssembly, metadata);
    }

    /// <summary>
    /// Read dump.cs file which contains all decompiled type info
    /// </summary>
    public string? ReadDumpCs(string outputDir)
    {
        var dumpPath = Path.Combine(outputDir, "dump.cs");
        if (File.Exists(dumpPath))
        {
            return File.ReadAllText(dumpPath);
        }
        return null;
    }

    /// <summary>
    /// Read script.json which contains method addresses
    /// </summary>
    public string? ReadScriptJson(string outputDir)
    {
        var scriptPath = Path.Combine(outputDir, "script.json");
        if (File.Exists(scriptPath))
        {
            return File.ReadAllText(scriptPath);
        }
        return null;
    }

    /// <summary>
    /// Search in dump.cs for a pattern
    /// </summary>
    public List<string> SearchInDump(string outputDir, string keyword, int contextLines = 5)
    {
        var results = new List<string>();
        var dumpPath = Path.Combine(outputDir, "dump.cs");

        if (!File.Exists(dumpPath))
        {
            return results;
        }

        var lines = File.ReadAllLines(dumpPath);
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                var start = Math.Max(0, i - contextLines);
                var end = Math.Min(lines.Length - 1, i + contextLines);

                var context = new StringBuilder();
                context.AppendLine($"// Match at line {i + 1}:");
                for (int j = start; j <= end; j++)
                {
                    var prefix = j == i ? ">>> " : "    ";
                    context.AppendLine($"{prefix}{lines[j]}");
                }
                results.Add(context.ToString());

                if (results.Count >= 20) break; // Limit results
            }
        }

        return results;
    }

    /// <summary>
    /// Get method address from script.json
    /// </summary>
    public Dictionary<string, object>? GetMethodInfo(string outputDir, string methodName)
    {
        var scriptPath = Path.Combine(outputDir, "script.json");
        if (!File.Exists(scriptPath))
        {
            return null;
        }

        try
        {
            var json = File.ReadAllText(scriptPath);
            using var doc = JsonDocument.Parse(json);

            if (doc.RootElement.TryGetProperty("ScriptMethod", out var methods))
            {
                foreach (var method in methods.EnumerateArray())
                {
                    if (method.TryGetProperty("Name", out var name) &&
                        name.GetString()?.Contains(methodName, StringComparison.OrdinalIgnoreCase) == true)
                    {
                        var result = new Dictionary<string, object>();
                        foreach (var prop in method.EnumerateObject())
                        {
                            result[prop.Name] = prop.Value.ToString();
                        }
                        return result;
                    }
                }
            }
        }
        catch
        {
            // Ignore parse errors
        }

        return null;
    }

    public bool TryFindMethodRva(string outputDir, string methodName, out long rva, out string? matchedName, out string? signature)
    {
        rva = 0;
        matchedName = null;
        signature = null;

        if (string.IsNullOrWhiteSpace(outputDir) || string.IsNullOrWhiteSpace(methodName))
        {
            return false;
        }

        var scriptPath = Path.Combine(outputDir, "script.json");
        if (!File.Exists(scriptPath))
        {
            return false;
        }

        // script.json is huge; avoid JsonDocument parsing. Do a simple line scan:
        // Each ScriptMethod entry looks like:
        //   "Address": 7972768,
        //   "Name": "EscapeGame.UIGen.Keyboard$$SetCurrentBtn",
        //   "Signature": "void ..."
        try
        {
            long lastAddress = -1;
            using var fs = new FileStream(scriptPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 16);

            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                if (line.Contains("\"Address\"", StringComparison.Ordinal))
                {
                    var m = System.Text.RegularExpressions.Regex.Match(line, "\"Address\"\\s*:\\s*(\\d+)");
                    if (m.Success && long.TryParse(m.Groups[1].Value, out var parsed))
                    {
                        lastAddress = parsed;
                    }
                    continue;
                }

                if (line.Contains("\"Name\"", StringComparison.Ordinal))
                {
                    var m = System.Text.RegularExpressions.Regex.Match(line, "\"Name\"\\s*:\\s*\"([^\"]+)\"");
                    if (!m.Success)
                    {
                        continue;
                    }

                    var name = m.Groups[1].Value;
                    if (name.IndexOf(methodName, StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        continue;
                    }

                    matchedName = name;

                    // best-effort: read forward a couple lines for signature
                    var pos = reader.BaseStream.Position;
                    var sigLine = reader.ReadLine();
                    if (sigLine != null && sigLine.Contains("\"Signature\"", StringComparison.Ordinal))
                    {
                        var sm = System.Text.RegularExpressions.Regex.Match(sigLine, "\"Signature\"\\s*:\\s*\"([^\"]+)\"");
                        if (sm.Success) signature = sm.Groups[1].Value;
                    }
                    else
                    {
                        // reset if we didn't actually consume signature
                        reader.BaseStream.Position = pos;
                        reader.DiscardBufferedData();
                    }

                    if (lastAddress >= 0)
                    {
                        rva = lastAddress;
                        return true;
                    }
                }
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    public Dictionary<long, string> GetMethodDisplayNamesByRva(string outputDir, IEnumerable<long> rvas)
    {
        var metadata = GetMethodMetadataByRva(outputDir, rvas);
        return metadata
            .Where(kv => !string.IsNullOrWhiteSpace(kv.Value.DisplayName))
            .ToDictionary(kv => kv.Key, kv => kv.Value.DisplayName!);
    }

    public sealed class ScriptMethodMetadata
    {
        public long Address { get; init; }
        public string? Name { get; init; }
        public string? Signature { get; init; }
        public string? DisplayName { get; init; }
    }

    public Dictionary<long, ScriptMethodMetadata> GetMethodMetadataByRva(string outputDir, IEnumerable<long> rvas)
    {
        var result = new Dictionary<long, ScriptMethodMetadata>();
        if (string.IsNullOrWhiteSpace(outputDir))
        {
            return result;
        }

        var targets = new HashSet<long>(rvas.Where(v => v >= 0));
        if (targets.Count == 0)
        {
            return result;
        }

        var scriptPath = Path.Combine(outputDir, "script.json");
        if (!File.Exists(scriptPath))
        {
            return result;
        }

        try
        {
            long currentAddress = -1;
            string? currentName = null;
            string? currentSignature = null;

            void FlushCurrent()
            {
                if (currentAddress < 0 || !targets.Contains(currentAddress))
                {
                    return;
                }

                if (result.ContainsKey(currentAddress))
                {
                    return;
                }

                var preferred = ExtractFunctionNameFromSignature(currentSignature)
                    ?? NormalizeScriptMethodName(currentName);

                result[currentAddress] = new ScriptMethodMetadata
                {
                    Address = currentAddress,
                    Name = currentName,
                    Signature = currentSignature,
                    DisplayName = preferred
                };
            }

            using var fs = new FileStream(scriptPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1 << 16);

            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                if (line.Contains("\"Address\"", StringComparison.Ordinal))
                {
                    FlushCurrent();
                    currentName = null;
                    currentSignature = null;
                    currentAddress = -1;

                    var m = Regex.Match(line, "\"Address\"\\s*:\\s*(\\d+)");
                    if (m.Success && long.TryParse(m.Groups[1].Value, out var parsed))
                    {
                        currentAddress = parsed;
                    }

                    continue;
                }

                if (currentAddress < 0)
                {
                    continue;
                }

                if (line.Contains("\"Name\"", StringComparison.Ordinal))
                {
                    var m = Regex.Match(line, "\"Name\"\\s*:\\s*\"([^\"]+)\"");
                    if (m.Success)
                    {
                        currentName = m.Groups[1].Value;
                    }
                    continue;
                }

                if (line.Contains("\"Signature\"", StringComparison.Ordinal))
                {
                    var m = Regex.Match(line, "\"Signature\"\\s*:\\s*\"([^\"]+)\"");
                    if (m.Success)
                    {
                        currentSignature = m.Groups[1].Value;
                    }
                    continue;
                }
            }

            FlushCurrent();
        }
        catch
        {
            // Ignore parse errors; return best-effort matches.
        }

        return result;
    }

    private static string? ExtractFunctionNameFromSignature(string? signature)
    {
        if (string.IsNullOrWhiteSpace(signature))
        {
            return null;
        }

        var m = Regex.Match(
            signature,
            @"^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            RegexOptions.CultureInvariant);
        if (!m.Success)
        {
            return null;
        }

        return m.Groups[1].Value;
    }

    private static string? NormalizeScriptMethodName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        var normalized = name.Replace("$$", "__", StringComparison.Ordinal);
        normalized = Regex.Replace(normalized, @"[^A-Za-z0-9_]", "_", RegexOptions.CultureInvariant);
        normalized = Regex.Replace(normalized, @"_+", "_", RegexOptions.CultureInvariant);
        normalized = normalized.Trim('_');
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
    }
}
