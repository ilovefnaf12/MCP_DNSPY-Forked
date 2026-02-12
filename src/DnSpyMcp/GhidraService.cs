using System.Diagnostics;
using System.Text;

namespace DnSpyMcp;

public sealed class GhidraService
{
    private readonly string _defaultGhidraRoot;
    private readonly string _scriptDir;

    public GhidraService()
    {
        // Default: co-located with this repo/tool layout. Can be overridden per-call via parameters.
        _defaultGhidraRoot = @"f:\dsnpyForClaude\tools\ghidra";
        _scriptDir = Path.Combine(AppContext.BaseDirectory, "GhidraScripts");
    }

    public sealed class NativeDecompileResult
    {
        public bool Success { get; set; }
        public string? OutputFile { get; set; }
        public string? Stdout { get; set; }
        public string? Stderr { get; set; }
        public string? ErrorMessage { get; set; }
        public string? AnalyzeHeadlessPath { get; set; }
        public string? ProjectDir { get; set; }
        public string? ProjectName { get; set; }
    }

    public NativeDecompileResult DecompileAtRva(
        string gameAssemblyPath,
        long rva,
        string outputFilePath,
        string? displayName = null,
        string? ghidraRootOverride = null,
        string? javaHomeOverride = null,
        int timeoutSeconds = 900)
    {
        try
        {
            if (!File.Exists(gameAssemblyPath))
            {
                return new NativeDecompileResult
                {
                    Success = false,
                    ErrorMessage = $"GameAssembly not found: {gameAssemblyPath}"
                };
            }

            var ghidraRoot = string.IsNullOrWhiteSpace(ghidraRootOverride) ? _defaultGhidraRoot : ghidraRootOverride!;
            var analyzeHeadless = FindAnalyzeHeadless(ghidraRoot);
            if (analyzeHeadless == null)
            {
                return new NativeDecompileResult
                {
                    Success = false,
                    ErrorMessage = $"Ghidra not found. Expected analyzeHeadless.bat under: {ghidraRoot}",
                };
            }

            // Preflight: ensure we have a usable Java.
            // If Java is missing, analyzeHeadless.bat will "pause" and hang in a headless process.
            var javaExe = FindJavaExe(javaHomeOverride);
            if (javaExe == null)
            {
                return new NativeDecompileResult
                {
                    Success = false,
                    ErrorMessage =
                        "Java not found. Ghidra 12.x requires JDK 21. " +
                        "Install JDK 21 and either set JAVA_HOME/PATH globally or pass javaHome to il2cpp_native_decompile."
                };
            }

            // If Java isn't provided explicitly, infer JAVA_HOME from the resolved java.exe so we can
            // run without relying on global environment variables.
            var resolvedJavaHome = !string.IsNullOrWhiteSpace(javaHomeOverride)
                ? javaHomeOverride
                : TryInferJavaHomeFromJavaExe(javaExe);

            Directory.CreateDirectory(Path.GetDirectoryName(outputFilePath)!);

            var projectDir = Path.Combine(Path.GetDirectoryName(outputFilePath)!, "ghidra_project");
            Directory.CreateDirectory(projectDir);

            var projectName = "il2cpp_native_" + DateTime.Now.ToString("yyyyMMdd_HHmmss");

            // Note: For PE binaries, Ghidra sets image base from the PE header; Il2CppDumper's script.json uses RVA.
            // Our script converts RVA -> imageBase + RVA.
            var scriptPath = _scriptDir;
            var postScript = "DecompileAtRva.java";

            var args = new List<string>
            {
                Quote(projectDir),
                Quote(projectName),
                "-import", Quote(gameAssemblyPath),
                "-overwrite",
                "-noanalysis",
                "-scriptPath", Quote(scriptPath),
                "-postScript", postScript, rva.ToString(), Quote(outputFilePath), Quote(displayName ?? string.Empty),
            };

            var startInfo = new ProcessStartInfo
            {
                FileName = analyzeHeadless,
                Arguments = string.Join(" ", args),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            if (!string.IsNullOrWhiteSpace(resolvedJavaHome))
            {
                var javaHome = resolvedJavaHome!;
                startInfo.Environment["JAVA_HOME"] = javaHome;

                var javaBin = Path.Combine(javaHome, "bin");
                if (Directory.Exists(javaBin))
                {
                    // Prepend java bin so analyzeHeadless can find java without global PATH edits.
                    var existingPath = startInfo.Environment.ContainsKey("PATH")
                        ? startInfo.Environment["PATH"]
                        : Environment.GetEnvironmentVariable("PATH");
                    startInfo.Environment["PATH"] = javaBin + ";" + (existingPath ?? string.Empty);
                }
            }

            using var process = new Process { StartInfo = startInfo };
            var stdout = new StringBuilder();
            var stderr = new StringBuilder();

            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null) stdout.AppendLine(e.Data);
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null) stderr.AppendLine(e.Data);
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            if (!process.WaitForExit(timeoutSeconds * 1000))
            {
                try { process.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return new NativeDecompileResult
                {
                    Success = false,
                    ErrorMessage = $"Ghidra analyzeHeadless timed out after {timeoutSeconds} seconds",
                    AnalyzeHeadlessPath = analyzeHeadless,
                    ProjectDir = projectDir,
                    ProjectName = projectName,
                    Stdout = stdout.ToString(),
                    Stderr = stderr.ToString()
                };
            }

            if (!File.Exists(outputFilePath))
            {
                return new NativeDecompileResult
                {
                    Success = false,
                    ErrorMessage = $"Decompile output was not created: {outputFilePath}",
                    AnalyzeHeadlessPath = analyzeHeadless,
                    ProjectDir = projectDir,
                    ProjectName = projectName,
                    Stdout = stdout.ToString(),
                    Stderr = stderr.ToString()
                };
            }

            return new NativeDecompileResult
            {
                Success = true,
                OutputFile = outputFilePath,
                AnalyzeHeadlessPath = analyzeHeadless,
                ProjectDir = projectDir,
                ProjectName = projectName,
                Stdout = stdout.ToString(),
                Stderr = stderr.ToString()
            };
        }
        catch (Exception ex)
        {
            return new NativeDecompileResult
            {
                Success = false,
                ErrorMessage = $"Failed to run Ghidra headless: {ex.GetType().Name}: {ex.Message}"
            };
        }
    }

    private static string? FindJavaExe(string? javaHomeOverride)
    {
        // 1) Explicit override
        if (!string.IsNullOrWhiteSpace(javaHomeOverride))
        {
            var candidate = Path.Combine(javaHomeOverride!, "bin", "java.exe");
            if (File.Exists(candidate)) return candidate;
            return null;
        }

        // 1.5) Common co-located install path used by this project:
        // Keep this as a fallback so callers don't have to modify global env vars.
        // Example: F:\dsnpyForClaude\tools\jdk21\jdk-21.0.9+10\bin\java.exe
        try
        {
            var toolRoot = @"f:\dsnpyForClaude\tools\jdk21";
            if (Directory.Exists(toolRoot))
            {
                var java = Directory.GetFiles(toolRoot, "java.exe", SearchOption.AllDirectories)
                    .FirstOrDefault(p => p.EndsWith(@"\bin\java.exe", StringComparison.OrdinalIgnoreCase));
                if (java != null) return java;
            }
        }
        catch
        {
            // ignore
        }

        // 2) JAVA_HOME
        var envHome = Environment.GetEnvironmentVariable("JAVA_HOME");
        if (!string.IsNullOrWhiteSpace(envHome))
        {
            var candidate = Path.Combine(envHome!, "bin", "java.exe");
            if (File.Exists(candidate)) return candidate;
        }

        // 3) PATH scan
        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var part in path.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(part.Trim(), "java.exe");
                if (File.Exists(candidate)) return candidate;
            }
            catch
            {
                // ignore bad path entries
            }
        }

        return null;
    }

    private static string? TryInferJavaHomeFromJavaExe(string javaExePath)
    {
        try
        {
            // <javaHome>\bin\java.exe
            var binDir = Path.GetDirectoryName(javaExePath);
            if (binDir == null) return null;
            if (!binDir.EndsWith(Path.DirectorySeparatorChar + "bin", StringComparison.OrdinalIgnoreCase))
            {
                // If it's not in a \bin folder, we can't safely infer
                return null;
            }

            var home = Path.GetDirectoryName(binDir);
            if (home == null) return null;
            return Directory.Exists(home) ? home : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? FindAnalyzeHeadless(string ghidraRoot)
    {
        if (string.IsNullOrWhiteSpace(ghidraRoot) || !Directory.Exists(ghidraRoot))
        {
            return null;
        }

        try
        {
            // Typical layout: <ghidraRoot>\ghidra_*\support\analyzeHeadless.bat
            var candidate = Directory.GetFiles(ghidraRoot, "analyzeHeadless.bat", SearchOption.AllDirectories)
                .FirstOrDefault();
            return candidate;
        }
        catch
        {
            return null;
        }
    }

    private static string Quote(string value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";
        if (value.Contains(' ') || value.Contains('\t') || value.Contains('"'))
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }
        return "\"" + value + "\"";
    }
}
