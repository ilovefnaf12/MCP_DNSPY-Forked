# IL2CPP Dump（dnspy MCP / DnSpyMcp）跑通记录

> 目的：解决 `dnspy/il2cpp_dump` 在 Windows 非交互环境下无法稳定产出工件的问题，让我们能得到 **IL2CPP 的类型信息 + 方法地址（script.json）+ DummyDll**，以便后续做更深入的 native 侧分析/Hook。

## 结论（当前已跑通）

`il2cpp_dump` 现在可以稳定生成：
- `dump.cs`
- `script.json`（包含方法地址等）
- `stringliteral.json`
- `il2cpp.h`
- `DummyDll/*.dll`（仅签名/字段布局，无方法体）

示例输出（KotamaAcademyCitadel）：
- `F:\dsnpyForClaude\tools\Il2CppDumper\output\KotamaAcademyCitadel_20260115_223118`
- `F:\dsnpyForClaude\tools\Il2CppDumper\output\KotamaAcademyCitadel_20260115_223118\DummyDll`

## 根因分析（为什么之前会失败）

### 1) Il2CppDumper 输出目录不是 “WorkingDirectory”
当前使用的 Il2CppDumper（`F:\dsnpyForClaude\tools\Il2CppDumper\Il2CppDumper.exe`）会把输出写到：
- **它自己的可执行文件所在目录**（exeDir），而不是 DnSpyMcp 进程给它设置的 `WorkingDirectory`。

因此旧实现里即使 `WorkingDirectory = outputDir`：
- `outputDir` 仍然是空的
- DnSpyMcp 检测不到 `DummyDll/dump.cs/script.json`，返回 `Il2CppDumper produced no output`

### 2) 非交互环境下的 `Console.ReadKey` 崩溃
Il2CppDumper 在末尾会提示 `Press any key to exit...`，并调用 `Console.ReadKey()`：
- 当 stdin 被重定向 / 没有真实控制台时，会抛：
  - `System.InvalidOperationException: Cannot read keys ... Console input has been redirected`

这会导致 dump 即便做完了，也会以异常退出（对于 MCP 来说属于失败路径）。

## 修复方案（已落地）

修复点在 DnSpyMcp 侧（不是去改 Il2CppDumper 源码）。

文件：`F:\dsnpyForClaude\src\DnSpyMcp\Il2CppService.cs`

核心改动：
1) **为每次 dump 创建独立 outputDir**
2) 把 `Il2CppDumper.exe` **复制到 outputDir 内**（stage）
3) 在 outputDir 内写入 `config.json`，并强制：
   - `"RequireAnyKey": false`
4) 运行 stage 后的 exe（让输出自然落到 outputDir），并保持 stdout/stderr 捕获

这样：
- 输出工件能出现在 outputDir（DnSpyMcp 能发现）
- 不会再 `ReadKey` 崩溃（非交互可跑通）

发布方式：
- `dotnet publish F:\dsnpyForClaude\src\DnSpyMcp\DnSpyMcp.csproj -c Release -o F:\dsnpyForClaude\publish`

注意：发布时 `F:\dsnpyForClaude\publish\DnSpyMcp.dll` 可能被正在运行的 DnSpyMcp 进程锁定，需要先停止该进程再 publish。

## 如何验证（不依赖 Codex 内置工具调用）

DnSpyMcp 支持 JSON line framing（第一条消息以 `{` 开头即可）。

一次性验证（stdin 关闭后进程退出）：

### 1) ping
```powershell
$json='{"jsonrpc":"2.0","id":1,"method":"ping"}'
[IO.File]::WriteAllBytes('F:\dsnpyForClaude\ping_input.txt',[Text.Encoding]::UTF8.GetBytes($json+"`n"))
cmd /c "type F:\dsnpyForClaude\ping_input.txt | F:\dsnpyForClaude\publish\DnSpyMcp.exe"
```

### 2) il2cpp_dump
```powershell
$call = @{
  jsonrpc='2.0'; id=1; method='tools/call';
  params=@{
    name='il2cpp_dump';
    arguments=@{
      gameDir='E:\\SteamLibrary\\steamapps\\common\\KotamaAcademyCitadel';
      metadataPath='E:\\SteamLibrary\\steamapps\\common\\KotamaAcademyCitadel\\KotamaAcademyCitadel_Data\\il2cpp_data\\Metadata\\global-metadata.dat'
    }
  }
} | ConvertTo-Json -Compress

[IO.File]::WriteAllBytes('F:\dsnpyForClaude\il2cpp_dump_input.txt',[Text.Encoding]::UTF8.GetBytes($call+\"`n\"))
cmd /c \"type F:\\dsnpyForClaude\\il2cpp_dump_input.txt | F:\\dsnpyForClaude\\publish\\DnSpyMcp.exe\"
```

输出 JSON 中会包含 outputDir 路径。

## 重要认知：IL2CPP “反编译内部实现” 的边界

- `DummyDll` / `dump.cs` 给的是 **类型结构与方法签名**（可以定位类/字段/方法名，帮助搜索与 Hook）
- **不包含 C# 方法体实现**（IL2CPP 已经编译成 native）
- 想看“实现”，通常要走：
  - `script.json` 提供的 method 地址
  - 配合 IDA/Ghidra/ghidra.py/ida.py 之类脚本在 native 层反汇编定位

## 后续可用的工作流（围绕键位绑定问题）

1) `il2cpp_dump` 得到 outputDir
2) 用 `il2cpp_search` 搜索关键类型/方法名（例：`EscapeGame.UIGen.Keyboard`、`SetCurrentBtn`）
3) 用 `il2cpp_get_method_address` 拿方法地址（native 定位）
4) 需要字段布局时，用 `DummyDll` 或 `dump.cs` 对齐结构

## Native 伪代码（新增）

### 能拿到什么
- **可以拿到**：Ghidra Decompiler 的 C-like 伪代码（native 层逻辑），适合定位分支/条件/调用链。
- **拿不到**：原始 C# 方法体（IL2CPP 已经编译为 native）。

### 依赖
- 需要本机安装 Ghidra（headless 模式即可）。
- 安装步骤见：`F:/dsnpyForClaude/docs/GHIDRA_SETUP.md`

### MCP 工具（DnSpyMcp 新增）
- `il2cpp_native_decompile`
  - 输入：`outputDir`（包含 `script.json`）、`methodName`、`gameAssemblyPath`（或 `gameDir`）、可选 `ghidraRoot`
  - 可选：`javaHome`（建议直接传 JDK 21 的安装目录，这样不需要全局改环境变量）
  - 输出：把伪代码写到 `outputDir\\native_decompile\\<matched>.c`
