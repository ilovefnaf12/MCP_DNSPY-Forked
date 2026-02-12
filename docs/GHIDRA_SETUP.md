# Ghidra 安装（供 DnSpyMcp IL2CPP native 反编译使用）

> 你不希望我在机器上下载文件，所以这里给出官方链接与本地落盘路径约定。  
> 目标：让 `DnSpyMcp` 的 `il2cpp_native_decompile` 能找到 `analyzeHeadless.bat` 并产出伪代码。

## 1) 下载链接（官方）

- Release 页面（推荐）：https://github.com/NationalSecurityAgency/ghidra/releases/latest

在 Assets 中下载类似文件名（以实际版本为准）：
- `ghidra_<version>_PUBLIC_<date>.zip`

## 2) 解压路径约定

把 zip 解压到：
- `F:\dsnpyForClaude\tools\ghidra\`

解压后目录一般长这样：
- `F:\dsnpyForClaude\tools\ghidra\ghidra_<version>_PUBLIC\support\analyzeHeadless.bat`

只要这条 `analyzeHeadless.bat` 存在，DnSpyMcp 就能递归找到它。

## 3) Java 说明

Ghidra Headless 需要 Java。

你当前的版本是 `ghidra_12.0.1_PUBLIC`，它的官方文档明确写了：
- **Ghidra 12.0 最低需要 JDK 21**（Windows 64-bit）。

### JDK 21 下载链接（推荐：Adoptium Temurin 21 LTS）
- 发行页（可自己挑 MSI/ZIP）：https://adoptium.net/temurin/releases/?version=21

如果你想用多线程下载器直接拉“latest”资产，这两条通常最方便：
- ZIP（x64, HotSpot）：https://github.com/adoptium/temurin21-binaries/releases/latest/download/OpenJDK21U-jdk_x64_windows_hotspot.zip
- MSI（x64, HotSpot）：https://github.com/adoptium/temurin21-binaries/releases/latest/download/OpenJDK21U-jdk_x64_windows_hotspot.msi

如果运行 `analyzeHeadless.bat` 时报 Java 相关错误，再处理 Java 环境即可。

### 本项目推荐的落盘位置（免全局环境变量）

把 JDK 21 zip 解压到：
- `F:\dsnpyForClaude\tools\jdk21\`

例如本次实际路径：
- `F:\dsnpyForClaude\tools\jdk21\jdk-21.0.9+10\bin\java.exe`

## 4) 验证（可选）

在 PowerShell 里运行（路径按你的实际版本调整）：
```powershell
F:\dsnpyForClaude\tools\ghidra\ghidra_<version>_PUBLIC\support\analyzeHeadless.bat
```

如果能输出 usage/help（而不是立即报“找不到 java”等），说明 headless 可用。

## 5) 不想改全局环境变量的做法（推荐给 MCP）

DnSpyMcp 的 `il2cpp_native_decompile` 支持传入 `javaHome`：
- 直接传你的 JDK 解压/安装目录（包含 `bin\\java.exe` 的那一层）
- DnSpyMcp 会为子进程临时设置 `JAVA_HOME`，并把 `<javaHome>\\bin` 临时 prepend 到 PATH

这样无需修改系统环境变量，对其它软件也不会产生影响。
