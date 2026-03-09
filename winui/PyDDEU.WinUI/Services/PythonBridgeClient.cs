using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using PyDDEU.WinUI.Models;

namespace PyDDEU.WinUI.Services
{
    public sealed class PythonBridgeClient : IDisposable
    {
        private sealed class PythonInvocation
        {
            public PythonInvocation(string fileName, string argumentsPrefix)
            {
                FileName = fileName;
                ArgumentsPrefix = argumentsPrefix;
            }

            public string FileName { get; }
            public string ArgumentsPrefix { get; }
        }

        private readonly string _repoRoot;
        private PythonInvocation? _selectedInvocation;
        private bool _disposed;

        public PythonBridgeClient()
        {
            _repoRoot = FindRepoRoot(AppContext.BaseDirectory);
        }

        public string RepoRoot
        {
            get { return _repoRoot; }
        }

        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (_selectedInvocation != null)
            {
                return;
            }

            var candidates = BuildInvocations(_repoRoot);
            Exception? lastError = null;
            foreach (var candidate in candidates)
            {
                try
                {
                    var health = await RunHealthAsync(candidate, cancellationToken);
                    var ok = health != null && (health["ok"]?.GetValue<bool>() ?? false);
                    if (!ok)
                    {
                        continue;
                    }

                    _selectedInvocation = candidate;
                    return;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                }
            }

            throw new InvalidOperationException(
                "Python bridge could not be initialized. Ensure .venv Python is available and pyddeu package is importable.",
                lastError
            );
        }

        public async Task<BridgeCommandResult> ExecuteAsync(
            string command,
            JsonObject? payload,
            Func<JsonObject, Task>? onEvent,
            CancellationToken cancellationToken = default
        )
        {
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(command))
            {
                throw new ArgumentException("command is required", nameof(command));
            }

            await InitializeAsync(cancellationToken);
            var invocation = _selectedInvocation!;
            var args = BuildArguments(invocation, "--command " + command);
            var result = new BridgeCommandResult();

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = invocation.FileName,
                    Arguments = args,
                    WorkingDirectory = _repoRoot,
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8,
                },
                EnableRaisingEvents = true,
            };

            var cancellationRegistration = cancellationToken.Register(() =>
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch
                {
                    // ignore
                }
            });

            try
            {
                if (!process.Start())
                {
                    throw new InvalidOperationException("Could not start Python bridge process.");
                }

                if (payload != null)
                {
                    var json = payload.ToJsonString();
                    await process.StandardInput.WriteAsync(json.AsMemory(), cancellationToken);
                }
                process.StandardInput.Close();

                var outputTask = ReadOutputAsync(process, result, onEvent, cancellationToken);
                var errorTask = ReadErrorAsync(process, onEvent, cancellationToken);
                await Task.WhenAll(outputTask, errorTask, process.WaitForExitAsync(cancellationToken));

                result.ExitCode = process.ExitCode;
                if (cancellationToken.IsCancellationRequested)
                {
                    throw new OperationCanceledException(cancellationToken);
                }

                if (result.ExitCode != 0)
                {
                    var message =
                        (result.LastError != null ? result.LastError["message"]?.GetValue<string>() : null)
                        ?? string.Format("Bridge command '{0}' failed with exit code {1}.", command, result.ExitCode);
                    throw new InvalidOperationException(message);
                }

                return result;
            }
            finally
            {
                cancellationRegistration.Dispose();
            }
        }

        private static async Task ReadOutputAsync(
            Process process,
            BridgeCommandResult result,
            Func<JsonObject, Task>? onEvent,
            CancellationToken cancellationToken
        )
        {
            while (true)
            {
                var line = await process.StandardOutput.ReadLineAsync(cancellationToken);
                if (line == null)
                {
                    break;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                JsonObject? obj = null;
                try
                {
                    obj = JsonNode.Parse(line) as JsonObject;
                }
                catch
                {
                    // ignore malformed line
                }

                if (obj == null)
                {
                    continue;
                }

                var type = obj["type"]?.GetValue<string>() ?? string.Empty;
                if (string.Equals(type, "result", StringComparison.OrdinalIgnoreCase))
                {
                    result.Result = obj;
                }
                else if (string.Equals(type, "error", StringComparison.OrdinalIgnoreCase))
                {
                    result.LastError = obj;
                }

                if (onEvent != null)
                {
                    await onEvent(obj);
                }
            }
        }

        private static async Task ReadErrorAsync(
            Process process,
            Func<JsonObject, Task>? onEvent,
            CancellationToken cancellationToken
        )
        {
            while (true)
            {
                var line = await process.StandardError.ReadLineAsync(cancellationToken);
                if (line == null)
                {
                    break;
                }

                if (onEvent == null || string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var evt = new JsonObject
                {
                    ["type"] = "log",
                    ["level"] = "STDERR",
                    ["message"] = line,
                };
                await onEvent(evt);
            }
        }

        private async Task<JsonObject?> RunHealthAsync(
            PythonInvocation invocation,
            CancellationToken cancellationToken
        )
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = invocation.FileName,
                    Arguments = BuildArguments(invocation, "--health"),
                    WorkingDirectory = _repoRoot,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8,
                },
            };

            if (!process.Start())
            {
                throw new InvalidOperationException(string.Format("Could not start '{0}'.", invocation.FileName));
            }

            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            var error = await process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    string.Format(
                        "Health check failed for '{0}'. Exit={1}. {2}",
                        invocation.FileName,
                        process.ExitCode,
                        error
                    )
                );
            }

            var line = output
                .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault();
            if (line == null)
            {
                throw new InvalidOperationException(
                    string.Format("Health output was empty for '{0}'.", invocation.FileName)
                );
            }
            return JsonNode.Parse(line) as JsonObject;
        }

        private static string BuildArguments(PythonInvocation invocation, string bridgeArgs)
        {
            var prefix = string.IsNullOrWhiteSpace(invocation.ArgumentsPrefix)
                ? string.Empty
                : invocation.ArgumentsPrefix + " ";
            return (prefix + "-m pyddeu.winui_bridge " + bridgeArgs).Trim();
        }

        private static List<PythonInvocation> BuildInvocations(string repoRoot)
        {
            var list = new List<PythonInvocation>();
            var venv = Path.Combine(repoRoot, ".venv", "Scripts", "python.exe");
            var venv2 = Path.Combine(repoRoot, "venv", "Scripts", "python.exe");

            if (File.Exists(venv))
            {
                list.Add(new PythonInvocation(venv, string.Empty));
            }
            if (File.Exists(venv2))
            {
                list.Add(new PythonInvocation(venv2, string.Empty));
            }

            list.Add(new PythonInvocation("py", "-3.11"));
            list.Add(new PythonInvocation("py", "-3"));
            list.Add(new PythonInvocation("python", string.Empty));
            return list;
        }

        private static string FindRepoRoot(string startDirectory)
        {
            // First check: config file next to exe pointing to repo root
            var configPath = Path.Combine(startDirectory, "pyddeu_repo.txt");
            if (File.Exists(configPath))
            {
                var configured = File.ReadAllText(configPath).Trim();
                if (Directory.Exists(configured) && Directory.Exists(Path.Combine(configured, "pyddeu")))
                {
                    return configured;
                }
            }

            // Walk up from exe directory
            var dir = new DirectoryInfo(startDirectory);
            while (dir != null)
            {
                var pyproject = Path.Combine(dir.FullName, "pyproject.toml");
                var pyddeuDir = Path.Combine(dir.FullName, "pyddeu");
                if (File.Exists(pyproject) && Directory.Exists(pyddeuDir))
                {
                    return dir.FullName;
                }
                dir = dir.Parent;
            }

            // Fallback: check current working directory
            var cwd = Directory.GetCurrentDirectory();
            if (Directory.Exists(Path.Combine(cwd, "pyddeu")))
            {
                return cwd;
            }

            return startDirectory;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(PythonBridgeClient));
            }
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }
}
