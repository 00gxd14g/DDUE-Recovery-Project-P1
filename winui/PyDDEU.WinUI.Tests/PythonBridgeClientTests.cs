using System.Collections;
using System.Reflection;
using System.Text.Json.Nodes;
using PyDDEU.WinUI.Services;

namespace PyDDEU.WinUI.Tests;

[TestClass]
public class PythonBridgeClientTests
{
    private static readonly Type InvocationType =
        typeof(PythonBridgeClient).GetNestedType("PythonInvocation", BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("PythonInvocation nested type was not found.");

    [TestMethod]
    public void BuildArguments_AppendsPrefixBeforeBridgeArgs()
    {
        var invocation = CreateInvocation("py", "-3.11");

        var args = InvokePrivateStatic<string>("BuildArguments", invocation, "--health");

        Assert.AreEqual("-3.11 -m pyddeu.winui_bridge --health", args);
    }

    [TestMethod]
    public void BuildInvocations_IncludesRepoVirtualEnvsBeforeFallbacks()
    {
        var repoRoot = CreateTempDirectory();
        try
        {
            var dotVenv = Path.Combine(repoRoot, ".venv", "Scripts");
            var plainVenv = Path.Combine(repoRoot, "venv", "Scripts");
            Directory.CreateDirectory(dotVenv);
            Directory.CreateDirectory(plainVenv);
            File.WriteAllText(Path.Combine(dotVenv, "python.exe"), string.Empty);
            File.WriteAllText(Path.Combine(plainVenv, "python.exe"), string.Empty);

            var invocations = ((IEnumerable)InvokePrivateStatic<object>("BuildInvocations", repoRoot))
                .Cast<object>()
                .ToList();

            CollectionAssert.AreEqual(
                new[]
                {
                    Path.Combine(dotVenv, "python.exe"),
                    Path.Combine(plainVenv, "python.exe"),
                    "py",
                    "py",
                    "python",
                },
                invocations.Select(GetFileName).ToArray()
            );
        }
        finally
        {
            Directory.Delete(repoRoot, recursive: true);
        }
    }

    [TestMethod]
    public void FindRepoRoot_UsesConfiguredMarkerDirectory()
    {
        var configuredRoot = CreateTempDirectory();
        var startDirectory = CreateTempDirectory();

        try
        {
            Directory.CreateDirectory(Path.Combine(configuredRoot, "pyddeu"));
            File.WriteAllText(Path.Combine(startDirectory, "pyddeu_repo.txt"), configuredRoot);

            var repoRoot = InvokePrivateStatic<string>("FindRepoRoot", startDirectory);

            Assert.AreEqual(configuredRoot, repoRoot);
        }
        finally
        {
            Directory.Delete(configuredRoot, recursive: true);
            Directory.Delete(startDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task ExecuteAsync_ParsesEventsAndResult()
    {
        using var repo = FakeBridgeRepo.Create();
        using var client = CreateTestClient(repo.RootPath);
        var events = new List<JsonObject>();

        var result = await client.ExecuteAsync(
            "demo",
            new JsonObject { ["message"] = "hello" },
            evt =>
            {
                events.Add(evt);
                return Task.CompletedTask;
            }
        );

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsNotNull(result.Result);
        Assert.AreEqual("result", result.Result["type"]?.GetValue<string>());
        Assert.AreEqual("hello", result.Result["echo"]?.GetValue<string>());
        Assert.HasCount(3, events);
        Assert.AreEqual("log", events[0]["type"]?.GetValue<string>());
        Assert.AreEqual("status", events[1]["type"]?.GetValue<string>());
        Assert.AreEqual("result", events[2]["type"]?.GetValue<string>());
    }

    [TestMethod]
    public async Task ExecuteAsync_ForwardsStderrAsLogEvent()
    {
        using var repo = FakeBridgeRepo.Create();
        using var client = CreateTestClient(repo.RootPath);
        var events = new List<JsonObject>();

        var result = await client.ExecuteAsync(
            "stderr",
            new JsonObject(),
            evt =>
            {
                events.Add(evt);
                return Task.CompletedTask;
            }
        );

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsTrue(events.Any(evt =>
            evt["type"]?.GetValue<string>() == "log"
            && evt["level"]?.GetValue<string>() == "STDERR"
            && evt["message"]?.GetValue<string>() == "bridge stderr line"));
    }

    [TestMethod]
    public async Task ExecuteAsync_ThrowsBridgeMessageOnError()
    {
        using var repo = FakeBridgeRepo.Create();
        using var client = CreateTestClient(repo.RootPath);

        var ex = await ExpectExceptionAsync<InvalidOperationException>(() =>
            client.ExecuteAsync("fail", new JsonObject(), _ => Task.CompletedTask));

        Assert.AreEqual("simulated failure", ex.Message);
    }

    [TestMethod]
    public async Task ExecuteAsync_HonorsCancellation()
    {
        using var repo = FakeBridgeRepo.Create();
        using var client = CreateTestClient(repo.RootPath);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        await ExpectExceptionAsync<OperationCanceledException>(() =>
            client.ExecuteAsync("sleep", new JsonObject(), _ => Task.CompletedTask, cts.Token));
    }

    private static object CreateInvocation(string fileName, string argumentsPrefix)
    {
        return Activator.CreateInstance(InvocationType, fileName, argumentsPrefix)
            ?? throw new InvalidOperationException("Could not create PythonInvocation.");
    }

    private static PythonBridgeClient CreateTestClient(string repoRoot)
    {
        var pythonPath = FindRepoPython();
        var method = typeof(PythonBridgeClient).GetMethod("CreateForTesting", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("CreateForTesting method was not found.");
        return (PythonBridgeClient)(method.Invoke(null, new object?[] { repoRoot, pythonPath, string.Empty })
            ?? throw new InvalidOperationException("CreateForTesting returned null."));
    }

    private static string GetFileName(object invocation)
    {
        var property = InvocationType.GetProperty("FileName", BindingFlags.Instance | BindingFlags.Public)
            ?? throw new InvalidOperationException("FileName property not found.");
        return (string)(property.GetValue(invocation)
            ?? throw new InvalidOperationException("FileName was null."));
    }

    private static T InvokePrivateStatic<T>(string methodName, params object?[] args)
    {
        var method = typeof(PythonBridgeClient).GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException($"Method '{methodName}' was not found.");
        return (T)(method.Invoke(null, args)
            ?? throw new InvalidOperationException($"Method '{methodName}' returned null."));
    }

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "pyddeu-winui-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static string FindRepoPython()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, ".venv", "Scripts", "python.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
            dir = dir.Parent;
        }

        throw new AssertInconclusiveException("Repo .venv python.exe was not found.");
    }

    private static async Task<TException> ExpectExceptionAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException ex)
        {
            return ex;
        }

        throw new AssertFailedException($"Expected exception of type {typeof(TException).Name} was not thrown.");
    }

    private sealed class FakeBridgeRepo : IDisposable
    {
        private const string BridgeScript = """
import argparse
import json
import sys
import time

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--command", default="")
    args = parser.parse_args()

    if args.health:
        emit({"type": "health", "ok": True, "details": {"python": sys.executable}})
        return 0

    raw = sys.stdin.read()
    payload = json.loads(raw) if raw.strip() else {}

    if args.command == "demo":
        emit({"type": "log", "level": "INFO", "message": "demo-start"})
        emit({"type": "status", "operation": "demo", "message": payload.get("message", "")})
        emit({"type": "result", "command": "demo", "echo": payload.get("message", "")})
        return 0

    if args.command == "stderr":
        print("bridge stderr line", file=sys.stderr, flush=True)
        emit({"type": "result", "command": "stderr", "ok": True})
        return 0

    if args.command == "fail":
        emit({"type": "error", "code": "bridge_error", "message": "simulated failure"})
        return 1

    if args.command == "sleep":
        time.sleep(30)
        emit({"type": "result", "command": "sleep", "ok": True})
        return 0

    emit({"type": "error", "code": "unknown_command", "message": args.command})
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
""";

        private FakeBridgeRepo(string rootPath)
        {
            RootPath = rootPath;
        }

        public string RootPath { get; }

        public static FakeBridgeRepo Create()
        {
            var rootPath = CreateTempDirectory();
            Directory.CreateDirectory(Path.Combine(rootPath, "pyddeu"));
            File.WriteAllText(Path.Combine(rootPath, "pyddeu", "__init__.py"), string.Empty);
            File.WriteAllText(Path.Combine(rootPath, "pyddeu", "winui_bridge.py"), BridgeScript);
            return new FakeBridgeRepo(rootPath);
        }

        public void Dispose()
        {
            Directory.Delete(RootPath, recursive: true);
        }
    }
}
