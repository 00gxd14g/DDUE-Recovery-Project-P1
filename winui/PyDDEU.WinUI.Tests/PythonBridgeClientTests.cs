using System.Collections;
using System.Reflection;
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

    private static object CreateInvocation(string fileName, string argumentsPrefix)
    {
        return Activator.CreateInstance(InvocationType, fileName, argumentsPrefix)
            ?? throw new InvalidOperationException("Could not create PythonInvocation.");
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
}
