using System.Reflection;
using System.Text.Json.Nodes;
using PyDDEU.WinUI.ViewModels;

namespace PyDDEU.WinUI.Tests;

[TestClass]
public class MainPageViewModelTests
{
    [TestMethod]
    public void UpdateFiles_KeepsDistinctEntriesWithSameInodeWhenDedupeKeysDiffer()
    {
        var viewModel = CreateViewModel();
        var payload = new JsonArray
        {
            new JsonObject
            {
                ["display_path"] = "Users/Alice/report.docx",
                ["path"] = "Users/Alice/report.docx",
                ["dedupe_key"] = "pytsk3|4096|42|users/alice/report.docx",
                ["source"] = "pytsk3",
                ["part_offset"] = 4096,
                ["inode"] = 42,
                ["status"] = "ACTIVE",
                ["size"] = 10,
                ["is_dir"] = false,
            },
            new JsonObject
            {
                ["display_path"] = "Users/Alice/report-copy.docx",
                ["path"] = "Users/Alice/report-copy.docx",
                ["dedupe_key"] = "pytsk3|4096|42|users/alice/report-copy.docx",
                ["source"] = "pytsk3",
                ["part_offset"] = 4096,
                ["inode"] = 42,
                ["status"] = "ACTIVE",
                ["size"] = 10,
                ["is_dir"] = false,
            },
        };

        InvokePrivateInstance(viewModel, "UpdateFiles", payload);

        Assert.HasCount(2, viewModel.Files);
        CollectionAssert.AreEqual(
            new[] { "Users/Alice/report.docx", "Users/Alice/report-copy.docx" },
            viewModel.Files.Select(file => file.DisplayPath).ToArray()
        );
    }

    [TestMethod]
    public void UpdateFiles_DropsExactDuplicateDedupeKey()
    {
        var viewModel = CreateViewModel();
        var payload = new JsonArray
        {
            new JsonObject
            {
                ["display_path"] = "Users/Alice/report.docx",
                ["path"] = "Users/Alice/report.docx",
                ["dedupe_key"] = "pytsk3|4096|42|users/alice/report.docx",
                ["source"] = "pytsk3",
                ["part_offset"] = 4096,
                ["inode"] = 42,
                ["status"] = "ACTIVE",
                ["size"] = 10,
                ["is_dir"] = false,
            },
            new JsonObject
            {
                ["display_path"] = "Users/Alice/report.docx",
                ["path"] = "Users/Alice/report.docx",
                ["dedupe_key"] = "pytsk3|4096|42|users/alice/report.docx",
                ["source"] = "pytsk3",
                ["part_offset"] = 4096,
                ["inode"] = 42,
                ["status"] = "ACTIVE",
                ["size"] = 10,
                ["is_dir"] = false,
            },
        };

        InvokePrivateInstance(viewModel, "UpdateFiles", payload);

        Assert.HasCount(1, viewModel.Files);
    }

    [TestMethod]
    public void ParseExtensions_TrimsDotsWhitespaceAndDuplicates()
    {
        var filters = InvokePrivateStatic<HashSet<string>>(
            typeof(MainPageViewModel),
            "ParseExtensions",
            " .jpg,PDF, jpg , .zip "
        );

        CollectionAssert.AreEquivalent(
            new[] { "jpg", "pdf", "zip" },
            filters.ToArray()
        );
    }

    [TestMethod]
    public void FileEntryModel_FileNamePrefersDisplayPath()
    {
        var file = new Models.FileEntryModel
        {
            Path = "wrong/path.bin",
            DisplayPath = "Users/Alice/report.docx",
        };

        Assert.AreEqual("report.docx", file.FileName);
    }

    private static MainPageViewModel CreateViewModel()
    {
        return new MainPageViewModel(null!);
    }

    private static void InvokePrivateInstance(object target, string methodName, params object?[] args)
    {
        var method = target.GetType().GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException($"Method '{methodName}' was not found.");
        _ = method.Invoke(target, args);
    }

    private static T InvokePrivateStatic<T>(Type type, string methodName, params object?[] args)
    {
        var method = type.GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException($"Method '{methodName}' was not found.");
        return (T)(method.Invoke(null, args)
            ?? throw new InvalidOperationException($"Method '{methodName}' returned null."));
    }
}
