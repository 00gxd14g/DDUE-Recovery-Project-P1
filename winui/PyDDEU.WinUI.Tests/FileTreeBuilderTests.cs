using PyDDEU.WinUI.Models;
using PyDDEU.WinUI.Services;

namespace PyDDEU.WinUI.Tests;

[TestClass]
public class FileTreeBuilderTests
{
    [TestMethod]
    public void Build_CreatesFolderHierarchyFromDisplayPath()
    {
        var files = new[]
        {
            new FileEntryModel
            {
                DisplayPath = "Users/Alice/Documents/report.docx",
                Path = "Users/Alice/Documents/report.docx",
                Size = 12,
                Inode = 1,
            },
        };

        var roots = FileTreeBuilder.Build(files);

        Assert.HasCount(1, roots);
        Assert.AreEqual("Users", roots[0].Name);
        Assert.IsTrue(roots[0].IsFolder);
        Assert.AreEqual("Alice", roots[0].Children[0].Name);
        Assert.AreEqual("Documents", roots[0].Children[0].Children[0].Name);
        Assert.AreEqual("report.docx", roots[0].Children[0].Children[0].Children[0].Name);
        Assert.IsFalse(roots[0].Children[0].Children[0].Children[0].IsFolder);
    }

    [TestMethod]
    public void EnumerateFiles_ReturnsAllDescendantsForFolderNode()
    {
        var files = new[]
        {
            new FileEntryModel
            {
                DisplayPath = "Users/Alice/a.txt",
                Path = "Users/Alice/a.txt",
                Size = 1,
                Inode = 1,
            },
            new FileEntryModel
            {
                DisplayPath = "Users/Alice/b.txt",
                Path = "Users/Alice/b.txt",
                Size = 2,
                Inode = 2,
            },
        };

        var roots = FileTreeBuilder.Build(files);
        var descendants = FileTreeBuilder.EnumerateFiles(roots[0]).ToList();

        Assert.HasCount(2, descendants);
        CollectionAssert.AreEquivalent(
            new[] { "a.txt", "b.txt" },
            descendants.Select(file => file.FileName).ToArray()
        );
    }
}
