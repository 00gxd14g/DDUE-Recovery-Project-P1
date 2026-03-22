using System.Collections.Generic;
using System.Linq;

namespace PyDDEU.WinUI.Models
{
    public sealed class FileTreeNodeModel
    {
        public string Key { get; init; } = string.Empty;
        public string Name { get; init; } = string.Empty;
        public string FullPath { get; init; } = string.Empty;
        public bool IsFolder { get; init; }
        public FileEntryModel? File { get; init; }
        public IReadOnlyList<FileTreeNodeModel> Children { get; init; } = Array.Empty<FileTreeNodeModel>();
        public int FolderCount { get; init; }
        public int FileCount { get; init; }

        public string MetaText
        {
            get
            {
                if (!IsFolder)
                {
                    return File?.SizeText ?? string.Empty;
                }

                var parts = new List<string>();
                if (FolderCount > 0)
                {
                    parts.Add(string.Format("{0} folder(s)", FolderCount));
                }
                if (FileCount > 0)
                {
                    parts.Add(string.Format("{0} file(s)", FileCount));
                }
                return string.Join(", ", parts);
            }
        }

        public string StatusBadge
        {
            get { return File?.StatusBadge ?? string.Empty; }
        }

        public string SizeText
        {
            get { return File?.SizeText ?? string.Empty; }
        }

        public string DisplayName
        {
            get { return File?.FileName ?? Name; }
        }
    }
}

namespace PyDDEU.WinUI.Services
{
    using PyDDEU.WinUI.Models;

    public static class FileTreeBuilder
    {
        private sealed class MutableNode
        {
            public string Name { get; init; } = string.Empty;
            public string FullPath { get; init; } = string.Empty;
            public bool IsFolder { get; set; }
            public FileEntryModel? File { get; set; }
            public Dictionary<string, MutableNode> Children { get; } = new(StringComparer.OrdinalIgnoreCase);
        }

        public static IReadOnlyList<FileTreeNodeModel> Build(IEnumerable<FileEntryModel> files)
        {
            var roots = new Dictionary<string, MutableNode>(StringComparer.OrdinalIgnoreCase);

            foreach (var file in files ?? Array.Empty<FileEntryModel>())
            {
                var path = NormalizePath(file);
                var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0)
                {
                    continue;
                }

                Dictionary<string, MutableNode> currentMap = roots;
                MutableNode? currentNode = null;

                for (int index = 0; index < parts.Length; index++)
                {
                    var part = parts[index];
                    var fullPath = index == 0 ? part : string.Format("{0}/{1}", currentNode!.FullPath, part);
                    if (!currentMap.TryGetValue(part, out var node))
                    {
                        node = new MutableNode
                        {
                            Name = part,
                            FullPath = fullPath,
                            IsFolder = true,
                        };
                        currentMap[part] = node;
                    }

                    currentNode = node;
                    if (index == parts.Length - 1)
                    {
                        if (file.IsDir)
                        {
                            currentNode.IsFolder = true;
                        }
                        else
                        {
                            currentNode.IsFolder = false;
                            currentNode.File = file;
                        }
                    }
                    currentMap = currentNode.Children;
                }
            }

            return roots.Values
                .OrderBy(node => node.Name, StringComparer.OrdinalIgnoreCase)
                .Select(ToModel)
                .ToList();
        }

        public static IEnumerable<FileEntryModel> EnumerateFiles(FileTreeNodeModel node)
        {
            if (node.File != null)
            {
                yield return node.File;
            }

            foreach (var child in node.Children)
            {
                foreach (var file in EnumerateFiles(child))
                {
                    yield return file;
                }
            }
        }

        private static FileTreeNodeModel ToModel(MutableNode node)
        {
            var children = node.Children.Values
                .OrderBy(child => child.IsFolder ? 0 : 1)
                .ThenBy(child => child.Name, StringComparer.OrdinalIgnoreCase)
                .Select(ToModel)
                .ToList();

            return new FileTreeNodeModel
            {
                Key = node.FullPath,
                Name = node.Name,
                FullPath = node.FullPath,
                IsFolder = node.IsFolder,
                File = node.File,
                Children = children,
                FolderCount = children.Count(child => child.IsFolder),
                FileCount = children.Count(child => !child.IsFolder),
            };
        }

        private static string NormalizePath(FileEntryModel file)
        {
            var path = (string.IsNullOrWhiteSpace(file.DisplayPath) ? file.Path : file.DisplayPath)
                .Replace('\\', '/')
                .Trim('/');
            if (!string.IsNullOrWhiteSpace(path))
            {
                return path;
            }

            return file.Inode > 0
                ? string.Format("inode_{0}", file.Inode)
                : "unknown";
        }
    }
}
