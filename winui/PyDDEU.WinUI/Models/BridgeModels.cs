using System.Collections.ObjectModel;
using System.Text.Json.Nodes;

namespace PyDDEU.WinUI.Models
{
    internal static class UiFormat
    {
        public static string FormatBytes(long bytes)
        {
            if (bytes < 0)
            {
                return "0 B";
            }

            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double value = bytes;
            int i = 0;
            while (value >= 1024 && i < units.Length - 1)
            {
                value /= 1024d;
                i++;
            }

            return string.Format("{0:F2} {1}", value, units[i]);
        }
    }

    public sealed class DiskInfoModel
    {
        public string Path { get; set; } = string.Empty;
        public long Size { get; set; }
        public string Description { get; set; } = string.Empty;

        public double SizeGb
        {
            get { return Size <= 0 ? 0 : (double)Size / (1024d * 1024d * 1024d); }
        }

        public string DisplayText
        {
            get { return string.Format("{0} ({1}) {2}", Path, UiFormat.FormatBytes(Size), Description).Trim(); }
        }
    }

    public sealed class PartitionInfoModel
    {
        public int Index { get; set; }
        public long StartOffset { get; set; }
        public long Length { get; set; }
        public string Scheme { get; set; } = string.Empty;
        public string TypeStr { get; set; } = string.Empty;
        public string Filesystem { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;

        public double SizeGb
        {
            get { return Length <= 0 ? 0 : (double)Length / (1024d * 1024d * 1024d); }
        }

        public long LbaStart
        {
            get { return StartOffset >= 0 ? StartOffset / 512 : 0; }
        }

        public long LbaEnd
        {
            get { return Length > 0 ? ((StartOffset + Length) / 512) - 1 : LbaStart; }
        }

        public string DisplayText
        {
            get
            {
                var label = string.Format(
                    "[{0}] {1} {2} LBA={3}..{4} start={5} size={6:F2}GB",
                    Index,
                    Scheme,
                    TypeStr,
                    LbaStart,
                    LbaEnd,
                    StartOffset,
                    SizeGb
                );
                if (!string.IsNullOrWhiteSpace(Name))
                {
                    label += " name=" + Name;
                }
                if (!string.IsNullOrWhiteSpace(Filesystem) && !label.Contains(Filesystem, StringComparison.OrdinalIgnoreCase))
                {
                    label += " fs=" + Filesystem;
                }
                return label;
            }
        }

        public string SizeText
        {
            get { return UiFormat.FormatBytes(Length); }
        }
    }

    public sealed class FileEntryModel
    {
        public string Path { get; set; } = string.Empty;
        public string DisplayPath { get; set; } = string.Empty;
        public long Size { get; set; }
        public string Status { get; set; } = string.Empty;
        public long Inode { get; set; }
        public long PartOffset { get; set; }
        public bool IsDir { get; set; }
        public string? ResidentDataB64 { get; set; }
        public JsonArray? DataRuns { get; set; }
        public long? DataSize { get; set; }
        public int? ClusterSize { get; set; }
        public string Source { get; set; } = string.Empty;
        public string NameSource { get; set; } = string.Empty;
        public string DedupeKey { get; set; } = string.Empty;

        public string FileName
        {
            get
            {
                var rawPath = string.IsNullOrWhiteSpace(DisplayPath) ? Path : DisplayPath;
                var p = (rawPath ?? "").Replace('\\', '/');
                var idx = p.LastIndexOf('/');
                return idx >= 0 ? p.Substring(idx + 1) : p;
            }
        }

        public string SizeText
        {
            get { return UiFormat.FormatBytes(Size); }
        }

        public string StatusBadge
        {
            get
            {
                var s = Status ?? "";
                var src = Source ?? "";
                if (!string.IsNullOrEmpty(src) && src != "pytsk3")
                {
                    return string.Format("{0} [{1}]", s, src.ToUpperInvariant());
                }
                return s;
            }
        }

        public override string ToString()
        {
            return FileName;
        }
    }

    /// <summary>
    /// Represents a folder node in the file tree hierarchy.
    /// </summary>
    public sealed class FolderNodeInfo
    {
        public string Name { get; set; } = string.Empty;
        public string FullPath { get; set; } = string.Empty;
        public int FileCount { get; set; }
        public int FolderCount { get; set; }

        public string DisplayText
        {
            get { return Name; }
        }

        public string MetaText
        {
            get
            {
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

        public override string ToString()
        {
            return DisplayText;
        }
    }

    public sealed class LogEntryModel
    {
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string Level { get; set; } = "INFO";
        public string Message { get; set; } = string.Empty;

        public string DisplayText
        {
            get { return string.Format("[{0:HH:mm:ss}] [{1}] {2}", Timestamp, Level, Message); }
        }
    }

    public sealed class BridgeCommandResult
    {
        public int ExitCode { get; set; }
        public JsonObject? Result { get; set; }
        public JsonObject? LastError { get; set; }
    }
}
