using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;
using PyDDEU.WinUI.Models;
using PyDDEU.WinUI.Services;

namespace PyDDEU.WinUI.ViewModels
{
    public sealed class MainPageViewModel : INotifyPropertyChanged, IDisposable
    {
        private readonly PythonBridgeClient _bridge = new();
        private readonly DispatcherQueue _dispatcherQueue;
        private readonly ObservableCollection<DiskInfoModel> _disks = new();
        private readonly ObservableCollection<PartitionInfoModel> _partitions = new();
        private readonly ObservableCollection<FileEntryModel> _files = new();
        private readonly ObservableCollection<LogEntryModel> _logs = new();

        private CancellationTokenSource? _activeCommandCts;
        private DiskInfoModel? _selectedDisk;
        private PartitionInfoModel? _selectedPartition;
        private bool _initialized;
        private bool _disposed;
        private bool _isBusy;
        private string _sourcePath = string.Empty;
        private string _outputPath = GetDefaultOutputPath();
        private bool _includeDeleted = true;
        private bool _includeActive = true;
        private bool _aggressivePartitionScan;
        private bool _imageSelectedPartitionOnly = true;
        private double _maxRecords = 50000;
        private string _exportExtensions = string.Empty;
        private string _statusText = "Ready";
        private double _progressValue;
        private bool _isProgressIndeterminate;
        private string _progressText = "0%";

        public MainPageViewModel(DispatcherQueue dispatcherQueue)
        {
            _dispatcherQueue = dispatcherQueue;
            _disks.CollectionChanged += (_, _) => OnPropertyChanged(nameof(DiskCount));
            _partitions.CollectionChanged += (_, _) => OnPropertyChanged(nameof(PartitionCount));
            _files.CollectionChanged += (_, _) => OnPropertyChanged(nameof(FileCount));
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action? LogAdded;
        public event Action? FilesUpdated;

        public ObservableCollection<DiskInfoModel> Disks
        {
            get { return _disks; }
        }

        public ObservableCollection<PartitionInfoModel> Partitions
        {
            get { return _partitions; }
        }

        public ObservableCollection<FileEntryModel> Files
        {
            get { return _files; }
        }

        public ObservableCollection<LogEntryModel> Logs
        {
            get { return _logs; }
        }

        public bool IsBusy
        {
            get { return _isBusy; }
            private set
            {
                if (!SetProperty(ref _isBusy, value))
                {
                    return;
                }

                OnPropertyChanged(nameof(CommandsEnabled));
                OnPropertyChanged(nameof(CanStop));
            }
        }

        public bool CommandsEnabled
        {
            get { return !IsBusy; }
        }

        public bool CanStop
        {
            get { return IsBusy; }
        }

        public int DiskCount
        {
            get { return _disks.Count; }
        }

        public int PartitionCount
        {
            get { return _partitions.Count; }
        }

        public int FileCount
        {
            get { return _files.Count; }
        }

        public bool IsAdmin
        {
            get
            {
                try
                {
                    using var identity = WindowsIdentity.GetCurrent();
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
                catch
                {
                    return false;
                }
            }
        }

        public string SourcePath
        {
            get { return _sourcePath; }
            set { SetProperty(ref _sourcePath, value); }
        }

        public string OutputPath
        {
            get { return _outputPath; }
            set { SetProperty(ref _outputPath, value); }
        }

        public bool IncludeDeleted
        {
            get { return _includeDeleted; }
            set { SetProperty(ref _includeDeleted, value); }
        }

        public bool IncludeActive
        {
            get { return _includeActive; }
            set { SetProperty(ref _includeActive, value); }
        }

        public bool AggressivePartitionScan
        {
            get { return _aggressivePartitionScan; }
            set { SetProperty(ref _aggressivePartitionScan, value); }
        }

        public bool ImageSelectedPartitionOnly
        {
            get { return _imageSelectedPartitionOnly; }
            set { SetProperty(ref _imageSelectedPartitionOnly, value); }
        }

        public double MaxRecords
        {
            get { return _maxRecords; }
            set { SetProperty(ref _maxRecords, value); }
        }

        public string ExportExtensions
        {
            get { return _exportExtensions; }
            set { SetProperty(ref _exportExtensions, value); }
        }

        public string StatusText
        {
            get { return _statusText; }
            set { SetProperty(ref _statusText, value); }
        }

        public double ProgressValue
        {
            get { return _progressValue; }
            set { SetProperty(ref _progressValue, value); }
        }

        public bool IsProgressIndeterminate
        {
            get { return _isProgressIndeterminate; }
            set { SetProperty(ref _isProgressIndeterminate, value); }
        }

        public string ProgressText
        {
            get { return _progressText; }
            set { SetProperty(ref _progressText, value); }
        }

        public async Task InitializeAsync()
        {
            if (_initialized)
            {
                return;
            }

            _initialized = true;
            AddLog("INFO", "Initializing bridge...");
            try
            {
                await _bridge.InitializeAsync();
                AddLog("INFO", "Bridge initialized.");
                await ListDisksAsync();
            }
            catch (Exception ex)
            {
                AddLog("ERROR", "Initialization failed: " + ex.Message);
                StatusText = "Bridge initialization failed.";
                IsProgressIndeterminate = false;
                ProgressText = "0%";
                ProgressValue = 0;
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            RequestStop();
            _bridge.Dispose();
            _disposed = true;
        }

        public DiskInfoModel? SelectedDisk
        {
            get { return _selectedDisk; }
            set
            {
                if (!SetProperty(ref _selectedDisk, value))
                {
                    return;
                }

                if (_selectedDisk != null)
                {
                    SourcePath = _selectedDisk.Path;
                }
            }
        }

        public PartitionInfoModel? SelectedPartition
        {
            get { return _selectedPartition; }
            set
            {
                if (!SetProperty(ref _selectedPartition, value))
                {
                    return;
                }

                if (_selectedPartition != null)
                {
                    AddLog("INFO", "Selected partition index=" + _selectedPartition.Index);
                }
            }
        }

        public void SetSelectedDisk(DiskInfoModel? disk)
        {
            SelectedDisk = disk;
        }

        public void SetSelectedPartition(PartitionInfoModel? part)
        {
            SelectedPartition = part;
        }

        public void RequestStop()
        {
            if (_activeCommandCts == null || _activeCommandCts.IsCancellationRequested)
            {
                return;
            }

            AddLog("WARNING", "Stop requested.");
            _activeCommandCts.Cancel();
        }

        public void ClearLogs()
        {
            Logs.Clear();
            AddLog("INFO", "Logs cleared.");
        }

        public async Task ListDisksAsync()
        {
            await RunCommandAsync(
                "Listing disks...",
                async token =>
                {
                    var result = await _bridge.ExecuteAsync(
                        "list_disks",
                        new JsonObject(),
                        OnBridgeEventAsync,
                        token
                    );

                    var disks = result.Result?["disks"] as JsonArray;
                    Disks.Clear();
                    if (disks != null)
                    {
                        foreach (var node in disks)
                        {
                            var o = node as JsonObject;
                            if (o == null)
                            {
                                continue;
                            }

                            Disks.Add(
                                new DiskInfoModel
                                {
                                    Path = ReadString(o, "path"),
                                    Size = ReadLong(o, "size"),
                                    Description = ReadString(o, "description"),
                                }
                            );
                        }
                    }

                    if (Disks.Count > 0)
                    {
                        SetSelectedDisk(Disks[0]);
                    }

                    StatusText = string.Format("{0} disk(s) listed.", Disks.Count);
                    IsProgressIndeterminate = false;
                    ProgressValue = 100;
                    ProgressText = "100%";
                    AddLog("INFO", StatusText);
                }
            );
        }

        public async Task ScanPartitionsAsync()
        {
            await RunCommandAsync(
                "Scanning partitions...",
                async token =>
                {
                    var source = RequireSourcePath();
                    var payload = new JsonObject
                    {
                        ["source_path"] = source,
                        ["aggressive"] = AggressivePartitionScan,
                    };

                    var result = await _bridge.ExecuteAsync("scan_partitions", payload, OnBridgeEventAsync, token);
                    var partitions = result.Result?["partitions"] as JsonArray;
                    Partitions.Clear();
                    if (partitions != null)
                    {
                        foreach (var node in partitions)
                        {
                            var o = node as JsonObject;
                            if (o == null)
                            {
                                continue;
                            }

                            Partitions.Add(
                                new PartitionInfoModel
                                {
                                    Index = ReadInt(o, "index"),
                                    StartOffset = ReadLong(o, "start_offset"),
                                    Length = ReadLong(o, "length"),
                                    Scheme = ReadString(o, "scheme"),
                                    TypeStr = ReadString(o, "type_str"),
                                    Name = ReadString(o, "name"),
                                }
                            );
                        }
                    }

                    if (Partitions.Count > 0)
                    {
                        SetSelectedPartition(Partitions[0]);
                    }
                    else
                    {
                        _selectedPartition = null;
                    }

                    StatusText = string.Format("{0} partition(s) found.", Partitions.Count);
                    IsProgressIndeterminate = false;
                    ProgressValue = 100;
                    ProgressText = "100%";
                    AddLog("INFO", StatusText);
                }
            );
        }

        public async Task DeepScanAsync()
        {
            await RunCommandAsync(
                "Running deep NTFS scan...",
                async token =>
                {
                    var source = RequireSourcePath();
                    if (_selectedPartition == null)
                    {
                        throw new InvalidOperationException("Select a partition first.");
                    }

                    var payload = new JsonObject
                    {
                        ["source_path"] = source,
                        ["partition_start"] = _selectedPartition.StartOffset,
                        ["partition_length"] = _selectedPartition.Length,
                        ["include_deleted"] = IncludeDeleted,
                        ["include_active"] = IncludeActive,
                        ["max_records"] = (int)Math.Clamp(MaxRecords, 100, 500000),
                        ["max_resident_bytes"] = 1024 * 1024,
                    };

                    var result = await _bridge.ExecuteAsync("deep_scan", payload, OnBridgeEventAsync, token);
                    UpdateFiles(result.Result?["files"] as JsonArray);
                    StatusText = string.Format("Deep scan completed. {0} file(s) listed.", Files.Count);
                    IsProgressIndeterminate = false;
                    ProgressValue = 100;
                    ProgressText = "100%";
                    AddLog("INFO", StatusText);
                }
            );
        }

        public async Task ParseFilesystemAsync()
        {
            await RunCommandAsync(
                "Parsing filesystem...",
                async token =>
                {
                    var source = RequireSourcePath();
                    if (_selectedPartition == null)
                    {
                        throw new InvalidOperationException("Select a partition first.");
                    }

                    var payload = new JsonObject
                    {
                        ["source_path"] = source,
                        ["partition_start"] = _selectedPartition.StartOffset,
                        ["partition_length"] = _selectedPartition.Length,
                        ["max_entries"] = (int)Math.Clamp(MaxRecords, 100, 500000),
                    };

                    var result = await _bridge.ExecuteAsync("parse_fs", payload, OnBridgeEventAsync, token);
                    UpdateFiles(result.Result?["files"] as JsonArray);
                    StatusText = string.Format("Filesystem parsed. {0} file(s).", Files.Count);
                    IsProgressIndeterminate = false;
                    ProgressValue = 100;
                    ProgressText = "100%";
                    AddLog("INFO", StatusText);
                }
            );
        }

        public async Task RecoverAllAsync()
        {
            var allFiles = Files.ToList();
            await RecoverSelectedAsync(allFiles);
        }

        public async Task ExportAllAsync()
        {
            if (!IncludeDeleted && !IncludeActive)
            {
                StatusText = "Export filter is invalid.";
                AddLog("ERROR", "Select at least one of Include Deleted or Include Active.");
                return;
            }

            var filtered = Files
                .Where(file => !file.IsDir)
                .Where(file => IncludeDeleted || !string.Equals(file.Status, "DELETED", StringComparison.OrdinalIgnoreCase))
                .Where(file => IncludeActive || !string.Equals(file.Status, "ACTIVE", StringComparison.OrdinalIgnoreCase))
                .Where(file => IsExportExtensionAllowed(file))
                .ToList();

            if (filtered.Count == 0)
            {
                StatusText = "No files matched export filters.";
                AddLog("WARNING", "No files match the current export filters.");
                return;
            }

            await RecoverItemsAsync(filtered, "Exporting filtered files...", "Export completed");
        }

        public async Task MftScanAsync()
        {
            await RunCommandAsync(
                "Running MFT raw scan...",
                async token =>
                {
                    var source = RequireSourcePath();
                    var payload = new JsonObject
                    {
                        ["source_path"] = source,
                        ["include_deleted"] = IncludeDeleted,
                        ["include_active"] = IncludeActive,
                        ["max_records"] = (int)Math.Clamp(MaxRecords, 100, 500000),
                        ["max_resident_bytes"] = 1024 * 1024,
                    };

                    // If partition is selected, scope scan and provide cluster info for recovery
                    if (_selectedPartition != null)
                    {
                        payload["start"] = _selectedPartition.StartOffset;
                        payload["end"] = _selectedPartition.StartOffset + _selectedPartition.Length;
                    }

                    var result = await _bridge.ExecuteAsync("mft_scan", payload, OnBridgeEventAsync, token);
                    UpdateFiles(result.Result?["files"] as JsonArray);
                    StatusText = string.Format("MFT scan completed. {0} file(s) listed.", Files.Count);
                    IsProgressIndeterminate = false;
                    ProgressValue = 100;
                    ProgressText = "100%";
                    AddLog("INFO", StatusText);
                }
            );
        }

        public async Task FileCarveAsync()
        {
            await RunCommandAsync(
                "Running file carve...",
                async token =>
                {
                    var source = RequireSourcePath();
                    var outDir = RequireOutputPath();
                    var payload = new JsonObject
                    {
                        ["source_path"] = source,
                        ["out_dir"] = outDir,
                    };

                    var result = await _bridge.ExecuteAsync("file_carve", payload, OnBridgeEventAsync, token);
                    var found = ReadInt(result.Result, "found");
                    StatusText = string.Format("File carve completed. found={0}", found);
                    IsProgressIndeterminate = false;
                    ProgressValue = 100;
                    ProgressText = "100%";
                    AddLog("INFO", StatusText);
                }
            );
        }

        public async Task CreateImageAsync(string outPath)
        {
            if (string.IsNullOrWhiteSpace(outPath))
            {
                return;
            }

            await RunCommandAsync(
                "Creating image...",
                async token =>
                {
                    var source = RequireSourcePath();
                    var payload = new JsonObject
                    {
                        ["source_path"] = source,
                        ["out_path"] = outPath,
                    };

                    if (ImageSelectedPartitionOnly && _selectedPartition != null)
                    {
                        payload["start"] = _selectedPartition.StartOffset;
                        payload["end"] = _selectedPartition.StartOffset + _selectedPartition.Length;
                    }

                    await _bridge.ExecuteAsync("create_image", payload, OnBridgeEventAsync, token);
                    StatusText = "Image created: " + outPath;
                    IsProgressIndeterminate = false;
                    ProgressValue = 100;
                    ProgressText = "100%";
                    AddLog("INFO", StatusText);
                }
            );
        }

        public async Task RecoverSelectedAsync(IReadOnlyList<FileEntryModel> selectedItems)
        {
            await RecoverItemsAsync(selectedItems, "Recovering selected files...", "Recovery completed");
        }

        private async Task RecoverItemsAsync(
            IReadOnlyList<FileEntryModel> selectedItems,
            string operation,
            string completionLabel
        )
        {
            await RunCommandAsync(
                operation,
                async token =>
                {
                    if (selectedItems == null || selectedItems.Count == 0)
                    {
                        throw new InvalidOperationException("Select at least one file to recover.");
                    }

                    var source = RequireSourcePath();
                    var output = RequireOutputPath();
                    var items = new JsonArray();
                    foreach (var item in selectedItems)
                    {
                        var node = new JsonObject
                        {
                            ["path"] = item.Path,
                            ["size"] = item.Size,
                            ["status"] = item.Status,
                            ["inode"] = item.Inode,
                            ["part_offset"] = item.PartOffset,
                            ["is_dir"] = item.IsDir,
                            ["data_size"] = item.DataSize,
                            ["cluster_size"] = item.ClusterSize,
                        };

                        if (!string.IsNullOrWhiteSpace(item.ResidentDataB64))
                        {
                            node["resident_data_b64"] = item.ResidentDataB64;
                        }
                        if (item.DataRuns != null)
                        {
                            node["data_runs"] = item.DataRuns.DeepClone();
                        }

                        items.Add((JsonNode)node);
                    }

                    var payload = new JsonObject
                    {
                        ["source_path"] = source,
                        ["output_root"] = output,
                        ["skip_existing"] = true,
                        ["overwrite"] = false,
                        ["items"] = items,
                    };

                    var result = await _bridge.ExecuteAsync("recover_items", payload, OnBridgeEventAsync, token);
                    var ok = ReadInt(result.Result, "ok");
                    var skipped = ReadInt(result.Result, "skipped");
                    var errors = ReadInt(result.Result, "errors");
                    StatusText = string.Format(
                        "{0}. ok={1} skipped={2} errors={3}",
                        completionLabel,
                        ok,
                        skipped,
                        errors
                    );
                    IsProgressIndeterminate = false;
                    ProgressValue = 100;
                    ProgressText = "100%";
                    AddLog("INFO", StatusText);
                }
            );
        }

        private async Task RunCommandAsync(string operation, Func<CancellationToken, Task> work)
        {
            if (IsBusy)
            {
                AddLog("WARNING", "Another operation is already running.");
                return;
            }

            IsBusy = true;
            StatusText = operation;
            IsProgressIndeterminate = true;
            ProgressValue = 0;
            ProgressText = "...";
            _activeCommandCts = new CancellationTokenSource();

            try
            {
                await work(_activeCommandCts.Token);
            }
            catch (OperationCanceledException)
            {
                StatusText = "Operation canceled.";
                IsProgressIndeterminate = false;
                ProgressValue = 0;
                ProgressText = "0%";
                AddLog("WARNING", "Operation canceled.");
            }
            catch (Exception ex)
            {
                StatusText = "Error: " + ex.Message;
                IsProgressIndeterminate = false;
                ProgressValue = 0;
                ProgressText = "0%";
                AddLog("ERROR", ex.Message);
            }
            finally
            {
                _activeCommandCts?.Dispose();
                _activeCommandCts = null;
                IsBusy = false;
            }
        }

        private Task OnBridgeEventAsync(JsonObject evt)
        {
            _ = _dispatcherQueue.TryEnqueue(() =>
            {
                var type = (evt["type"]?.GetValue<string>() ?? string.Empty).ToLowerInvariant();
                if (type == "log")
                {
                    AddLog(ReadString(evt, "level", "INFO"), ReadString(evt, "message"));
                    return;
                }

                if (type == "progress")
                {
                    var current = ReadLong(evt, "current");
                    var total = ReadLong(evt, "total");
                    UpdateProgress(current, total);
                    return;
                }

                if (type == "status")
                {
                    var message = ReadString(evt, "message");
                    if (!string.IsNullOrWhiteSpace(message))
                    {
                        StatusText = message;
                    }
                    return;
                }

                if (type == "error")
                {
                    AddLog("ERROR", ReadString(evt, "message", "Bridge error."));
                }
            });
            return Task.CompletedTask;
        }

        private void UpdateFiles(JsonArray? files)
        {
            Files.Clear();
            if (files == null)
            {
                FilesUpdated?.Invoke();
                return;
            }

            var seenEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var node in files)
            {
                var o = node as JsonObject;
                if (o == null)
                {
                    continue;
                }

                var inode = ReadLong(o, "inode");
                var displayPath = ReadString(o, "display_path", ReadString(o, "path"));
                var source = ReadString(o, "source");
                var partOffset = ReadLong(o, "part_offset");
                var dedupeKey = ReadString(o, "dedupe_key");
                if (string.IsNullOrWhiteSpace(dedupeKey))
                {
                    var normalized = (displayPath ?? string.Empty).Replace('\\', '/').Trim('/').ToLowerInvariant();
                    dedupeKey = string.Format("{0}|{1}|{2}|{3}", source, partOffset, inode, normalized);
                }
                if (!seenEntries.Add(dedupeKey))
                {
                    continue;
                }

                JsonArray? runs = null;
                if (o["data_runs"] is JsonArray parsedRuns)
                {
                    runs = parsedRuns.DeepClone() as JsonArray;
                }

                Files.Add(
                    new FileEntryModel
                    {
                        Path = displayPath ?? string.Empty,
                        DisplayPath = displayPath ?? string.Empty,
                        Size = ReadLong(o, "size"),
                        Status = ReadString(o, "status"),
                        Inode = inode,
                        PartOffset = partOffset,
                        IsDir = ReadBool(o, "is_dir"),
                        ResidentDataB64 = ReadNullableString(o, "resident_data_b64"),
                        DataRuns = runs,
                        DataSize = ReadNullableLong(o, "data_size"),
                        ClusterSize = ReadNullableInt(o, "cluster_size"),
                        Source = source,
                        NameSource = ReadString(o, "name_source"),
                        DedupeKey = dedupeKey,
                    }
                );
            }

            FilesUpdated?.Invoke();
        }

        private bool IsExportExtensionAllowed(FileEntryModel file)
        {
            var filters = ParseExtensions(ExportExtensions);
            if (filters.Count == 0)
            {
                return true;
            }

            var path = (file.DisplayPath ?? file.Path ?? string.Empty).Replace('\\', '/');
            var fileName = path.Split('/').LastOrDefault() ?? string.Empty;
            var dotIndex = fileName.LastIndexOf('.');
            if (dotIndex < 0 || dotIndex == fileName.Length - 1)
            {
                return false;
            }

            var extension = fileName[(dotIndex + 1)..].Trim().ToLowerInvariant();
            return filters.Contains(extension);
        }

        private static HashSet<string> ParseExtensions(string raw)
        {
            var filters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(raw))
            {
                return filters;
            }

            foreach (var piece in raw.Split(','))
            {
                var ext = piece.Trim().TrimStart('.').ToLowerInvariant();
                if (!string.IsNullOrWhiteSpace(ext))
                {
                    filters.Add(ext);
                }
            }

            return filters;
        }

        private void UpdateProgress(long current, long total)
        {
            if (total > 0)
            {
                IsProgressIndeterminate = false;
                ProgressValue = Math.Clamp(current * 100d / total, 0, 100);
                ProgressText = string.Format("{0:0}%", ProgressValue);
            }
            else
            {
                IsProgressIndeterminate = true;
                ProgressText = "...";
            }
        }

        public void AddLog(string level, string message)
        {
            var safeMessage = message?.Trim();
            if (string.IsNullOrWhiteSpace(safeMessage))
            {
                return;
            }

            Logs.Add(
                new LogEntryModel
                {
                    Timestamp = DateTime.Now,
                    Level = string.IsNullOrWhiteSpace(level) ? "INFO" : level.Trim().ToUpperInvariant(),
                    Message = safeMessage,
                }
            );

            while (Logs.Count > 1000)
            {
                Logs.RemoveAt(0);
            }

            LogAdded?.Invoke();
        }

        private static string ReadString(JsonObject? obj, string key, string fallback = "")
        {
            if (obj == null)
            {
                return fallback;
            }

            try
            {
                return obj[key]?.GetValue<string>() ?? fallback;
            }
            catch
            {
                return fallback;
            }
        }

        private static string? ReadNullableString(JsonObject? obj, string key)
        {
            if (obj == null || obj[key] == null)
            {
                return null;
            }

            try
            {
                return obj[key]!.GetValue<string>();
            }
            catch
            {
                return null;
            }
        }

        private static bool ReadBool(JsonObject? obj, string key)
        {
            if (obj == null)
            {
                return false;
            }

            try
            {
                return obj[key]?.GetValue<bool>() ?? false;
            }
            catch
            {
                return false;
            }
        }

        private static int ReadInt(JsonObject? obj, string key, int fallback = 0)
        {
            if (obj == null)
            {
                return fallback;
            }

            try
            {
                return obj[key]?.GetValue<int>() ?? fallback;
            }
            catch
            {
                return fallback;
            }
        }

        private static int? ReadNullableInt(JsonObject? obj, string key)
        {
            if (obj == null || obj[key] == null)
            {
                return null;
            }

            try
            {
                return obj[key]!.GetValue<int>();
            }
            catch
            {
                return null;
            }
        }

        private static long ReadLong(JsonObject? obj, string key, long fallback = 0)
        {
            if (obj == null)
            {
                return fallback;
            }

            try
            {
                return obj[key]?.GetValue<long>() ?? fallback;
            }
            catch
            {
                return fallback;
            }
        }

        private static long? ReadNullableLong(JsonObject? obj, string key)
        {
            if (obj == null || obj[key] == null)
            {
                return null;
            }

            try
            {
                return obj[key]!.GetValue<long>();
            }
            catch
            {
                return null;
            }
        }

        private string RequireSourcePath()
        {
            var source = SourcePath.Trim();
            if (string.IsNullOrWhiteSpace(source) && _selectedDisk != null)
            {
                source = _selectedDisk.Path;
            }

            if (string.IsNullOrWhiteSpace(source))
            {
                throw new InvalidOperationException("Set a source path or choose a disk first.");
            }

            SourcePath = source;
            return source;
        }

        private string RequireOutputPath()
        {
            var output = OutputPath.Trim();
            if (string.IsNullOrWhiteSpace(output))
            {
                throw new InvalidOperationException("Set an output folder first.");
            }

            Directory.CreateDirectory(output);
            OutputPath = output;
            return output;
        }

        private static string GetDefaultOutputPath()
        {
            var desktop = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                "recovered"
            );
            return desktop;
        }

        private bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
            {
                return false;
            }

            field = value;
            OnPropertyChanged(propertyName);
            return true;
        }

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
