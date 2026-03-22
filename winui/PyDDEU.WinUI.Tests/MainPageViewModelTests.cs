using System.Text.Json.Nodes;
using PyDDEU.WinUI.Models;
using PyDDEU.WinUI.Services;
using PyDDEU.WinUI.ViewModels;

namespace PyDDEU.WinUI.Tests;

[TestClass]
public class MainPageViewModelTests
{
    [TestMethod]
    public async Task ListDisksAsync_PopulatesDisksAndSelectsFirst()
    {
        var bridge = new FakeBridgeClient();
        bridge.ResultFactory = command =>
        {
            Assert.AreEqual("list_disks", command);
            return new BridgeCommandResult
            {
                ExitCode = 0,
                Result = new JsonObject
                {
                    ["type"] = "result",
                    ["command"] = "list_disks",
                    ["disks"] = new JsonArray
                    {
                        new JsonObject { ["path"] = "disk0.img", ["size"] = 1024, ["description"] = "Disk 0" },
                        new JsonObject { ["path"] = "disk1.img", ["size"] = 2048, ["description"] = "Disk 1" },
                    },
                },
            };
        };

        using var viewModel = CreateViewModel(bridge);
        await viewModel.ListDisksAsync();

        Assert.AreEqual(2, viewModel.DiskCount);
        Assert.AreEqual("disk0.img", viewModel.SelectedDisk?.Path);
        Assert.AreEqual("disk0.img", viewModel.SourcePath);
        Assert.AreEqual("2 disk(s) listed.", viewModel.StatusText);
        Assert.IsTrue(viewModel.CommandsEnabled);
        Assert.IsFalse(viewModel.CanStop);
    }

    [TestMethod]
    public async Task ScanPartitionsAsync_PopulatesPartitionsAndSelectsFirst()
    {
        var bridge = new FakeBridgeClient();
        bridge.ResultFactory = command =>
        {
            Assert.AreEqual("scan_partitions", command);
            return new BridgeCommandResult
            {
                ExitCode = 0,
                Result = new JsonObject
                {
                    ["type"] = "result",
                    ["command"] = "scan_partitions",
                    ["partitions"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["index"] = 1,
                            ["start_offset"] = 4096,
                            ["length"] = 8192,
                            ["scheme"] = "GPT",
                            ["type_str"] = "Basic",
                            ["name"] = "Data",
                        },
                    },
                },
            };
        };

        using var viewModel = CreateViewModel(bridge);
        viewModel.SourcePath = "disk0.img";
        await viewModel.ScanPartitionsAsync();

        Assert.AreEqual(1, viewModel.PartitionCount);
        Assert.AreEqual(1, viewModel.SelectedPartition?.Index);
        Assert.AreEqual("1 partition(s) found.", viewModel.StatusText);
    }

    [TestMethod]
    public async Task ScanPartitionsAsync_AutoSelectsNtfsPartitionInsteadOfFirstSystemPartition()
    {
        var bridge = new FakeBridgeClient();
        bridge.ResultFactory = command =>
        {
            Assert.AreEqual("scan_partitions", command);
            return new BridgeCommandResult
            {
                ExitCode = 0,
                Result = new JsonObject
                {
                    ["type"] = "result",
                    ["command"] = "scan_partitions",
                    ["partitions"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["index"] = 1,
                            ["start_offset"] = 2048,
                            ["length"] = 268435456,
                            ["scheme"] = "GPT",
                            ["type_str"] = "EFI System",
                            ["name"] = "EFI",
                            ["filesystem"] = "FAT32",
                        },
                        new JsonObject
                        {
                            ["index"] = 2,
                            ["start_offset"] = 105906176,
                            ["length"] = 250000000000,
                            ["scheme"] = "GPT",
                            ["type_str"] = "Basic data partition (NTFS)",
                            ["name"] = "Windows",
                            ["filesystem"] = "NTFS",
                        },
                    },
                },
            };
        };

        using var viewModel = CreateViewModel(bridge);
        viewModel.SourcePath = "disk0.img";
        await viewModel.ScanPartitionsAsync();

        Assert.AreEqual(2, viewModel.SelectedPartition?.Index);
    }

    [TestMethod]
    public async Task ConnectAsync_ValidatesSourceAndShowsConnectedStatus()
    {
        var bridge = new FakeBridgeClient();
        var sink = new FakeLogSink();
        bridge.ResultFactory = command =>
        {
            Assert.AreEqual("connect", command);
            return new BridgeCommandResult
            {
                ExitCode = 0,
                Result = new JsonObject
                {
                    ["type"] = "result",
                    ["command"] = "connect",
                    ["source_path"] = "disk0.img",
                    ["size"] = 1024L,
                    ["sector_size"] = 512,
                    ["map_path"] = "pyddeu.map.disk0.json",
                },
            };
        };

        using var viewModel = CreateViewModel(bridge, sink);
        viewModel.SourcePath = "disk0.img";

        await viewModel.ConnectAsync();

        Assert.AreEqual("Connected: disk0.img", viewModel.StatusText);
        Assert.IsTrue(viewModel.Logs.Any(log => log.Message.Contains("Connected: disk0.img")));
        Assert.IsTrue(sink.Entries.Any(log => log.Message.Contains("Connected: disk0.img")));
    }

    [TestMethod]
    public async Task ListDisksAsync_TogglesBusyStateDuringExecution()
    {
        var bridge = new FakeBridgeClient();
        var started = new TaskCompletionSource();
        var release = new TaskCompletionSource();

        bridge.ExecuteHandler = async (command, payload, onEvent, cancellationToken) =>
        {
            started.SetResult();
            await release.Task.WaitAsync(cancellationToken);
            return new BridgeCommandResult
            {
                ExitCode = 0,
                Result = new JsonObject
                {
                    ["type"] = "result",
                    ["command"] = command,
                    ["disks"] = new JsonArray(),
                },
            };
        };

        using var viewModel = CreateViewModel(bridge);
        var task = viewModel.ListDisksAsync();
        await started.Task;

        Assert.IsTrue(viewModel.IsBusy);
        Assert.IsFalse(viewModel.CommandsEnabled);
        Assert.IsTrue(viewModel.CanStop);

        release.SetResult();
        await task;

        Assert.IsFalse(viewModel.IsBusy);
        Assert.IsTrue(viewModel.CommandsEnabled);
        Assert.IsFalse(viewModel.CanStop);
    }

    [TestMethod]
    public async Task ParseFilesystemAsync_UpdatesFilesAndDeduplicatesEntries()
    {
        var bridge = new FakeBridgeClient();
        bridge.ResultFactory = command =>
        {
            Assert.AreEqual("parse_fs", command);
            return new BridgeCommandResult
            {
                ExitCode = 0,
                Result = new JsonObject
                {
                    ["type"] = "result",
                    ["command"] = "parse_fs",
                    ["files"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["path"] = "Users/Alice/report.docx",
                            ["display_path"] = "Users/Alice/report.docx",
                            ["size"] = 120,
                            ["status"] = "ACTIVE",
                            ["inode"] = 42,
                            ["part_offset"] = 4096,
                            ["source"] = "pytsk3",
                            ["dedupe_key"] = "dup-key",
                        },
                        new JsonObject
                        {
                            ["path"] = "Users/Alice/report.docx",
                            ["display_path"] = "Users/Alice/report.docx",
                            ["size"] = 120,
                            ["status"] = "ACTIVE",
                            ["inode"] = 42,
                            ["part_offset"] = 4096,
                            ["source"] = "pytsk3",
                            ["dedupe_key"] = "dup-key",
                        },
                    },
                },
            };
        };

        using var viewModel = CreateViewModel(bridge);
        viewModel.SourcePath = "disk0.img";
        viewModel.SetSelectedPartition(new PartitionInfoModel { Index = 1, StartOffset = 4096, Length = 8192 });
        await viewModel.ParseFilesystemAsync();

        Assert.AreEqual(1, viewModel.FileCount);
        Assert.AreEqual("Users/Alice/report.docx", viewModel.Files[0].DisplayPath);
        Assert.AreEqual("Filesystem parsed. 1 file(s).", viewModel.StatusText);
    }

    [TestMethod]
    public async Task ExportAllAsync_FiltersByStatusAndExtension()
    {
        var bridge = new FakeBridgeClient();
        bridge.ResultFactory = command =>
        {
            Assert.AreEqual("recover_items", command);
            var items = bridge.LastPayload?["items"] as JsonArray;
            Assert.IsNotNull(items);
            Assert.AreEqual(1, items.Count);
            Assert.AreEqual("Users/Alice/keep.jpg", ((JsonObject)items[0]!)["path"]?.GetValue<string>());

            return new BridgeCommandResult
            {
                ExitCode = 0,
                Result = new JsonObject
                {
                    ["type"] = "result",
                    ["command"] = "recover_items",
                    ["ok"] = 1,
                    ["skipped"] = 0,
                    ["errors"] = 0,
                },
            };
        };

        using var viewModel = CreateViewModel(bridge);
        viewModel.SourcePath = "disk0.img";
        viewModel.OutputPath = Path.Combine(Path.GetTempPath(), "pyddeu-export-test");
        viewModel.IncludeDeleted = false;
        viewModel.IncludeActive = true;
        viewModel.ExportExtensions = "jpg,pdf";
        viewModel.Files.Add(new FileEntryModel { Path = "Users/Alice/keep.jpg", DisplayPath = "Users/Alice/keep.jpg", Status = "ACTIVE", Size = 10, Inode = 1 });
        viewModel.Files.Add(new FileEntryModel { Path = "Users/Alice/drop.txt", DisplayPath = "Users/Alice/drop.txt", Status = "ACTIVE", Size = 10, Inode = 2 });
        viewModel.Files.Add(new FileEntryModel { Path = "Users/Alice/deleted.pdf", DisplayPath = "Users/Alice/deleted.pdf", Status = "DELETED", Size = 10, Inode = 3 });

        await viewModel.ExportAllAsync();

        Assert.AreEqual("Export completed. ok=1 skipped=0 errors=0", viewModel.StatusText);
    }

    [TestMethod]
    public async Task RecoverSelectedAsync_ShowsErrorWhenOutputPathMissing()
    {
        using var viewModel = CreateViewModel(new FakeBridgeClient());
        viewModel.SourcePath = "disk0.img";
        viewModel.OutputPath = " ";

        await viewModel.RecoverSelectedAsync(
            new[] { new FileEntryModel { Path = "Users/Alice/test.txt", DisplayPath = "Users/Alice/test.txt", Inode = 1, Size = 4 } }
        );

        Assert.AreEqual("Error: Set an output folder first.", viewModel.StatusText);
        Assert.IsTrue(viewModel.Logs.Any(log => log.Level == "ERROR" && log.Message.Contains("Set an output folder first.")));
    }

    [TestMethod]
    public async Task CreateImageAsync_UsesSelectedPartitionBoundsWhenEnabled()
    {
        var bridge = new FakeBridgeClient();
        bridge.ResultFactory = command =>
        {
            Assert.AreEqual("create_image", command);
            Assert.AreEqual(4096, bridge.LastPayload?["start"]?.GetValue<long>());
            Assert.AreEqual(12288, bridge.LastPayload?["end"]?.GetValue<long>());
            return new BridgeCommandResult
            {
                ExitCode = 0,
                Result = new JsonObject { ["type"] = "result", ["command"] = "create_image" },
            };
        };

        using var viewModel = CreateViewModel(bridge);
        viewModel.SourcePath = "disk0.img";
        viewModel.ImageSelectedPartitionOnly = true;
        viewModel.SetSelectedPartition(new PartitionInfoModel { Index = 1, StartOffset = 4096, Length = 8192 });

        await viewModel.CreateImageAsync("disk-output.img");

        Assert.AreEqual("Image created: disk-output.img", viewModel.StatusText);
    }

    [TestMethod]
    public async Task RequestStop_CancelsRunningOperation()
    {
        var bridge = new FakeBridgeClient();
        var started = new TaskCompletionSource();

        bridge.ExecuteHandler = async (command, payload, onEvent, cancellationToken) =>
        {
            started.SetResult();
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            return new BridgeCommandResult
            {
                ExitCode = 0,
                Result = new JsonObject { ["type"] = "result", ["command"] = command, ["disks"] = new JsonArray() },
            };
        };

        using var viewModel = CreateViewModel(bridge);
        var task = viewModel.ListDisksAsync();
        await started.Task;
        viewModel.RequestStop();
        await task;

        Assert.AreEqual("Operation canceled.", viewModel.StatusText);
        Assert.IsTrue(viewModel.Logs.Any(log => log.Level == "WARNING" && log.Message.Contains("Operation canceled.")));
    }

    [TestMethod]
    public void AddLog_WritesToConfiguredSink()
    {
        var sink = new FakeLogSink();
        using var viewModel = CreateViewModel(new FakeBridgeClient(), sink);

        viewModel.AddLog("INFO", "terminal mirror");

        Assert.AreEqual(1, sink.InitializeCallCount);
        Assert.HasCount(1, sink.Entries);
        Assert.AreEqual("terminal mirror", sink.Entries[0].Message);
    }

    private static MainPageViewModel CreateViewModel(FakeBridgeClient bridge, FakeLogSink? sink = null)
    {
        return new MainPageViewModel(bridge, sink ?? new FakeLogSink(), action =>
        {
            action();
            return true;
        });
    }

    private sealed class FakeBridgeClient : IPythonBridgeClient
    {
        public Func<string, JsonObject?, Func<JsonObject, Task>?, CancellationToken, Task<BridgeCommandResult>>? ExecuteHandler { get; set; }
        public Func<string, BridgeCommandResult>? ResultFactory { get; set; }
        public JsonObject? LastPayload { get; private set; }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<BridgeCommandResult> ExecuteAsync(
            string command,
            JsonObject? payload,
            Func<JsonObject, Task>? onEvent,
            CancellationToken cancellationToken = default
        )
        {
            LastPayload = payload?.DeepClone() as JsonObject;
            if (ExecuteHandler != null)
            {
                return ExecuteHandler(command, payload, onEvent, cancellationToken);
            }

            return Task.FromResult(
                ResultFactory?.Invoke(command)
                ?? new BridgeCommandResult
                {
                    ExitCode = 0,
                    Result = new JsonObject { ["type"] = "result", ["command"] = command },
                }
            );
        }

        public void Dispose()
        {
        }
    }

    private sealed class FakeLogSink : IAppLogSink
    {
        public int InitializeCallCount { get; private set; }
        public List<LogEntryModel> Entries { get; } = new();

        public void Initialize()
        {
            InitializeCallCount++;
        }

        public void Write(LogEntryModel entry)
        {
            Entries.Add(entry);
        }
    }
}
