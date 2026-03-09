using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using PyDDEU.WinUI.Models;
using PyDDEU.WinUI.ViewModels;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace PyDDEU.WinUI.Views
{
    public partial class MainPage : Page
    {
        public MainPageViewModel ViewModel { get; }

        public MainPage()
        {
            InitializeComponent();
            ViewModel = new MainPageViewModel(DispatcherQueue);
            DataContext = ViewModel;

            ViewModel.LogAdded += OnLogAdded;
            ViewModel.FilesUpdated += OnFilesUpdated;
        }

        private async void OnPageLoaded(object sender, RoutedEventArgs e)
        {
            if (!ViewModel.IsAdmin)
            {
                AdminWarningBar.IsOpen = true;
            }

            await ViewModel.InitializeAsync();

            // Sync disk selection in UI (TwoWay binding on SelectedItem can be unreliable)
            if (ViewModel.Disks.Count > 0 && DisksListView.SelectedIndex < 0)
            {
                DisksListView.SelectedIndex = 0;
            }
        }

        private void OnPageUnloaded(object sender, RoutedEventArgs e)
        {
            ViewModel.LogAdded -= OnLogAdded;
            ViewModel.FilesUpdated -= OnFilesUpdated;
            ViewModel.Dispose();
        }

        private void OnLogAdded()
        {
            if (ViewModel.Logs.Count > 0)
            {
                LogsListView.ScrollIntoView(ViewModel.Logs[^1]);
            }
        }

        private void OnFilesUpdated()
        {
            RebuildFileTree();
        }

        private async void OnListDisksClicked(object sender, RoutedEventArgs e)
        {
            await ViewModel.ListDisksAsync();

            // Sync disk selection in UI
            if (ViewModel.Disks.Count > 0 && DisksListView.SelectedIndex < 0)
            {
                DisksListView.SelectedIndex = 0;
            }
        }

        private async void OnScanPartitionsClicked(object sender, RoutedEventArgs e)
        {
            await ViewModel.ScanPartitionsAsync();

            // Sync partition selection in UI
            if (ViewModel.Partitions.Count > 0 && PartitionsListView.SelectedIndex < 0)
            {
                PartitionsListView.SelectedIndex = 0;
            }
        }

        private async void OnDeepScanClicked(object sender, RoutedEventArgs e)
        {
            await ViewModel.DeepScanAsync();
        }

        private async void OnMftScanClicked(object sender, RoutedEventArgs e)
        {
            await ViewModel.MftScanAsync();
        }

        private async void OnParseFsClicked(object sender, RoutedEventArgs e)
        {
            await ViewModel.ParseFilesystemAsync();
        }

        private async void OnFileCarveClicked(object sender, RoutedEventArgs e)
        {
            var confirmed = await ShowConfirmationAsync(
                "File Carve",
                "This will scan the source for file signatures and write carved files to the output folder. Continue?"
            );
            if (confirmed)
            {
                await ViewModel.FileCarveAsync();
            }
        }

        private async void OnCreateImageClicked(object sender, RoutedEventArgs e)
        {
            var outPath = await PickImageOutputPathAsync();
            if (string.IsNullOrWhiteSpace(outPath))
            {
                return;
            }

            var confirmed = await ShowConfirmationAsync(
                "Create Image",
                string.Format("This will create a raw disk image at:\n{0}\n\nThis may take a long time. Continue?", outPath)
            );
            if (confirmed)
            {
                await ViewModel.CreateImageAsync(outPath);
            }
        }

        private async void OnRecoverSelectedClicked(object sender, RoutedEventArgs e)
        {
            var selected = CollectSelectedFiles();
            if (selected.Count == 0)
            {
                await ShowInfoAsync("No Selection", "Select files or folders from the tree to recover.\nSelecting a folder recovers all files inside it.");
                return;
            }

            var confirmed = await ShowConfirmationAsync(
                "Recover Files",
                string.Format("Recover {0} file(s) to:\n{1}\n\nContinue?", selected.Count, ViewModel.OutputPath)
            );
            if (confirmed)
            {
                await ViewModel.RecoverSelectedAsync(selected);
            }
        }

        private async void OnRecoverAllClicked(object sender, RoutedEventArgs e)
        {
            if (ViewModel.Files.Count == 0)
            {
                await ShowInfoAsync("No Files", "Run a scan first to find files.");
                return;
            }

            var confirmed = await ShowConfirmationAsync(
                "Recover All",
                string.Format("Recover all {0} file(s) to:\n{1}\n\nContinue?", ViewModel.Files.Count, ViewModel.OutputPath)
            );
            if (confirmed)
            {
                await ViewModel.RecoverAllAsync();
            }
        }

        private async void OnExportAllClicked(object sender, RoutedEventArgs e)
        {
            if (ViewModel.Files.Count == 0)
            {
                await ShowInfoAsync("No Files", "Run a scan first to find files.");
                return;
            }

            var filterLabel = string.IsNullOrWhiteSpace(ViewModel.ExportExtensions)
                ? "all extensions"
                : ViewModel.ExportExtensions;
            var confirmed = await ShowConfirmationAsync(
                "Export All",
                string.Format(
                    "Export visible files matching extensions: {0}\nTo:\n{1}\n\nContinue?",
                    filterLabel,
                    ViewModel.OutputPath
                )
            );
            if (confirmed)
            {
                await ViewModel.ExportAllAsync();
            }
        }

        private void OnStopClicked(object sender, RoutedEventArgs e)
        {
            ViewModel.RequestStop();
        }

        private void OnClearLogsClicked(object sender, RoutedEventArgs e)
        {
            ViewModel.ClearLogs();
        }

        private async void OnPickSourceClicked(object sender, RoutedEventArgs e)
        {
            var path = await PickSourceFileAsync();
            if (!string.IsNullOrWhiteSpace(path))
            {
                ViewModel.SourcePath = path;
                ViewModel.AddLog("INFO", "Source selected: " + path);
            }
        }

        private async void OnPickOutputFolderClicked(object sender, RoutedEventArgs e)
        {
            var path = await PickOutputFolderAsync();
            if (!string.IsNullOrWhiteSpace(path))
            {
                ViewModel.OutputPath = path;
                ViewModel.AddLog("INFO", "Output folder selected: " + path);
            }
        }

        private void OnDisksSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ViewModel.SetSelectedDisk(DisksListView.SelectedItem as DiskInfoModel);
        }

        private void OnPartitionsSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ViewModel.SetSelectedPartition(PartitionsListView.SelectedItem as PartitionInfoModel);
        }

        private void OnFileTreeItemInvoked(TreeView sender, TreeViewItemInvokedEventArgs args)
        {
            UpdateSelectionText();
        }

        // -------------------------------------------------------------------
        // File tree building
        // -------------------------------------------------------------------

        private void RebuildFileTree()
        {
            FilesTreeView.RootNodes.Clear();

            if (ViewModel.Files.Count == 0)
            {
                FileSelectionText.Text = string.Empty;
                return;
            }

            // Track folder data separately — TreeViewNode.Content will hold UI elements
            var folderMap = new Dictionary<string, TreeViewNode>(StringComparer.OrdinalIgnoreCase);
            var folderInfoMap = new Dictionary<string, FolderNodeInfo>(StringComparer.OrdinalIgnoreCase);

            foreach (var file in ViewModel.Files)
            {
                var path = (string.IsNullOrWhiteSpace(file.DisplayPath) ? file.Path : file.DisplayPath)
                    .Replace('\\', '/')
                    .Trim('/');
                if (string.IsNullOrEmpty(path))
                {
                    path = file.Inode > 0
                        ? string.Format("inode_{0}", file.Inode)
                        : "unknown";
                }

                var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0)
                {
                    continue;
                }

                TreeViewNode? parent = null;
                var accumulated = string.Empty;

                for (int i = 0; i < parts.Length; i++)
                {
                    accumulated = i == 0 ? parts[i] : accumulated + "/" + parts[i];
                    bool isLeaf = i == parts.Length - 1;

                    if (isLeaf && !file.IsDir)
                    {
                        var fileNode = new TreeViewNode
                        {
                            Content = BuildFileContent(file),
                            IsExpanded = false,
                        };

                        if (parent == null)
                        {
                            FilesTreeView.RootNodes.Add(fileNode);
                        }
                        else
                        {
                            parent.Children.Add(fileNode);
                        }

                        // Update parent folder counts
                        if (parent != null && folderInfoMap.TryGetValue(GetNodeKey(parent), out var parentFolder))
                        {
                            parentFolder.FileCount++;
                            UpdateFolderContent(parent, parentFolder);
                        }
                    }
                    else
                    {
                        if (!folderMap.TryGetValue(accumulated, out var folderNode))
                        {
                            var folderInfo = new FolderNodeInfo
                            {
                                Name = parts[i],
                                FullPath = accumulated,
                            };
                            folderNode = new TreeViewNode
                            {
                                Content = BuildFolderContent(folderInfo),
                                IsExpanded = false,
                            };
                            folderMap[accumulated] = folderNode;
                            folderInfoMap[accumulated] = folderInfo;

                            if (parent == null)
                            {
                                FilesTreeView.RootNodes.Add(folderNode);
                            }
                            else
                            {
                                parent.Children.Add(folderNode);
                                if (parent != null && folderInfoMap.TryGetValue(GetNodeKey(parent), out var pf))
                                {
                                    pf.FolderCount++;
                                    UpdateFolderContent(parent, pf);
                                }
                            }
                        }
                        parent = folderNode;
                    }
                }
            }

            FileSelectionText.Text = string.Empty;
        }

        private static string GetNodeKey(TreeViewNode node)
        {
            // Retrieve the folder path from the Tag on the StackPanel content
            if (node.Content is StackPanel sp && sp.Tag is string key)
            {
                return key;
            }
            return string.Empty;
        }

        private static StackPanel BuildFolderContent(FolderNodeInfo info)
        {
            var panel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 6,
                Padding = new Thickness(2),
                Tag = info.FullPath, // used by GetNodeKey for lookup
            };

            panel.Children.Add(new FontIcon
            {
                Glyph = "\uE8B7",
                FontSize = 14,
            });

            panel.Children.Add(new TextBlock
            {
                Text = info.Name,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
            });

            panel.Children.Add(new TextBlock
            {
                Text = info.MetaText,
                FontSize = 11,
                Opacity = 0.5,
                VerticalAlignment = VerticalAlignment.Center,
                Tag = "meta", // marker for UpdateFolderContent
            });

            return panel;
        }

        private static void UpdateFolderContent(TreeViewNode node, FolderNodeInfo info)
        {
            if (node.Content is StackPanel sp)
            {
                foreach (var child in sp.Children)
                {
                    if (child is TextBlock tb && tb.Tag as string == "meta")
                    {
                        tb.Text = info.MetaText;
                        break;
                    }
                }
            }
        }

        private static StackPanel BuildFileContent(FileEntryModel file)
        {
            var panel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 8,
                Padding = new Thickness(2),
                Tag = file, // store model for CollectSelectedFiles
            };

            // Status badge
            var badgeBorder = new Border
            {
                Padding = new Thickness(5, 1, 5, 1),
                CornerRadius = new CornerRadius(4),
                Background = Application.Current.Resources["ShellAccentMutedBrush"] as Brush
                    ?? new SolidColorBrush(Colors.Gray),
            };
            badgeBorder.Child = new TextBlock
            {
                Text = file.StatusBadge,
                FontSize = 11,
                FontWeight = FontWeights.SemiBold,
            };
            panel.Children.Add(badgeBorder);

            // File name
            panel.Children.Add(new TextBlock
            {
                Text = file.FileName,
                FontSize = 13,
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth = 400,
            });

            // Size
            panel.Children.Add(new TextBlock
            {
                Text = file.SizeText,
                FontSize = 12,
                Opacity = 0.7,
                VerticalAlignment = VerticalAlignment.Center,
            });

            return panel;
        }

        // -------------------------------------------------------------------
        // Selection helpers
        // -------------------------------------------------------------------

        private List<FileEntryModel> CollectSelectedFiles()
        {
            var result = new List<FileEntryModel>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var node in FilesTreeView.SelectedNodes)
            {
                CollectFilesFromNode(node, result, seen);
            }

            return result;
        }

        private static void CollectFilesFromNode(TreeViewNode node, List<FileEntryModel> result, HashSet<string> seen)
        {
            // Content is now a StackPanel; FileEntryModel stored in Tag
            var file = ExtractFileModel(node);
            if (file != null)
            {
                var dedupeKey = string.IsNullOrWhiteSpace(file.DedupeKey)
                    ? string.Format(
                        "{0}|{1}|{2}|{3}",
                        file.Source,
                        file.PartOffset,
                        file.Inode,
                        (string.IsNullOrWhiteSpace(file.DisplayPath) ? file.Path : file.DisplayPath)
                            .Replace('\\', '/')
                            .Trim('/')
                            .ToLowerInvariant()
                    )
                    : file.DedupeKey;
                if (seen.Add(dedupeKey))
                {
                    result.Add(file);
                }
            }
            else
            {
                // Folder node - collect all children recursively
                foreach (var child in node.Children)
                {
                    CollectFilesFromNode(child, result, seen);
                }
            }
        }

        private static FileEntryModel? ExtractFileModel(TreeViewNode node)
        {
            if (node.Content is StackPanel sp && sp.Tag is FileEntryModel file)
            {
                return file;
            }
            // Fallback: direct Content check (shouldn't happen, but safe)
            if (node.Content is FileEntryModel directFile)
            {
                return directFile;
            }
            return null;
        }

        private void UpdateSelectionText()
        {
            var count = FilesTreeView.SelectedNodes.Count;
            if (count > 0)
            {
                // Count actual files that would be recovered
                var files = CollectSelectedFiles();
                FileSelectionText.Text = string.Format("({0} file(s) selected)", files.Count);
            }
            else
            {
                FileSelectionText.Text = string.Empty;
            }
        }

        // -------------------------------------------------------------------
        // Dialogs & Pickers
        // -------------------------------------------------------------------

        private static IntPtr GetWindowHandle()
        {
            return App.MainWindow == null ? IntPtr.Zero : WindowNative.GetWindowHandle(App.MainWindow);
        }

        private async Task<bool> ShowConfirmationAsync(string title, string message)
        {
            if (App.MainWindow?.Content?.XamlRoot == null)
            {
                return true;
            }

            var dialog = new ContentDialog
            {
                Title = title,
                Content = message,
                PrimaryButtonText = "Continue",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = App.MainWindow.Content.XamlRoot,
            };

            var result = await dialog.ShowAsync();
            return result == ContentDialogResult.Primary;
        }

        private async Task ShowInfoAsync(string title, string message)
        {
            if (App.MainWindow?.Content?.XamlRoot == null)
            {
                return;
            }

            var dialog = new ContentDialog
            {
                Title = title,
                Content = message,
                CloseButtonText = "OK",
                DefaultButton = ContentDialogButton.Close,
                XamlRoot = App.MainWindow.Content.XamlRoot,
            };

            await dialog.ShowAsync();
        }

        private async Task<string?> PickSourceFileAsync()
        {
            var picker = new FileOpenPicker
            {
                SuggestedStartLocation = PickerLocationId.ComputerFolder,
                ViewMode = PickerViewMode.List,
            };
            picker.FileTypeFilter.Add("*");

            var hwnd = GetWindowHandle();
            if (hwnd == IntPtr.Zero)
            {
                return null;
            }

            InitializeWithWindow.Initialize(picker, hwnd);
            var file = await picker.PickSingleFileAsync();
            return file?.Path;
        }

        private async Task<string?> PickOutputFolderAsync()
        {
            var picker = new FolderPicker
            {
                SuggestedStartLocation = PickerLocationId.Desktop,
            };
            picker.FileTypeFilter.Add("*");

            var hwnd = GetWindowHandle();
            if (hwnd == IntPtr.Zero)
            {
                return null;
            }

            InitializeWithWindow.Initialize(picker, hwnd);
            var folder = await picker.PickSingleFolderAsync();
            return folder?.Path;
        }

        private async Task<string?> PickImageOutputPathAsync()
        {
            var picker = new FileSavePicker
            {
                SuggestedStartLocation = PickerLocationId.Desktop,
                SuggestedFileName = "pyddeu-image",
                DefaultFileExtension = ".img",
            };

            picker.FileTypeChoices.Add("Raw image", new System.Collections.Generic.List<string> { ".img", ".dd" });
            var hwnd = GetWindowHandle();
            if (hwnd == IntPtr.Zero)
            {
                return null;
            }

            InitializeWithWindow.Initialize(picker, hwnd);
            var file = await picker.PickSaveFileAsync();
            return file?.Path;
        }
    }
}
