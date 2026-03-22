using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using PyDDEU.WinUI.Models;

namespace PyDDEU.WinUI.Views
{
    public sealed class FileTreeTemplateSelector : DataTemplateSelector
    {
        public DataTemplate? FolderTemplate { get; set; }
        public DataTemplate? FileTemplate { get; set; }

        protected override DataTemplate SelectTemplateCore(object item)
        {
            // Safety: unwrap TreeViewNode if WinUI passes the node instead of Content
            if (item is TreeViewNode node)
            {
                item = node.Content;
            }

            if (item is FileTreeNodeModel treeNode)
            {
                if (!treeNode.IsFolder && FileTemplate != null)
                {
                    return FileTemplate;
                }

                if (FolderTemplate != null)
                {
                    return FolderTemplate;
                }
            }

            if (item is FileEntryModel && FileTemplate != null)
            {
                return FileTemplate;
            }

            if (FolderTemplate != null)
            {
                return FolderTemplate;
            }

            return base.SelectTemplateCore(item);
        }
    }
}
