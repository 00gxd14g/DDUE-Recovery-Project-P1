using System.Text;
using PyDDEU.WinUI.Models;

namespace PyDDEU.WinUI.Services
{
    public sealed class FileLogSink : IAppLogSink
    {
        private static readonly object Sync = new();
        private readonly string _logPath;

        public FileLogSink()
            : this(GetDefaultLogPath())
        {
        }

        internal FileLogSink(string logPath)
        {
            _logPath = logPath;
        }

        public void Initialize()
        {
            var directory = Path.GetDirectoryName(_logPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }

        public void Write(LogEntryModel entry)
        {
            Initialize();

            try
            {
                lock (Sync)
                {
                    File.AppendAllText(_logPath, entry.DisplayText + Environment.NewLine, Encoding.UTF8);
                }

                System.Diagnostics.Debug.WriteLine(entry.DisplayText);
            }
            catch
            {
                // Ignore file sink failures; in-app log list remains the source of truth.
            }
        }

        private static string GetDefaultLogPath()
        {
            var configured = Environment.GetEnvironmentVariable("PYDDEU_DEBUG_LOG");
            if (!string.IsNullOrWhiteSpace(configured))
            {
                return configured;
            }

            var baseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PyDDEU"
            );
            return Path.Combine(baseDir, "debug-console.log");
        }
    }
}
