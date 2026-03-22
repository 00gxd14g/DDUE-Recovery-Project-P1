using PyDDEU.WinUI.Models;
using PyDDEU.WinUI.Services;

namespace PyDDEU.WinUI.Tests;

[TestClass]
public class FileLogSinkTests
{
    [TestMethod]
    public void Write_AppendsDisplayTextToConfiguredFile()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "pyddeu-log-sink-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var logPath = Path.Combine(tempDir, "debug.log");

        try
        {
            var sink = new FileLogSink(logPath);
            sink.Initialize();
            sink.Write(
                new LogEntryModel
                {
                    Timestamp = new DateTime(2026, 3, 9, 12, 0, 0),
                    Level = "INFO",
                    Message = "hello terminal",
                }
            );

            var text = File.ReadAllText(logPath);
            StringAssert.Contains(text, "hello terminal");
            StringAssert.Contains(text, "[INFO]");
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }
}
