using PyDDEU.WinUI.Models;

namespace PyDDEU.WinUI.Services
{
    public interface IAppLogSink
    {
        void Initialize();

        void Write(LogEntryModel entry);
    }
}
