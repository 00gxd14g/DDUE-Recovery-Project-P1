using System.Text.Json.Nodes;
using PyDDEU.WinUI.Models;

namespace PyDDEU.WinUI.Services
{
    public interface IPythonBridgeClient : IDisposable
    {
        Task InitializeAsync(CancellationToken cancellationToken = default);

        Task<BridgeCommandResult> ExecuteAsync(
            string command,
            JsonObject? payload,
            Func<JsonObject, Task>? onEvent,
            CancellationToken cancellationToken = default
        );
    }
}
