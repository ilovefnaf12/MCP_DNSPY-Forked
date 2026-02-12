using System.Text;
using DnSpyMcp;

// Ensure UTF-8 encoding for stdin/stdout
Console.InputEncoding = Encoding.UTF8;
Console.OutputEncoding = Encoding.UTF8;

var server = new McpServer();
var cts = new CancellationTokenSource();

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

try
{
    await server.RunAsync(Console.OpenStandardInput(), Console.OpenStandardOutput(), cts.Token);
}
catch (OperationCanceledException)
{
    // Normal shutdown
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Fatal error: {ex.Message}");
    Environment.Exit(1);
}
