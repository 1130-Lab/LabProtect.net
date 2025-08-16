using System.Diagnostics;

namespace EncryptedApp.Common.AntiCrack_DotNet
{
    public interface IAntiCrackMonitor : IDisposable
    {
        public Action<string>? OnDetected { get; set; }
        public CancellationTokenSource CancellationTokenSource { get; }

        /// <summary>
        /// Starts all anti-debug checks with the specified time interval.
        /// </summary>
        public void Start(int timeInterval = 1000)
        {
            Task.Factory.StartNew(async () => await PerformChecks(timeInterval),
                CancellationTokenSource.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default)
                .ContinueWith(t =>
                {
                    if (t.IsFaulted)
                    {
                        Trace.WriteLine($"AntiDebug checks failed: {t.Exception?.GetBaseException().Message}");
                    }
                });
        }

        /// <summary>
        /// Performs anti-crack checks at the specified time interval.
        /// </summary>
        public Task PerformChecks(int timeInterval);
    }
}
