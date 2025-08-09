using AntiCrack_DotNet;
using System.Diagnostics;
using System.Management;

namespace EncryptedApp.Common.AntiCrack_DotNet
{
    public sealed class AntiSniff : IAntiCrackMonitor
    {
        private static SemaphoreSlim _taskLock = new SemaphoreSlim(1, 1);
        private HashSet<string> _badWindowNames = new HashSet<string>() { "wireshark", "tcpdump", "npcap", "tshark" };
        private ManagementEventWatcher? _watcher;
        private WqlEventQuery? startQuery = OperatingSystem.IsWindows() ? new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace") : null;
        private readonly bool _windows = OperatingSystem.IsWindows();

        public Action? OnDetected { get; set; }
        public CancellationTokenSource CancellationTokenSource { get; }


        public AntiSniff(CancellationTokenSource source)
        {
            CancellationTokenSource = source ?? throw new ArgumentNullException(nameof(source));
        }

        public async Task PerformChecks(int timeInterval)
        {
            if (_windows)
            {
                StartWindowsAntiSniff();
            }
            while (!CancellationTokenSource.IsCancellationRequested)
            {
                await _taskLock.WaitAsync(CancellationTokenSource.Token);
                try
                {
                    if (!_windows)
                    {
                        if (FindCrossPlatformAntiSniff())
                        {
                            OnDetected?.Invoke();
                        }
                    }
                }
                finally
                {
                    _taskLock.Release();
                }
                await Task.Delay(timeInterval, CancellationTokenSource.Token);
            }
            StopWindowsAntiSniff();
        }

        public void StartWindowsAntiSniff()
        {
            if (!_windows)
            {
                throw new PlatformNotSupportedException("This method is only supported on Windows.");
            }
            _watcher = new ManagementEventWatcher(startQuery);
            _watcher.EventArrived += _watcher_EventArrived;
            _watcher.Start();
        }

        private void StopWindowsAntiSniff()
        {
            if (!_windows)
            {
                throw new PlatformNotSupportedException("This method is only supported on Windows.");
            }
            if (_watcher != null)
            {
                _watcher.EventArrived -= _watcher_EventArrived;
                _watcher.Stop();
                _watcher.Dispose();
                _watcher = null;
            }
        }

        private void _watcher_EventArrived(object sender, EventArrivedEventArgs e)
        {
            if(!_windows)
            {
                throw new PlatformNotSupportedException("This method is only supported on Windows.");
            }
            if (e == null || e.NewEvent == null)
            {
                return; // No ProcessName property, skip this event
            }
            var processNameProperty = e.NewEvent.Properties["ProcessName"];
            if (processNameProperty == null || processNameProperty.Value == null)
            {
                return; // No ProcessName property, skip this event
            }
            string processName = e.NewEvent.Properties["ProcessName"].Value.ToString()!;

            foreach (string window in _badWindowNames)
            {
                if (Utils.Contains(processName!, window))
                {
                    OnDetected?.Invoke();
                }
            }
        }

        public bool FindCrossPlatformAntiSniff()
        {
            Process[] GetProcesses = Process.GetProcesses();
            foreach (Process GetWindow in GetProcesses)
            {
                try
                {
                    if (GetWindow.MainWindowHandle != IntPtr.Zero)
                    {
                        string title = GetWindow.MainWindowTitle;
                        if (string.IsNullOrEmpty(title)) continue;

                        foreach (string BadWindows in _badWindowNames)
                        {
                            if (Utils.Contains(title, BadWindows))
                            {
                                OnDetected?.Invoke();
                                return true;
                            }
                        }
                    }
                }
                catch
                {
                    continue;
                }
            }
            return false;
        }

        public void Dispose()
        {
            if (!CancellationTokenSource.IsCancellationRequested)
            {
                CancellationTokenSource.Cancel();
            }
            if (_windows && _watcher != null)
            {
                StopWindowsAntiSniff();
            }
        }
    }
}
