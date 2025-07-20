using AntiCrack_DotNet;
using System.Diagnostics;
using System.Management;

namespace EncryptedApp.Common.AntiCrack_DotNet
{
    public sealed class AntiSniff
    {


        /// <summary>
        /// Checks for the presence of known debugger windows.
        /// Requires elevated permissions.
        /// </summary>
        /// <returns>Returns true if a known debugger window is detected, otherwise false.</returns>
        private static HashSet<string> _badWindowNames = new HashSet<string>() { "wireshark", "tcpdump", "npcap", "tshark" };
        private static bool _windowAntiSniffInitialized = false;
        private static bool _windowAntiSniffEnabled = false;
        private static ManagementEventWatcher? _watcher;
        public static bool FindWindowAntiSniff()
        {
            if (OperatingSystem.IsWindows() == false)
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
                                    GetWindow.Kill();
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
            }
            else if (OperatingSystem.IsWindows() && !_windowAntiSniffInitialized)
            {
                var startQuery = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
                _watcher = new ManagementEventWatcher(startQuery);
                _watcher.EventArrived += (s, e) =>
                {
                    string processName = e.NewEvent.Properties["ProcessName"].Value.ToString();

                    foreach (string BadWindows in _badWindowNames)
                    {
                        if (Utils.Contains(processName!, BadWindows))
                        {
                            _windowAntiSniffEnabled = true;
                        }
                    }
                };
                _watcher.Start();

                Process[] GetProcesses = Process.GetProcesses();
                foreach (Process getWindow in GetProcesses)
                {
                    try
                    {
                        if (getWindow.MainWindowHandle != IntPtr.Zero)
                        {
                            string title = getWindow.MainWindowTitle;
                            if (string.IsNullOrEmpty(title)) continue;

                            foreach (string BadWindows in _badWindowNames)
                            {
                                if (Utils.Contains(title, BadWindows))
                                {
                                    getWindow.Kill();
                                    _windowAntiSniffEnabled = true;
                                }
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            return _windowAntiSniffEnabled;
        }
    }
}
