using AntiCrack_DotNet;
using System.Diagnostics;
using System.Management;

namespace EncryptedApp.Common.AntiCrack_DotNet
{
    public sealed class AntiSniff : IAntiCrackMonitor
    {
        private static SemaphoreSlim _taskLock = new SemaphoreSlim(1, 1);
        private HashSet<string> _badWindowNames = new HashSet<string>()
        {
            "wireshark",       // Wireshark
            "tcpdump",         // Tcpdump
            "npcap",           // Npcap
            "tshark",          // TShark
            "etherape",        // EtherApe
            "ettercap",        // Ettercap
            "kismet",          // Kismet
            "netsniff-ng",     // Netsniff-ng
            "snort",           // Snort
            "suricata",        // Suricata
            "zeek",            // Zeek (formerly Bro)
            "dumpcap",         // Dumpcap (used by Wireshark)
            "windump",         // WinDump (Windows port of tcpdump)
            "smartshark",      // SmartShark
            "cloudshark",      // CloudShark
            "omnipeek",        // OmniPeek
            "commview",        // CommView
            "packetyzer",      // Packetyzer
            "capsa",           // Capsa Network Analyzer
            "observer",        // Observer Analyzer
            "charles",         // Charles Proxy
            "fiddler",         // Fiddler
            "mitmproxy",       // mitmproxy
            "paros",           // Paros Proxy
            "burpsuite",       // Burp Suite
            "netscout",        // NetScout
            "netmon",          // Microsoft Network Monitor
            "networkminer",    // NetworkMiner
            "openwips-ng",     // OpenWIPS-ng
            "aircrack-ng",     // Aircrack-ng
            "airodump-ng",     // Airodump-ng
            "airoscript-ng"   // Airoscript-ng
        };
        private readonly bool _windows = OperatingSystem.IsWindows();

        public Action<string>? OnDetected { get; set; }
        public CancellationTokenSource CancellationTokenSource { get; }


        public AntiSniff(CancellationTokenSource source)
        {
            CancellationTokenSource = source ?? throw new ArgumentNullException(nameof(source));
        }

        public async Task PerformChecks(int timeInterval)
        {
            while (!CancellationTokenSource.IsCancellationRequested)
            {
                await _taskLock.WaitAsync(CancellationTokenSource.Token);
                try
                {
                    if (FindCrossPlatformAntiSniff())
                    {
                        OnDetected?.Invoke(nameof(FindCrossPlatformAntiSniff));
                    }
                }
                finally
                {
                    _taskLock.Release();
                }
                await Task.Delay(timeInterval, CancellationTokenSource.Token);
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
                                OnDetected?.Invoke(nameof(FindCrossPlatformAntiSniff));
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
        }
    }
}
