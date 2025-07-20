using System.Diagnostics;

namespace AntiCrack_DotNet
{
    internal class Shared
    {
        private static SemaphoreSlim _moduleFetchLock = new SemaphoreSlim(1, 1);
        private static List<ProcessModule>? _modules = null;
        private static DateTime _lastFetchTimeUtc = DateTime.UtcNow;
        internal static List<ProcessModule> Modules
        {
            get
            {
                _moduleFetchLock.Wait();
                try
                {
                    if(_modules != null && DateTime.UtcNow - _lastFetchTimeUtc < TimeSpan.FromSeconds(1)) // Limit of one fetch per second.
                    {
                        return _modules ?? new List<ProcessModule>();
                    }
                    _modules = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().ToList();
                    return _modules;
                }
                finally
                {
                    _moduleFetchLock.Release();
                }
            }
        }
    }
}
