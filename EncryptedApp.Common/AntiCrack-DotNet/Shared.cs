using System.Diagnostics;

namespace AntiCrack_DotNet
{
    internal class Shared
    {
        private static SemaphoreSlim _moduleFetchLock = new SemaphoreSlim(1, 1);
        private static List<ProcessModule>? _modules = null;
        internal static List<ProcessModule> Modules
        {
            get
            {
                _moduleFetchLock.Wait();
                try
                {
                    if (_modules == null)
                    {
                        _modules = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().ToList();
                    }
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
