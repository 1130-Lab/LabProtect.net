using AntiCrack_DotNet;
using EncryptedApp.Common;
using EncryptedApp.Common.AntiCrack_DotNet;
using System.Net.Http.Json;
using System.Reflection;

namespace EncryptedAppTest
{
    internal class Program
    {
        private static Dictionary<string, Assembly> _loadedAssemblies = new Dictionary<string, Assembly>();
        private static CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private static IAntiCrackMonitor _antiSniff = new AntiSniff(_cancellationTokenSource);
        private static IAntiCrackMonitor _antiDebug = new AntiDebug(_cancellationTokenSource);
        private static string _httpsAddress = "https://localhost:7046/";

        static async Task Main(string[] args)
        {
            _antiSniff.Start();
            _antiSniff.OnDetected += (source) =>
            {
                Console.WriteLine($"Anti-sniff detected! Source: {source}. Exiting...");
                Environment.Exit(1);
            };
#if !DEBUG
            _antiDebug.Start();
            _antiDebug.OnDetected += (source) =>
            {
                Console.WriteLine($"Anti-debug detected! Source: {source}. Exiting...");
                Environment.Exit(1);
            };
#endif 

            ParseArgs(args);
            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri(_httpsAddress);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            Console.WriteLine("Downloading modules...");
            var result = await client.GetAsync("EncryptedApp");
            Console.WriteLine("Modules downloaded.");
            if (result.IsSuccessStatusCode)
            {
                byte[] checksum = EncryptionUtility.GetSHA512ChecksumSubsampledFromFolder(Directory.GetCurrentDirectory(), 50, 65536);
                List<EncryptedModule>? modules = await result.Content.ReadFromJsonAsync<List<EncryptedModule>>();
                if (modules != null)
                {
                    for(int i = 0; i < modules.Count(); i++)
                    {
                        EncryptedModule module = modules[i];
                        if (File.Exists(module.Name))
                        {
                            File.Delete(module.Name);
                        }
                        byte[] decryptedChecksumKey = EncryptionUtility.DecryptBytesAes(module.TempKey, checksum, i == modules.Count - 1) ?? throw new Exception("Failed to decrypt checksum key.");
                        byte[] decryptedData = EncryptionUtility.DecryptBytesAes(module.Data, decryptedChecksumKey) ?? throw new Exception("Failed to decrypt module data.");
                        if (decryptedData != null)
                        {
                            var assembly = Assembly.Load(decryptedData);
                            _loadedAssemblies.Add(assembly.FullName!, assembly);
                            Console.WriteLine($"Decrypted and saved: {module.Name}");
                        }
                        else
                        {
                            Console.WriteLine($"Failed to decrypt: {module.Name}");
                        }
                    }
                }
            }
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                return _loadedAssemblies[args.Name];
            };
            Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
            foreach (var assembly in assemblies.Where(t => t.FullName!.Contains("System") == false && t.FullName.Contains("Microsoft") == false))
            {
                Console.WriteLine($"Loaded assembly: {assembly.GetName().Name}");
            }
            MyEncryptedApp app = new MyEncryptedApp();
            app.Run();
            Console.WriteLine("Secure application manager started.");
            Console.WriteLine("Press any key to exit...");
            Console.ReadLine();
            _cancellationTokenSource.Cancel();
        }

        private static void ParseArgs(string[] args)
        {
            foreach (var arg in args)
            {
                string[] parts = arg.Split('=');
                switch(parts[0])
                {
                    case "--dumpchecksumf":
                        byte[] checksumFilebased = EncryptionUtility.GetSHA512ChecksumSubsampledFromFolder(Directory.GetCurrentDirectory(), 50, 65536);
                        File.WriteAllBytes("checksum.bin", checksumFilebased);
                        break;
                    case "--dumpchecksum":
                        byte[] checksumRuntime = EncryptionUtility.GetSHA512Checksum();
                        File.WriteAllBytes("checksum.bin", checksumRuntime);
                        break;
                    case "--address":
                        if(parts.Length > 1)
                        {
                            _httpsAddress = parts[1];
                        }
                        break;
                }
            }
        }
    }

    public class MyEncryptedApp
    {
        private int _myResult;
        private string? _myString;
        public void Run()
        {
            _myString = new MyStringAppender.MyStringAppender().AppendStrings("Hello,");
            Console.WriteLine($"MyStringAppender result: {_myString}");
            _myResult = new MyCalculator.Calculator().Add(1, 2);
            Console.WriteLine($"MyCalculator result: {_myResult}");
        }
    }
}
