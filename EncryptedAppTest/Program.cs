using EncryptedApp.Common;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;

namespace EncryptedAppTest
{
    internal class Program
    {
        private static Dictionary<string, Assembly> _loadedAssemblies = new Dictionary<string, Assembly>();
        private static SecureApplicationManager _secureApp = new SecureApplicationManager(false, false, false, false, false, false, false, true);
        private static CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private static Task? _secureAppChecker;
        private static string _httpsAddress = "https://localhost:7046/";

        static async Task Main(string[] args)
        {
            ParseArgs(args);
            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri(_httpsAddress);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            Console.WriteLine("Downloading modules...");
            var result = await client.GetAsync("EncryptedApp");
            Console.WriteLine("Modules downloaded.");
            if (result.IsSuccessStatusCode)
            {
                byte[] checksum = GetSHA512Checksum();
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
            _secureAppChecker = Task.Run(() => _secureApp.Run(_cancellationTokenSource), _cancellationTokenSource.Token);
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
                    case "--dumpchecksum":
                        byte[] checksum = GetSHA512Checksum();
                        File.WriteAllBytes("checksum.bin", checksum);
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

        private static byte[] GetSHA512Checksum()
        {
            byte[] bytes = File.ReadAllBytes($"{Assembly.GetExecutingAssembly().GetName().Name}.exe");
            using (SHA512 sha = SHA512.Create())
            {
                return sha.ComputeHash(bytes);
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
