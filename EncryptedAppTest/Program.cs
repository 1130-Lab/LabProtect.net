using EncryptedApp.Common;
using System.Net.Http.Json;
using System.Reflection;

namespace EncryptedAppTest
{
    internal class Program
    {
        private static Dictionary<string, Assembly> _loadedAssemblies = new Dictionary<string, Assembly>();
        private static SecureApplicationManager _secureApp = new SecureApplicationManager();
        private static CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private static Task? _secureAppChecker;
        private int _myResult;
        private string? _myString;
        static async Task Main(string[] args)
        {
            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri("http://localhost:5000/");
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            Console.WriteLine("Downloading modules...");
            var result = await client.GetAsync("EncryptedApp");
            Console.WriteLine("Modules downloaded.");
            if (result.IsSuccessStatusCode)
            {
                IEnumerable<EncryptedModule>? modules = result.Content.ReadFromJsonAsync<IEnumerable<EncryptedModule>>().Result;
                if (modules != null)
                {
                    foreach (EncryptedModule module in modules)
                    {
                        if(File.Exists(module.Name))
                        {
                            File.Delete(module.Name);
                        }
                        byte[]? decryptedData = EncryptionUtility.DecryptBytesAes(module.Data, module.TempKey);
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
    }

    public class MyEncryptedApp
    {
        public void Run()
        {
            string myString = new MyStringAppender.MyStringAppender().AppendStrings("Hello,");
            Console.WriteLine($"MyStringAppender result: {myString}");
            int myResult = new MyCalculator.Calculator().Add(1, 2);
            Console.WriteLine($"MyCalculator result: {myResult}");
        }
    }
}
