namespace UnencryptedAppTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            MyEncryptedApp app = new MyEncryptedApp();
            app.Run();
            Console.WriteLine("Press any key to exit...");
            Console.ReadLine();
        }
    }

    public class MyEncryptedApp
    {
        private int _myResult;
        public string? _myString;
        public void Run()
        {
            _myString = new MyStringAppender.MyStringAppender().AppendStrings("Hello,");
            Console.WriteLine($"MyStringAppender result: {_myString}");
            _myResult = new MyCalculator.Calculator().Add(1, 2);
            Console.WriteLine($"MyCalculator result: {_myResult}");
        }
    }
}
