namespace EncryptedApp.Common
{
    public class EncryptedModule
    {
        public required byte[] TempKey { get; set; }
        public required string Name { get; set; }
        public required byte[] Data { get; set; }
    }
}
