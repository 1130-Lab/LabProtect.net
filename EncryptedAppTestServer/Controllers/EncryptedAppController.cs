using EncryptedApp.Common;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace EncryptedAppTestServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class EncryptedAppController : ControllerBase
    {
        private readonly ILogger<EncryptedAppController> _logger;

        public EncryptedAppController(ILogger<EncryptedAppController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Get()
        {
            byte[] calculatorTempKey = GenerateTempKey();
            byte[] calculatorChecksumTempKey = GetClientChecksumKey(calculatorTempKey);
            byte[] appenderTempKey = GenerateTempKey();
            byte[] appenderChecksumTempKey = GetClientChecksumKey(appenderTempKey);
            IEnumerable<EncryptedModule> payload = new List<EncryptedModule>()
            {
                new EncryptedModule
                {
                    TempKey = calculatorChecksumTempKey,
                    Name = "MyCalculator.dll",
                    Data = GetEncryptedDll("Modules/MyCalculator.dll", calculatorTempKey)
                },
                new EncryptedModule
                {
                    TempKey = appenderChecksumTempKey,
                    Name = "MyStringAppender.dll",
                    Data = GetEncryptedDll("Modules/MyStringAppender.dll", appenderTempKey)
                }
            };
            return Ok(payload);
        }

        private byte[] GetClientChecksumKey(byte[] tempKey)
        {
            byte[] checksum = System.IO.File.ReadAllBytes("Modules/checksum.bin");
            return EncryptionUtility.EncryptBytesAes(tempKey, checksum);
        }

        private byte[] GetEncryptedDll(string dll, byte[] tempKey)
        {
            byte[] myCalculator = System.IO.File.ReadAllBytes(dll);
            return EncryptionUtility.EncryptBytesAes(myCalculator, tempKey, false);
        }

        private static byte[] GenerateTempKey()
        {
            using var aes = Aes.Create();
            aes.GenerateKey();
            return aes.Key;
        }
    }
}
