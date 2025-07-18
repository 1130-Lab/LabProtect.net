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
            byte[] appenderTempKey = GenerateTempKey();
            IEnumerable<EncryptedModule> payload = new List<EncryptedModule>()
            {
                new EncryptedModule
                {
                    TempKey = calculatorTempKey,
                    Name = "MyCalculator.dll",
                    Data = GetEncryptedDll("Modules/MyCalculator.dll", calculatorTempKey)
                },
                new EncryptedModule
                {
                    TempKey = appenderTempKey,
                    Name = "MyStringAppender.dll",
                    Data = GetEncryptedDll("Modules/MyStringAppender.dll", appenderTempKey)
                }
            };
            return Ok(payload);
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
