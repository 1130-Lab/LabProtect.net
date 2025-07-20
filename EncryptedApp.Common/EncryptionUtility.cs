using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EncryptedApp.Common
{
    public class EncryptionUtility
    {
        private static readonly int _keySize = 32; // 256 bits for AES-256
        private static readonly int _saltSize = 32;
        private static readonly int _nonceSize = AesGcm.NonceByteSizes.MaxSize;
        private static readonly int _tagSize = AesGcm.TagByteSizes.MaxSize;

        public static byte[] EncryptBytesAes(byte[] bytes, byte[] password, bool clearKey = true)
        {
            try
            {
                if (password == null)
                    throw new Exception("Password is not set.");

                int cipherSize = bytes.Length;
                byte[] output = new byte[_saltSize + _nonceSize + _tagSize + cipherSize];
                using var outputStream = new MemoryStream(output);

                var salt = GenerateSalt();
                outputStream.Write(salt, 0, _saltSize);

                byte[] nonce = new byte[_nonceSize]; // 12 bytes recommended for GCM
                RandomNumberGenerator.Fill(nonce);
                outputStream.Write(nonce, 0, _nonceSize);

                byte[] tag = new byte[_tagSize]; // 128-bit tag

                using var keyDeriver = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
                byte[] key = keyDeriver.GetBytes(_keySize); // SHA256
                byte[] ciphertext = new byte[bytes.Length];
                using (var aesGcm = new AesGcm(key, _tagSize))
                {
                    aesGcm.Encrypt(nonce, bytes, ciphertext, tag);
                }
                outputStream.Write(tag, 0, _tagSize);
                outputStream.Write(ciphertext, 0, ciphertext.Length);

                return output;
            }
            finally
            {
                if(clearKey)
                {
                    Array.Clear(password, 0, password.Length);
                    GC.Collect();
                }
            }
        }

        public static byte[]? DecryptBytesAes(byte[] input, byte[] password, bool clearKey = true)
        {
            try
            {
                if (password == null)
                    throw new Exception("Password is not set.");

                using var bs = new MemoryStream(input);

                byte[] salt = new byte[_saltSize];
                bs.ReadExactly(salt);

                byte[] nonce = new byte[_nonceSize];
                bs.ReadExactly(nonce);

                byte[] tag = new byte[_tagSize];
                bs.ReadExactly(tag);

                byte[] ciphertext = new byte[bs.Length - salt.Length - nonce.Length - tag.Length];
                bs.ReadExactly(ciphertext);

                using var keyDeriver = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
                byte[] key = keyDeriver.GetBytes(_keySize);
                byte[] bytes = new byte[ciphertext.Length];
                using (var aesGcm = new AesGcm(key, _tagSize))
                {
                    aesGcm.Decrypt(nonce, ciphertext, tag, bytes);
                }

                return bytes;
            }
            catch { return null; }
            finally
            {
                if (clearKey)
                {
                    Array.Clear(password, 0, password.Length);
                    GC.Collect();
                }
            }
        }

        public static (bool success, T? result) TryDeserialize<T>(string data)
        {
            try
            {
                T result = JsonSerializer.Deserialize<T>(data) ?? throw new JsonException("Deserialization returned null.");
                return (true, result);
            }
            catch (Exception)
            {
                return (false, default);
            }
        }

        private static byte[] GenerateSalt()
        {
            byte[] salt = new byte[_saltSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);
            return salt;
        }
    }
}
