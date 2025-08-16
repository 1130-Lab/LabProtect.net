using System.Collections.Immutable;
using System.Data.SqlTypes;
using System.Reflection;
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

        /// <summary>
        /// Takes a seed value and optional sample size, then randomly selects bytes from each dll to generate the checksum.
        /// Useful for large assemblies where a full checksum would be too slow.
        /// </summary>
        /// <param name="folderPath"></param>
        /// <param name="seed"></param>
        /// <param name="sampleSize"></param>
        /// <param name="search"></param>
        /// <param name="filter"></param>
        /// <returns></returns>
        /// <exception cref="DirectoryNotFoundException"></exception>
        public static byte[] GetSHA512ChecksumSubsampledFromFolder(string folderPath, int seed, int sampleSize = 1024 * 1024 * 50, SearchOption search = SearchOption.AllDirectories, string filter = "*.dll")
        {
            Random rand = new Random(seed);
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"The directory '{folderPath}' does not exist.");
            var files = Directory.GetFiles(folderPath, filter, search).ToImmutableSortedSet();
            int totalBytes = 0;
            Dictionary<string, byte[]> samples = new Dictionary<string, byte[]>();
            object lockObj = new object();

            using (SHA512 sha = SHA512.Create())
            {
                var result = Parallel.ForEach(files, (assemblyFile) =>
                {
                    FileInfo info = new FileInfo(assemblyFile);
                    // If our file is more than int.MaxValue bytes, we clamp it to int.MaxValue.
                    int effectiveFileSize = info.Length > int.MaxValue ? int.MaxValue : (int)info.Length;
                    int bufferSize = (int)Math.Min(sampleSize, effectiveFileSize);
                    bool entireFile = bufferSize == effectiveFileSize;
                    byte[] buffer = new byte[bufferSize];

                    Interlocked.Add(ref totalBytes, bufferSize);

                    if (!entireFile)
                    {
                        using (var byteStream = new FileStream(assemblyFile, FileMode.Open, FileAccess.Read))
                        {
                            for (int i = 0; i < bufferSize; i++)
                            {
                                long start = rand.Next(0, effectiveFileSize);
                                byteStream.Seek(start, SeekOrigin.Begin);
                                int byteRead = byteStream.ReadByte();
                                buffer[i] = (byte)byteRead;
                            }
                        }
                    }
                    else
                    {
                        buffer = File.ReadAllBytes(assemblyFile);
                    }
                    lock (lockObj)
                    {
                        samples.Add(assemblyFile, buffer);
                    }
                });

                while (!result.IsCompleted && files.FirstOrDefault(t => samples.ContainsKey(t) == false) != null) ;
                
                byte[] allBytes = new byte[totalBytes];
                int offset = 0;
                // Read the samples and copy them to allBytes in definite order
                foreach (var assemblyFile in files)
                {
                    var sample = samples[assemblyFile];
                    Buffer.BlockCopy(sample, 0, allBytes, 0, sample.Length);
                    offset += sample.Length;
                }
                return sha.ComputeHash(allBytes);
            }
        }

        /// <summary>
        /// Incrementally computes the SHA512 checksum of all files in a folder.
        /// Useful for large folders where loading entire file into memory is impractical.
        /// </summary>
        /// <param name="folderPath"></param>
        /// <param name="sampleSize"></param>
        /// <param name="search"></param>
        /// <param name="filter"></param>
        /// <returns></returns>
        /// <exception cref="DirectoryNotFoundException"></exception>
        public static byte[] GetSHA512ChecksumIncrementalFromFolder(string folderPath, int sampleSize = 1024 * 1024, SearchOption search = SearchOption.AllDirectories, string filter = "*.dll")
        {
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"The directory '{folderPath}' does not exist.");
            var files = Directory.GetFiles(folderPath, filter, search).ToImmutableSortedSet();
            using (SHA512 sha = SHA512.Create())
            {
                foreach (var assemblyFile in files)
                {
                    byte[] buffer = new byte[sampleSize];
                    byte[] executableBytes = File.ReadAllBytes(assemblyFile);
                    int bytesRead = 0;
                    using (var stream = File.OpenRead(assemblyFile))
                    {
                        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            sha.TransformBlock(buffer, 0, bytesRead, null, 0);
                        }
                    }
                }
                return sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            }
        }

        public static byte[] GetSHA512ChecksumFromFolder(string folderPath, SearchOption search = SearchOption.AllDirectories, string filter = "*.dll")
        {
            if (!Directory.Exists(folderPath))
                throw new DirectoryNotFoundException($"The directory '{folderPath}' does not exist.");
            var files = Directory.GetFiles(folderPath, filter, search).ToImmutableSortedSet();
            int totalBytes = 0;
            Dictionary<string, byte[]> samples = new Dictionary<string, byte[]>();
            object lockObj = new object();
            var result = Parallel.ForEach(files, (assemblyFile) =>
            {
                byte[] buffer = File.ReadAllBytes(assemblyFile);

                Interlocked.Add(ref totalBytes, buffer.Length);

                lock (lockObj)
                {
                    samples.Add(assemblyFile, buffer);
                }
            });

            while (!result.IsCompleted && files.FirstOrDefault(t => samples.ContainsKey(t) == false) != null) ;
            byte[] allBytes = new byte[totalBytes];
            int offset = 0;
            // Read the samples and copy them to allBytes in definite order
            foreach (var assemblyFile in files)
            {
                var sample = samples[assemblyFile];
                Buffer.BlockCopy(sample, 0, allBytes, 0, sample.Length);
                offset += sample.Length;
            }

            using (SHA512 sha = SHA512.Create())
            {
                return sha.ComputeHash(allBytes);
            }
        }

        public static byte[] GetSHA512Checksum()
        {
            var assemblies = AppDomain.CurrentDomain.GetAssemblies().ToImmutableSortedSet();
            byte[]? allBytes = null;
            foreach (var assembly in assemblies)
            {
                string assemblyFile = $"{assembly.GetName().Name}.dll";
                if(!File.Exists(assemblyFile))
                {
                    continue; // Skip if the file does not exist
                }
                byte[] executableBytes = File.ReadAllBytes(assemblyFile);
                if(allBytes == null)
                {
                    allBytes = executableBytes;
                }
                else
                {
                    byte[] newBytes = new byte[allBytes.Length + executableBytes.Length];
                    Buffer.BlockCopy(allBytes, 0, newBytes, 0, allBytes.Length);
                    Buffer.BlockCopy(executableBytes, 0, newBytes, allBytes.Length, executableBytes.Length);
                    allBytes = newBytes;
                }
            }

            using (SHA512 sha = SHA512.Create())
            {
                return sha.ComputeHash(allBytes);
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
