using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GenCode
{
    public class Code
    {
        static Encoding _encoding;
        static Code()
        {
            _encoding = new UTF8Encoding(false, true);
        }
        public static int GetCode(string securityStamp, string phoneNumber)
        {
            var bytes = Encoding.Unicode.GetBytes(securityStamp);

            var purpose = "PhoneCode";
            var modifier = "PhoneNumber:" + purpose + ":" + phoneNumber;

            int code = GenerateCode(bytes, modifier);
            return code;
        }

        public static int GenerateCode(byte[] bytes, string modifier = null)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }
            ulong currentTimeStepNumber = GetCurrentTimeStepNumber(false);
            using (HMACSHA1 hmacsha = new HMACSHA1(bytes))
            {
                return ComputeTotp(hmacsha, currentTimeStepNumber, modifier);
            }
        }

        private static ulong GetCurrentTimeStepNumber(bool useJumboTimestep)
        {
            var _unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var _timestep = TimeSpan.FromSeconds(30.0);
            var _jumboTimestep = TimeSpan.FromMinutes(5.0);

            TimeSpan span = (TimeSpan)(DateTime.UtcNow - _unixEpoch);
            TimeSpan span2 = useJumboTimestep ? _jumboTimestep : _timestep;
            return (ulong)(span.Ticks / span2.Ticks);
        }

        private static int ComputeTotp(HashAlgorithm hashAlgorithm, ulong timestepNumber, string modifier)
        {
            byte[] bytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((long)timestepNumber));
            byte[] buffer2 = hashAlgorithm.ComputeHash(ApplyModifier(bytes, modifier));
            int index = buffer2[buffer2.Length - 1] & 15;
            int num2 = ((((buffer2[index] & 127) << 24) | ((buffer2[index + 1] & 255) << 16)) | ((buffer2[index + 2] & 255) << 8)) | (buffer2[index + 3] & 255);
            return (num2 % 1000000);
        }

        private static byte[] ApplyModifier(byte[] input, string modifier)
        {
            if (string.IsNullOrEmpty(modifier))
            {
                return input;
            }
            byte[] bytes = _encoding.GetBytes(modifier);
            byte[] dst = new byte[input.Length + bytes.Length];
            Buffer.BlockCopy(input, 0, dst, 0, input.Length);
            Buffer.BlockCopy(bytes, 0, dst, input.Length, bytes.Length);
            return dst;
        }

    }
    
    class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                var code = Code.GetCode("53f8306a-96d0-40f1-b9d0-991b3fa7afec", "123");
                Console.WriteLine("[{1}] Code: {0}", code, DateTime.Now);
                Thread.Sleep(10000);
            }
        }
    }
}
