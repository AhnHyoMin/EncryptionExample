using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Security.Cryptography;


namespace EncryptionExample
{
    class Program
    {
        private static SHA256Managed sha256Managed = new SHA256Managed();
        private static int m_KeySize = 256;
        private static int m_ivSize = 128;

        // 암호키
        private static string m_KEY = "zzzz";

        /// <summary>
        /// 반복 횟수
        /// </summary>
        private static int m_pwIterations = 100;

        static  string _Test = "100000001;Speed_f;0;0.567;1;Leg\r\n100000001; Animation_int;1;1.333;1;AllBody\r\n100000001; Animation_int;2;0.800;1;AllBody\r\n100000001; Animation_int;3;1.300;1;AllBody\r\n100000001; Animation_int;4;1.933;1;AllBody\r\n100000001; Animation_int;5;1.633;1;AllBody\r\n100000001; Animation_int;6;2.800;1;AllBody";


        static void Main(string[] args)
        {


            string _Str = Encryptor(_Test, m_KEY);
            Console.WriteLine("_Str :" + _Str);
            _Str =  Decryptor(_Str, m_KEY);
            Console.WriteLine("_Str :" + _Str);
        }

        /// <summary>
        ///  암호화
        /// </summary>
        /// <param name="_String"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string Encryptor(string _String, string password)
        {
            // 해시값 생성
            var salt = sha256Managed.ComputeHash(Encoding.UTF8.GetBytes(password.Length.ToString()));

            Aes _Aes = Aes.Create();

            // 비밀키 사이즈 세팅
            _Aes.KeySize = m_KeySize;
            // 암호화 작업 블록 사이즈
            _Aes.BlockSize = m_ivSize;

            _Aes.Mode = CipherMode.CBC;
            _Aes.Padding = PaddingMode.PKCS7;


            var key = new Rfc2898DeriveBytes(password, salt, m_pwIterations);

            // 대칭 알고리증에 대한 시크릿 키
            var _SecretKey = key.GetBytes(_Aes.KeySize / 8);
            // 대칭 알고리증에 대한 초기화 백터 
            var _Iv = key.GetBytes(_Aes.BlockSize / 8);
     
            // 암호기 생성
            ICryptoTransform _Encryptor = _Aes.CreateEncryptor(_SecretKey, _Iv);

            // Unicode로 인코딩
            byte[] _Data = Encoding.Unicode.GetBytes(_String);         

             _Data = _Encryptor.TransformFinalBlock(_Data, 0, _Data.Length);

            //8비트 부호 없는 정수로 구성된 배열을 base-64 숫자로 인코딩된 해당하는 문자열 표현으로 변환
            string _Text = System.Convert.ToBase64String(_Data);
      
         
            return _Text;


        }

        public static string Decryptor(string _String, string password)
        {
            // 해시값 생성
            var salt = sha256Managed.ComputeHash(Encoding.UTF8.GetBytes(password.Length.ToString()));

            Aes _Aes = Aes.Create();

            // 비밀키 사이즈 세팅
            _Aes.KeySize = m_KeySize;
            // 암호화 작업 블록 사이즈
            _Aes.BlockSize = m_ivSize;

            _Aes.Mode = CipherMode.CBC;
            _Aes.Padding = PaddingMode.PKCS7;

            var key = new Rfc2898DeriveBytes(password, salt, m_pwIterations);
            // 대칭 알고리증에 대한 시크릿 키
            var secretKey = key.GetBytes(_Aes.KeySize / 8);
            // 대칭 알고리증에 대한 초기화 백터 
            var iv = key.GetBytes(_Aes.BlockSize / 8);
            // 해독기 생성
            ICryptoTransform _Decryptor = _Aes.CreateDecryptor(secretKey, iv);

            // base-64 숫자의 이진 데이터를 해당하는 8비트 부호 없는 정수 배열로 인코딩하는 방법으로 지정된 문자열을 변환한다.
            byte[] _Data = Convert.FromBase64String(_String);
        
            _Data = _Decryptor.TransformFinalBlock(_Data, 0, _Data.Length);

            // Unicode로 인코딩
            string _str = Encoding.Unicode.GetString(_Data);          
            return _str;
        }
    }
}
