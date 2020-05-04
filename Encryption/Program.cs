namespace Encryption
{
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

    class DatabaseParam
    {
        public DatabaseParam()
        {

        }
        public string _strCiphertext;
        public string _strIV;
        public string _strKey;

         public DatabaseParam(string StrCiphertext, string StrIV, string StrKey)
        {
            this._strCiphertext = StrCiphertext;
            this._strIV = StrIV;
            this._strKey = StrKey;
        }

    }
    class Program
    {
        protected const string at = "@";
        private static byte[] result;

        protected static byte[] ConvertToByteArray(string OurValue)
        {
            byte[] result;
            string[] cipherstring;
            cipherstring = OurValue.Split(char.Parse(at));
            Array.Resize(ref cipherstring, cipherstring.Length - 9);
            result = Array.ConvertAll(cipherstring, new Converter<string, byte>(StringToByte));
            return result;
        }
        protected static byte StringToByte(string value)
        {
            return byte.Parse(value);
        }
        protected static byte[] AddRemoveSalt(byte[] param,bool IfRemove)
        {
            if (IfRemove)
            {
                result = new byte[param.Length - 8];
                result = param;
            }
            else
            {
                byte[] salt = new byte[8];
                using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
                {
                    // Fill the array with a random value.
                    rngCsp.GetBytes(salt);
                    var arrayList = new List<byte>();
                    arrayList.AddRange(param);
                    arrayList.AddRange(salt);
                    result = arrayList.ToArray();
                }
            }
            return result;
        }
        //help function to create string from byte[]
        protected static string CreateString(byte[] param)
        {
            string result = null;
            byte[] parasalt = AddRemoveSalt(param,false);
            for (int i = 0; i < parasalt.Length; i++)
            {
                result += parasalt[i] + at;
            }
            return result;
        }

        static void Main(string[] args)
        {
            string plaintext = null;
            int _enterResult;


            Console.WriteLine("To get password from database enter 1 , to insert new password or update enter 2");
            _enterResult = Convert.ToInt32(Console.ReadLine());
            if (_enterResult == 2)
            {
                Console.WriteLine("Enter new password:\n");
                plaintext = Console.ReadLine();
            }
            switch (_enterResult)
            {
                case 1:
                    DatabaseParam databaseParam1 = new DatabaseParam();
                    databaseParam1 = DatabaseLayer.ReturnPassword();
                    EncryptionDetails encryptionDetails1 = new EncryptionDetails();
                    encryptionDetails1.ciphertext = ConvertToByteArray(databaseParam1._strCiphertext);
                    encryptionDetails1.iv = ConvertToByteArray(databaseParam1._strIV);
                    encryptionDetails1.key = ConvertToByteArray(databaseParam1._strKey);
                    plaintext = null;
                    plaintext = RijndaelEncryption.DecryptStringFromBytes(encryptionDetails1);
                    Console.WriteLine("So the password saved in Database is : \n {0}", plaintext);
                    Console.ReadLine();
                    break;
                case 2:
                    EncryptionDetails encryptionDetails2 = new EncryptionDetails();
                    encryptionDetails2 = RijndaelEncryption.EncryptStringToBytes(plaintext);
                    DatabaseParam databaseParam2 = new DatabaseParam(CreateString(encryptionDetails2.ciphertext),
                    CreateString(encryptionDetails2.iv),
                    CreateString(encryptionDetails2.key));
                    DatabaseLayer.InsertUpdatePassword(databaseParam2);
                    break;
                default:
                    Console.WriteLine("Please enter corect number");
                    break;
            }

        }


    }

}
