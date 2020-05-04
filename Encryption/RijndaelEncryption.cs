namespace Encryption
{
using System.IO;
using System.Security.Cryptography;

	internal  class RijndaelEncryption
	{

		public static EncryptionDetails EncryptStringToBytes(string plainText)
		{
			byte[] encrypted;
			EncryptionDetails encryptionDetails = new EncryptionDetails();
			using (RijndaelManaged rijAlg = new RijndaelManaged())
			{
				
				rijAlg.GenerateIV();
				rijAlg.GenerateKey();
			 // Create an encryptor to perform the stream transform.
				ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

				// Create the streams used for encryption.
				using (MemoryStream msEncrypt = new MemoryStream())
				{
					using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
						{

							//Write all data to the stream.
							swEncrypt.Write(plainText);
						}
						encrypted = msEncrypt.ToArray();
					}
				}
				encryptionDetails.ciphertext = encrypted;
				encryptionDetails.iv = rijAlg.IV;
				encryptionDetails.key=rijAlg.Key;
			}

			return encryptionDetails;

		}

		public static string DecryptStringFromBytes(EncryptionDetails encryptionDetails)
		{
			string plaintext = null;
			
			using (RijndaelManaged rijAlg = new RijndaelManaged())
			{

				// Create a decryptor to perform the stream transform.
				ICryptoTransform decryptor = rijAlg.CreateDecryptor(encryptionDetails.key, encryptionDetails.iv);

				// Create the streams used for decryption.
				using (MemoryStream msDecrypt = new MemoryStream(encryptionDetails.ciphertext))
				{
					using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
					{
						using (StreamReader srDecrypt = new StreamReader(csDecrypt))
						{
							// Read the decrypted bytes from the decrypting stream
							// and place them in a string.
							plaintext = srDecrypt.ReadToEnd();
						}
					}
				}

			}

			return plaintext;

		}
	}
	public class EncryptionDetails
	{
		public byte[] ciphertext;
		public byte[] iv;
		public byte[] key;
		public string plaintext;
	}

}

				
		