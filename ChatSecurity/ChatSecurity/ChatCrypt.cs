using System;
using System.Text;
using System.Xml.Serialization;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IO;

namespace ChatSecurity
{
    /**
     * Helper class used for RSA encryption
     * 
     * @author Mikael Holmbom
     * @version 1.0
     */
    public class ChatCrypt
    {
        private RSACryptoServiceProvider _rsacsp = new RSACryptoServiceProvider(2048);
        
        // collection of other ChatCrypt public keys         
        private Dictionary<string, RSAParameters> _cryptKeys = new Dictionary<string, RSAParameters>();

        public ChatCrypt(){
           
        }

        /**
         * get this public crypt key as string
         */
        public string PublicKeyString { get {
                var _publicKey = _rsacsp.ExportParameters(false);
                
                var sw = new StringWriter();
                var xs = new XmlSerializer(typeof(RSAParameters));
                xs.Serialize(sw, _publicKey);

                return sw.ToString().Replace(Environment.NewLine, "");
            } }
        /**
         * add another ChatCrypts public key to use for encryption
         * @param pubKeyOwner
         * @param cryptKeyString the public 
         */
        public void AddCryptKey(string publicKeyOwner, string publicKey)
        {
            StringReader sr = new System.IO.StringReader(publicKey);
            XmlSerializer xs = new XmlSerializer(typeof(RSAParameters));
            RSAParameters pubkey = (RSAParameters)xs.Deserialize(sr);

            _cryptKeys.Add(publicKeyOwner, pubkey);
        }
        /**
         * remove a stored public key
         */
        public bool RemoveCryptKey(string publicKeyOwner)
        {
            return _cryptKeys.Remove(publicKeyOwner);
        }

        /**
         * Decrypt a plainText, encrypted by this ChatCrypts public key
         * @param plainText plainText to decrypt
         * @return the plainText, decrypted
         */
        public string Decrypt(string plainText)
        {
            byte[] plainBytes = Convert.FromBase64String(plainText);
            byte[] cipherBytes = _rsacsp.Decrypt(plainBytes, false);
            return Encoding.Unicode.GetString(cipherBytes);       
        }
        /**
         * crypt a plainText
         * @param publicKeyOwner requested key of public keys
         * @param plainText the plainText to encrypt
         * @return plainText encrypted
         */
        public string Crypt(string publicKeyOwner, string plainText)
        {
            RSAParameters rsap = new RSAParameters();
            // if publicKeyOwner found 
            if(! _cryptKeys.TryGetValue(publicKeyOwner, out rsap))
            {
                throw new ArgumentOutOfRangeException("Could not encrypt message");
            }

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            csp.ImportParameters(rsap);

            byte[] messageBytes = Encoding.Unicode.GetBytes(plainText);
            byte[] cipherBytes = csp.Encrypt(messageBytes, false);

            return Convert.ToBase64String(cipherBytes);
        }

    } // ! ChatCrypt
    
}
