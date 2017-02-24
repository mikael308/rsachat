using System.Text;
using System.Xml;
using System.Security.Cryptography;

namespace ChatSecurity
{
    /**
     * class used to handle and validate encrypted password\n
     * uses SHA512 to crypt password
     * @author Mikael Holmbom
     * @version 1.0
     */
    public class PasswordHandler
    {
        // filename of file containing passwords
        private string filename;
        private XmlDocument xmlDoc;

        public PasswordHandler(string filename)
        {
            this.filename = filename;
            xmlDoc = new XmlDocument();
        }
        /**
         * encrypts input param as SHA512
         * @param plainText the text to encrypt
         * @return encrypted string - ciphertext
         */
        private string Crypt(string plainText)
        {
            SHA512CryptoServiceProvider sha512csp = new SHA512CryptoServiceProvider();
            byte[] hashBytes = sha512csp.ComputeHash(new UTF8Encoding().GetBytes(plainText));
            
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
                sb.Append(hashBytes[i].ToString("X2"));

            return sb.ToString();
        }
        /**
         * validates username with password
         * @param username username
         * @param password password
         * @return true if username/password is valid
         */
        public bool Validate(string username, string password)
        {
            try
            {
                xmlDoc.Load(filename);
                // the stored hashed password
                string passw = xmlDoc
                    .SelectSingleNode("//user[@name='"+username+"']")
                        .Attributes["password"].Value;
                
                return Crypt(password).Equals(passw);
            }
            catch
            {
            }
            return false;
        }
        
    } // ! PasswordHandler
}
