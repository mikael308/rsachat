using System;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using ChatSecurity;

namespace ChatClient
{

    public partial class Form1 : Form
    {
        // crypt handler
        private ChatCrypt chatCrypt;
        
        // Will hold the user name
        private string UserName = "Unknown";
        private StreamWriter swSender;
        private StreamReader srReceiver;
        private TcpClient tcpServer;
        // Needed to update the form with messages from another thread
        private delegate void UpdateLogCallback(string strMessage);
        // Needed to set the form to a "disconnected" state from another thread
        private delegate void CloseConnectionCallback(string strReason);
        private Thread thrMessaging;
        private IPAddress ipAddr;
        private bool Connected;
        // flags used to determine response from server
        private static readonly string FLAG_GRANTED = "1";
        private static readonly string FLAG_DENIED = "0";

        public Form1()
        {
            // On application exit, don't forget to disconnect first
            Application.ApplicationExit += new EventHandler(OnApplicationExit);
            InitializeComponent();
        }

        // The event handler for application exit
        public void OnApplicationExit(object sender, EventArgs e)
        {
            if (Connected == true)
            {
                // Closes the connections, streams, etc.
                Connected = false;
                swSender.Close();
                srReceiver.Close();
                tcpServer.Close();
            }
        }

        private void btnConnect_Click(object sender, EventArgs e)
        {
            try
            {
                // If we are not currently connected but awaiting to connect
                if (Connected == false)
                {
                    // Initialize the connection
                    initializeConnection();
                }
                else // We are connected, thus disconnect
                {
                    closeConnection("Disconnected at user's request.");
                }
            }catch(SocketException se)
            {
                updateLog(se.Message);
            }
        }

        private void initializeConnection()
        {
            // Parse the IP address from the TextBox into an IPAddress object
            ipAddr = IPAddress.Parse(txtIp.Text);
            // Start a new TCP connections to the chat server
            tcpServer = new TcpClient();
            tcpServer.Connect(ipAddr, 1986);
            chatCrypt = new ChatCrypt();
            
            // Prepare the form
            UserName = txtUser.Text;

            swSender = new StreamWriter(tcpServer.GetStream());
            
            // Start the thread for receiving messages and further communication
            thrMessaging = new Thread(() =>
            {
                try
                {
                    if (setupConnection())
                    {
                        receiveMessage();
                    }
                        
                } catch(Exception e)
                {
                    this.Invoke(new UpdateLogCallback(this.updateLog), new object[] {
                        e.Message });
                }
            });
            thrMessaging.Start();
        }
        private void receiveMessage()
        {
            try
            {
                // While we are successfully connected, read incoming lines from the server
                while (Connected)
                {
                    string msg = chatCrypt.Decrypt(srReceiver.ReadLine());

                    // Show the decrypted messages in the log TextBox
                    this.Invoke(new UpdateLogCallback(this.updateLog), new object[] { msg });
                }
            }
            catch (IOException e)
            {
            }
        }
        private bool setupConnection()
        {
            // Receive the response from the server
            srReceiver = new StreamReader(tcpServer.GetStream());
            // send username and clients public cryptkey
            string setupMsg = txtUser.Text + "|" + chatCrypt.PublicKeyString;
            swSender.WriteLine(setupMsg);
            swSender.Flush();

            // If the first character of the response is 1, connection was successful
            string[] con_resp = srReceiver.ReadLine().Split('|');
            // If the first character is a 1, connection was successful
            if (con_resp[0] == FLAG_GRANTED)
            {
                // receive servers public key
                chatCrypt.AddCryptKey("server", con_resp[1]);

                // send user/password to server
                string password = txtPassword.Text;
                string loginMsg = this.UserName + "|" + password;
                loginMsg = chatCrypt.Crypt("server", loginMsg);

                swSender.WriteLine(loginMsg);
                swSender.Flush();
                
                // answer from server if user/password is granted
                string resp = srReceiver.ReadLine();
                resp = chatCrypt.Decrypt(resp);
                
                string[] login_resp = resp.Split('|');
                // Update the form to tell connect status
                if (login_resp[0].Equals(FLAG_GRANTED))
                {
                    Connected = true;
                    this.Invoke(new UpdateLogCallback(this.updateLog), new object[] { login_resp[1] });
                    this.Invoke((MethodInvoker) delegate {
                        // Disable and enable the appropriate fields
                        formChatEnabledView(true);
                    });
                    return true;
                }
                else if (login_resp[0].Equals(FLAG_DENIED))
                {
                    this.Invoke(new UpdateLogCallback(this.updateLog), new object[] { login_resp[1] });
                }

                return false;
            }
            else // If the first character is not a 1 (probably a 0), the connection was unsuccessful
            {
                string Reason = "Not Connected: ";
                // Extract the reason out of the response message. The reason starts at the 3rd character
                Reason += con_resp[1];//.Substring(2, ConResponse.Length - 2);
                // Update the form with the reason why we couldn't connect
                this.Invoke(new CloseConnectionCallback(this.closeConnection), new object[] { Reason });
                return false;
            }
            
        }

        // This method is called from a different thread in order to update the log TextBox
        private void updateLog(string strMessage)
        {
            // Append text also scrolls the TextBox to the bottom each time
            txtLog.AppendText(strMessage + "\r\n");
        }
        
        // Closes a current connection
        private void closeConnection(string Reason)
        {
            // Show the reason why the connection is ending
            txtLog.AppendText(Reason + "\r\n");
            // Enable and disable the appropriate controls on the form
            formChatEnabledView(false);

            // Close the objects
            Connected = false;
            swSender.Close();
            srReceiver.Close();
            tcpServer.Close();
        }

        // Sends the message typed in to the server
        private void sendMessage()
        {
            if (txtMessage.Lines.Length < 1)
            {
                return;
            }
            try
            {
                string cryptMsg = chatCrypt.Crypt("server", txtMessage.Text);
                    
                // send crypted message
                swSender.WriteLine(cryptMsg);
                swSender.Flush();
                txtMessage.Lines = null;
                    
            }catch(Exception e)
            {
                updateLog(e.Message);
            } 

            txtMessage.Text = "";
        }

        // We want to send the message when the Send button is clicked
        private void btnSend_Click(object sender, EventArgs e)
        {
            sendMessage();
        }

        // But we also want to send the message once Enter is pressed
        private void txtMessage_KeyPress(object sender, KeyPressEventArgs e)
        {
            // If the key is Enter
            if (e.KeyChar == (char)13)
            {
                sendMessage();
            }
        }

        /**
         * sets gui to chat state
         * @param b new enable chat value
         */
        private void formChatEnabledView(bool b)
        {
            txtIp.Enabled = !b ;
            txtUser.Enabled = !b;
            txtPassword.Enabled = !b;
            txtMessage.Enabled = b;
            btnSend.Enabled = b;
            btnConnect.Text = b ? "Disconnect" : "Connect";
        }
    }
}