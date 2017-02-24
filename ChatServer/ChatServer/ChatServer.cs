using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using System.Collections;
using ChatSecurity;

namespace ChatServer
{
    // Holds the arguments for the StatusChanged event
    public class StatusChangedEventArgs : EventArgs
    {
        // The argument we're interested in is a message describing the event
        private string EventMsg;

        // Property for retrieving and setting the event message
        public string EventMessage
        {
            get
            {
                return EventMsg;
            }
            set
            {
                EventMsg = value;
            }
        }

        // Constructor for setting the event message
        public StatusChangedEventArgs(string strEventMsg)
        {
            EventMsg = strEventMsg;
        }
    }

    // This delegate is needed to specify the parameters we're passing with our event
    public delegate void StatusChangedEventHandler(object sender, StatusChangedEventArgs e);

    class ChatServer
    {
        // the servers crypt helperobject
        private static ChatCrypt chatCrypt;
        private static PasswordHandler ph = new PasswordHandler("../../password.xml");
        // flags used to determine response from server
        public static readonly string FLAG_GRANTED = "1";
        public static readonly string FLAG_DENIED = "0";

        // maximum number of users connected to this server
        private static int maxUsers = 30;
        // This hash table stores users and connections (browsable by user)
        public static Hashtable htUsers = new Hashtable(maxUsers); // 30 users at one time limit
        // This hash table stores connections and users (browsable by connection)
        public static Hashtable htConnections = new Hashtable(maxUsers); // 30 users at one time limit
        // Will store the IP address passed to it
        private IPAddress ipAddress;
        private TcpClient tcpClient;
        // The event and its argument will notify the form when a user has connected, disconnected, send message, etc.
        public static event StatusChangedEventHandler StatusChanged;
        private static StatusChangedEventArgs e;

        // The constructor sets the IP address to the one retrieved by the instantiating object
        public ChatServer(IPAddress address)
        {
            ipAddress = address;
            chatCrypt = new ChatCrypt();
        }

        // The thread that will hold the connection listener
        private Thread thrListener;

        // The TCP object that listens for connections
        private TcpListener tlsClient;

        // Will tell the while loop to keep monitoring for connections
        bool ServRunning = false;

        // Add the user to the hash tables
        public static void AddUser(TcpClient tcpUser, string strUsername)
        {
            // Tell of the new connection to all other users and to the server form
            SendAdminMessage(strUsername + " has joined us");

            // First add the username and associated connection to both hash tables
            ChatServer.htUsers.Add(strUsername, tcpUser);
            ChatServer.htConnections.Add(tcpUser, strUsername);
                        
        }

        // Remove the user from the hash tables
        public static void RemoveUser(TcpClient tcpUser)
        {
            // If the user is there
            if (htConnections[tcpUser] != null)
            {
                string username = (string) htConnections[tcpUser];
                // First show the information and tell the other users about the disconnection
                SendAdminMessage(username + " has left us");

                // Remove the user from the hash table
                ChatServer.htUsers.Remove(ChatServer.htConnections[tcpUser]);
                ChatServer.htConnections.Remove(tcpUser);
                chatCrypt.RemoveCryptKey(username);
            }
        }

        // This is called when we want to raise the StatusChanged event
        public static void OnStatusChanged(StatusChangedEventArgs e)
        {
            StatusChangedEventHandler statusHandler = StatusChanged;
            if (statusHandler != null)
            {
                // Invoke the delegate
                statusHandler(null, e);
            }
        }

        // Send administrative messages
        public static void SendAdminMessage(string Message)
        {
            StreamWriter swSenderSender;

            // full message line to send 
            string sendMsg = "[Administrator]: " + Message;

            // First of all, show in our application who says what
            e = new StatusChangedEventArgs(sendMsg);
            OnStatusChanged(e);

            // Create an array of TCP clients, the size of the number of users we have
            TcpClient[] tcpClients = new TcpClient[ChatServer.htUsers.Count];
            // Copy the TcpClient objects into the array
            ChatServer.htUsers.Values.CopyTo(tcpClients, 0);
            // Loop through the list of TCP clients
            for (int i = 0; i < tcpClients.Length; i++)
            {
                // Try sending a message to each
                try
                {
                    // If the message is blank or the connection is null, break out
                    if (Message.Trim() == "" || tcpClients[i] == null)
                    {
                        continue;
                    }
                    
                    string receiverKey = (string)htConnections[tcpClients[i]];
                    string cryptMsg = chatCrypt.Crypt(receiverKey, sendMsg);
                    
                    // Send the message to the current user in the loop
                    swSenderSender = new StreamWriter(tcpClients[i].GetStream());
                    swSenderSender.WriteLine(cryptMsg);
                    swSenderSender.Flush();
                    swSenderSender = null;
                    
                    
                }
                catch // If there was a problem, the user is not there anymore, remove him
                {
                    RemoveUser(tcpClients[i]);
                }
            }
        }

        // Send messages from one user to all the others
        public static void SendMessage(string From, string Message)
        {
            StreamWriter swSenderSender;

            string decryptMsg = chatCrypt.Decrypt(Message);
            
            // is empty message -> dont send out
            if (decryptMsg.Trim() == "")
                return;

            // the message to send to receivers
            string sendMsg = "[" + From + "]: " + decryptMsg;

            // First of all, show in our application who says what
            e = new StatusChangedEventArgs(sendMsg);
            OnStatusChanged(e);

            // Create an array of TCP clients, the size of the number of users we have
            TcpClient[] tcpClients = new TcpClient[ChatServer.htUsers.Count];
            // Copy the TcpClient objects into the array
            ChatServer.htUsers.Values.CopyTo(tcpClients, 0);
            // Loop through the list of TCP clients
            for (int i = 0; i < tcpClients.Length; i++)
            {
                // Try sending a message to each
                try
                {
                    // If the connection is null, break out
                    if (tcpClients[i] == null)
                    {
                        continue;
                    }

                    string receiverKey = (string) htConnections[tcpClients[i]];
                    // crypt the message according to receivers public cryptkey
                    string cryptMsg = chatCrypt.Crypt(receiverKey, sendMsg);
                    
                    // Send the message to the current user in the loop
                    swSenderSender = new StreamWriter(tcpClients[i].GetStream());
                    swSenderSender.WriteLine(cryptMsg);
                    swSenderSender.Flush();
                    swSenderSender = null;
                    
                }
                catch // If there was a problem, the user is not there anymore, remove him
                {
                    RemoveUser(tcpClients[i]);
                }
            }
        }

        public void StartListening()
        {

            // Get the IP of the first network device, however this can prove unreliable on certain configurations
            IPAddress ipaLocal = ipAddress;

            // Create the TCP listener object using the IP of the server and the specified port
            tlsClient = new TcpListener(1986);

            // Start the TCP listener and listen for connections
            tlsClient.Start();

            // The while loop will check for true in this before checking for connections
            ServRunning = true;

            // Start the new tread that hosts the listener
            thrListener = new Thread(keepListening);
            thrListener.Start();
        }

        private void keepListening()
        {
            // While the server is running
            while (ServRunning == true)
            {
                // Accept a pending connection
                tcpClient = tlsClient.AcceptTcpClient();
                // Create a new instance of Connection
                Connection newConnection = new Connection(tcpClient, chatCrypt);
            }
        }
    }

    // This class handels connections; there will be as many instances of it as there will be connected users
    class Connection
    {
        TcpClient tcpClient;
        // The thread that will send information to the client
        private Thread thrSender;
        private StreamReader srReceiver;
        private StreamWriter swSender;
        private string currUser;
        private string strResponse;

        //private string cryptPublicKey;
        private ChatCrypt chatCrypt;
        private static PasswordHandler ph = new PasswordHandler("../../password.xml");

        // The constructor of the class takes in a TCP connection
        public Connection(TcpClient tcpCon, ChatCrypt chatCrypt)
        {
            //this.cryptPublicKey = cryptPublicKey;
            this.chatCrypt = chatCrypt;
            tcpClient = tcpCon;
            // The thread that accepts the client and awaits messages
            thrSender = new Thread(acceptClient);
            // The thread calls the AcceptClient() method
            thrSender.Start();
        }

        private void closeConnection()
        {
            // Close the currently open objects
            tcpClient.Close();
            srReceiver.Close();
            swSender.Close();
        }

        /**
         * Occures when a new client is accepted
         * if unsucessful connection flag denied is sent
         * if successful: servers public crypt key is sent to client
         *    server then waits for message as username|password
         *    server returns validation flag result and reads client messages
         */
        private void acceptClient()
        {
            srReceiver = new StreamReader(tcpClient.GetStream());
            swSender = new StreamWriter(tcpClient.GetStream());

            string cryptPubKey;
            try
            {
                // Read the account information from the client
                string[] rec = srReceiver.ReadLine().Split('|');
                currUser = rec[0];
                cryptPubKey = rec[1];
            } catch(Exception e)
            {
                return;
            }
            try
            {
                // We got a response from the client
                if (currUser == "")
                {
                    closeConnection();
                    return;
                }

                // Store the user name in the hash table
                if (ChatServer.htUsers.Contains(currUser) == true)
                {
                    // 0 means not connected
                    swSender.WriteLine(ChatServer.FLAG_DENIED + "|This username already exists.");
                    swSender.Flush();
                    closeConnection();
                    return;
                }
                else if (currUser == "Administrator")
                {
                    // 0 means not connected
                    swSender.WriteLine(ChatServer.FLAG_DENIED + "|This username is reserved.");
                    swSender.Flush();
                    closeConnection();
                    return;
                }
                else
                {
                    // send connection granted and the servers public crypt key to client
                    swSender.WriteLine(ChatServer.FLAG_GRANTED + "|" + chatCrypt.PublicKeyString);
                    swSender.Flush();

                    // wait for user|password response from client
                    strResponse = srReceiver.ReadLine();
                    if (strResponse == "" || strResponse == null)
                    {
                        return;
                    }
                    strResponse = chatCrypt.Decrypt(strResponse);

                    string[] rec = strResponse.Split('|');
                    // add clients public crypt key
                    chatCrypt.AddCryptKey(rec[0], cryptPubKey);

                    // check user - password 
                    if (ph.Validate(rec[0], rec[1]))
                    {
                        // Add the user to the hash tables and start listening for messages from him
                        ChatServer.AddUser(tcpClient, rec[0]);

                        // send ok to user
                        string msg = ChatServer.FLAG_GRANTED + "|" + "login succesful!";
                        msg = chatCrypt.Crypt(rec[0], msg);

                        swSender.WriteLine(msg);
                        swSender.Flush();
                    }
                    else // validation error
                    {
                        string msg = ChatServer.FLAG_DENIED + "|" + "wrong username/password";
                        msg = chatCrypt.Crypt(currUser, msg);

                        swSender.WriteLine(msg);
                        swSender.Flush();
                        closeConnection();
                        // after sending crypted message remove user from crypthelper
                        chatCrypt.RemoveCryptKey(currUser);
                    }

                }

                // Keep waiting for a message from the user
                while ((strResponse = srReceiver.ReadLine()) != "")
                {
                    // If it's invalid, remove the user
                    if (strResponse == null)
                    {
                        ChatServer.RemoveUser(tcpClient);
                    }
                    else
                    {
                        // Otherwise send the message to all the other users
                        ChatServer.SendMessage(currUser, strResponse);
                    }
                }
            }
            catch
            {
                // If anything went wrong with this user, disconnect him
                ChatServer.RemoveUser(tcpClient);
            }
        }
    }
}
