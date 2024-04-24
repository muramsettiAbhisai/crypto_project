#include <crypto++/cryptlib.h>
#include <crypto++/hex.h>
#include <crypto++/rsa.h>
#include <crypto++/files.h>
#include <crypto++/randpool.h>
#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h> // Added for multi-threading support
#include <map>
#include <string>
#include <sstream>
using namespace CryptoPP;
std::atomic<int> ticketCounter(0); // Atomic counter for ticket IDs
std::map<std::string, std::string> userMap;
pthread_mutex_t mapMutex = PTHREAD_MUTEX_INITIALIZER; // Mutex for thread-safe access to userMap


//for server private key
RSA::PrivateKey p_privateKey;
std::string iv("0123456789012345");
RandomPool randPool;


//for client  public key
RSA::PublicKey p_publicKey;


std::string RSAEncrypt(const std::string& plainText) {
    randPool.IncorporateEntropy((unsigned char*)iv.c_str(), iv.size());
    RSAES<OAEP<SHA256>>::Encryptor  encryptor(p_publicKey); 
    std::string cipherText;
    StringSource(plainText, true, new PK_EncryptorFilter(randPool, encryptor, new HexEncoder(new StringSink(cipherText))));
    return cipherText;
}
std::string decrypt(const std::string& encrypted) {
    std::string decrypted;
    try {
        RSAES<OAEP<SHA256>>::Decryptor decryptor(p_privateKey);
        StringSource(encrypted, true, new HexDecoder(new PK_DecryptorFilter( randPool, decryptor, new StringSink(decrypted))));
        decrypted = decrypted.substr(0, decrypted.find('\0'));
    } catch (const CryptoPP::Exception& ex) {
        std::cerr << "Error decrypting username: " << ex.what() << std::endl;
    }
    return decrypted;
}

void storeCredentials(const std::string& decryptedUsername, const std::string& hashedPassword) {
    pthread_mutex_lock(&mapMutex); // Lock the mutex before accessing userMap
    userMap[decryptedUsername] = hashedPassword;
    pthread_mutex_unlock(&mapMutex); // Unlock the mutex after accessing userMap
}

bool userExists(const std::string& username) {
    pthread_mutex_lock(&mapMutex); // Lock the mutex before accessing userMap
    bool exists = userMap.find(username) != userMap.end();
    pthread_mutex_unlock(&mapMutex); // Unlock the mutex after accessing userMap
    return exists;
}

bool authenticateUser(const std::string& username, const std::string& hashedPassword) {
    pthread_mutex_lock(&mapMutex); // Lock the mutex before accessing userMap
    bool authenticated = false;
    auto it = userMap.find(username);
    if (it != userMap.end()) {
        authenticated = it->second == hashedPassword;
    }
    pthread_mutex_unlock(&mapMutex); // Unlock the mutex after accessing userMap
    return authenticated;
}
std::string issueTicket(const std::string& username, const std::string& date, const std::string& to, const std::string& from) {
    static pthread_mutex_t ticketMutex = PTHREAD_MUTEX_INITIALIZER; // Mutex for thread-safe access to ticketCounter
    pthread_mutex_lock(&ticketMutex); // Lock the mutex before accessing ticketCounter
    int ticketID = ticketCounter.fetch_add(1); // Get and increment ticket ID atomically
    pthread_mutex_unlock(&ticketMutex); // Unlock the mutex after accessing ticketCounter
    
    std::string ticketFilename = "ticket_" + std::to_string(ticketID);
    std::ofstream ticketFile(ticketFilename + ".txt"); // Open ticket file with unique name
    if (ticketFile.is_open()) {
        //ticketFile << "Ticket ID: " << ticketID << std::endl;
        ticketFile << "Name : " << username << std::endl;
        ticketFile << "Date : " << date << std::endl;
        ticketFile << "From : " << from << std::endl;
        ticketFile << "To   : " << to << std::endl;
        /*
        ticketFile << "Flight Number: XYZ123" << std::endl; // Sample flight number
        ticketFile << "Seat Number: A1" << std::endl; // Sample seat assignment
        ticketFile << "Departure Time: 08:00 AM" << std::endl; // Sample departure time
        ticketFile << "Arrival Time: 10:00 AM" << std::endl; // Sample arrival time
        ticketFile << "Airline: ABC Airlines" << std::endl; // Sample airline
        ticketFile << "Gate: 5" << std::endl; // Sample gate number
        */
    } else {
        std::cerr << "Unable to open ticket file for writing." << std::endl;
    }
    return ticketFilename;
}

std::string signTicket(std::string ticketFilename){
        size_t underscorePos = ticketFilename.find('_');
        std::string ticketIDString = ticketFilename.substr(underscorePos + 1);
        std::string signatureFilename = "signature_" + ticketIDString;
        std::string signature_file=signatureFilename +".txt";
        std::ofstream signatureFile(signatureFilename + ".txt");
        if (!signatureFile.is_open()) {
               std::cerr << "Unable to open signature file for writing." << std::endl;
        }
        
        std::string iv("0123456789012345");
        RandomPool randPool;
        randPool.IncorporateEntropy((unsigned char*)iv.c_str(), iv.size());
        RSA::PrivateKey p_privateKey;
        FileSource privateKeySource("my_rsa_private2.bin", true);
        p_privateKey.Load(privateKeySource);
        RSASS<PKCS1v15, SHA256>::Signer signer(p_privateKey);  
        std::string ticket_file=ticketFilename+".txt";
        FileSource(ticket_file.c_str(), true, new SignerFilter(randPool, signer, new HexEncoder(new FileSink(signature_file.c_str()))));  
         
        signatureFile.close();
        return signatureFilename;      
         
                       
}
void* handleClient(void* arg) {
    // for sending its own public ley
    
    int nsfd = *((int*)arg);
    delete (int*)arg; // Free memory allocated for the argument
    std::ifstream publicKeyFile("my_rsa_public2.bin", std::ios::binary);
    std::stringstream publicKeyStream;
    publicKeyStream << publicKeyFile.rdbuf();
    std::string publicKey = publicKeyStream.str();
    send(nsfd, publicKey.c_str(), publicKey.size(), 0);
    
    char publicKeyBuffer[4096]; 
    int bytesReceived = recv(nsfd, publicKeyBuffer, sizeof(publicKeyBuffer), 0);
    if (bytesReceived <= 0) {
        std::cerr << "Error receiving public key from server" << std::endl;
    }
    std::string publicKeyString(publicKeyBuffer, bytesReceived);
    StringSource publicKeySource(publicKeyString, true);
    p_publicKey.Load(publicKeySource);  
    



    bool loggedIn = false;
    while (true) {
        if (!loggedIn) { 
            int choice;
            recv(nsfd, &choice, sizeof(choice), 0);
            //std::cout<<"recieved choice:"<<choice<<std::endl;
            char username[1000]={'\0'};
            recv(nsfd, username, sizeof(username), 0);
            //std::cout<<"recieved username:"<<username<<std::endl;
            char password[1000]={'\0'};
            int sz=recv(nsfd, password, sizeof(password), 0);
            //std::cout<<"recieved password:"<<password<<std::endl;

            
            std::string decryptedUsername = username;
            std::string hashedPassword = password;

            std::string decrypted = decrypt(decryptedUsername);
            //std::cout<<(decrypted);
            std::cout.flush();
            if (choice == 1) { // Signup
                if (userExists(decrypted)) {
                    std::string buff = "Username already exists!";
                    buff = RSAEncrypt(buff);
                    send(nsfd, buff.c_str(), buff.size(), 0);
                    sleep(1);
                } else {
                    storeCredentials(decrypted, hashedPassword);
                    std::string buff = "Signup successful!";
                    buff = RSAEncrypt(buff);
                    send(nsfd, buff.c_str(), buff.size(), 0);
                     sleep(1);
                }
            } else if (choice == 2) { // Login
                if (!userExists(decrypted)) {
                    std::string buff = "User does not exist!";
                    buff = RSAEncrypt(buff);
                    send(nsfd, buff.c_str(), buff.size(), 0);
                     sleep(1);
                } else if (authenticateUser(decrypted, hashedPassword)) {
                    
                    loggedIn=true;
                    std::string buff = "you are logged in";
                    buff = RSAEncrypt(buff);
                    send(nsfd, buff.c_str(), buff.size(), 0);
                     sleep(1);
                } else {
                    std::string buff = "Incorrect password!";
                    buff = RSAEncrypt(buff);
                    send(nsfd, buff.c_str(), buff.size(), 0);
                     sleep(1);
                }
            }
        }
        else
        {
                char status[1000]={'\0'};
                recv(nsfd, status, sizeof(status), 0);
                if(strcmp(status,"log_out")==0)
                {
                     loggedIn=0;
                     continue;
                }
                else if(strcmp(status,"verify_ticket")==0)
                {
                   continue;
                }
                std::cout<<"fetching details"<<std::endl;
           
                char name[1000]={'\0'}, date[1000]={'\0'}, to[1000]={'\0'}, from[1000]={'\0'};

                recv(nsfd, name, sizeof(name), 0);
                std::string name1=name;
                name1 = decrypt(name1);
                recv(nsfd, date, sizeof(date), 0);
                std::string date1=date;
               date1 = decrypt(date1);
                recv(nsfd, to, sizeof(to), 0);
                std::string to1=to;
                to1 = decrypt(to1);
                recv(nsfd, from, sizeof(from), 0);
                std::string from1=from;
                from1 = decrypt(from1);
                //std::cout<<from1<<to1<<date1<<name1;
                std::string ticketFilename,signatureFilename;
                ticketFilename=issueTicket(name1, date1, to1, from1); // Issue the ticket
                //std::cout<<name<<to<<from<<date;
                //std::cout.flush();
                signatureFilename=signTicket(ticketFilename);
                //send(nsfd, "Ticket issued successfully!", sizeof("Ticket issued successfully!"), 0);
                sleep(2);
                std::ifstream ticketFile(ticketFilename + ".txt");
                std::ifstream signatureFile(signatureFilename + ".txt");
                std::string line,line2;
                while (std::getline(ticketFile, line))
                {
                    line = RSAEncrypt(line);
                    send(nsfd, line.c_str(), line.size(), 0);
                    sleep(2);
                }
                ticketFile.close();
                std::cout<<"ticket is transmitted"<<std::endl;
                while (std::getline(signatureFile, line2))
                {
                    send(nsfd, line2.c_str(), line2.size(), 0);
                    sleep(2);
                }
                std::cout<<"successfully signed the ticket and sent it back"<<std::endl;
                signatureFile.close();
                

        }
        
    }

    close(nsfd);
    return nullptr;
}

int main() {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    randPool.IncorporateEntropy((unsigned char*)iv.c_str(), iv.size());
    FileSource privateKeySource("my_rsa_private2.bin", true);
    p_privateKey.Load(privateKeySource);
    
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port = htons(8081);
    int reuse = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    bind(sfd, reinterpret_cast<struct sockaddr*>(&server_address), sizeof(server_address));
    listen(sfd, 3);

    while (true) {
        int* nsfd = new int(); // Allocate memory for new socket file descriptor
        *nsfd = accept(sfd, NULL, NULL);
        pthread_t thread;
        pthread_create(&thread, NULL, handleClient, (void*)nsfd); // Create a new thread to handle client
        pthread_detach(thread); // Detach the thread to avoid memory leaks
    }

    close(sfd);
    return 0;
}
