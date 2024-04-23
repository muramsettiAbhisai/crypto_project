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

using namespace CryptoPP;
std::atomic<int> ticketCounter(0); // Atomic counter for ticket IDs
std::map<std::string, std::string> userMap;
pthread_mutex_t mapMutex = PTHREAD_MUTEX_INITIALIZER; // Mutex for thread-safe access to userMap

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
    int nsfd = *((int*)arg);
    delete (int*)arg; // Free memory allocated for the argument

    RSA::PrivateKey p_privateKey;
    FileSource privateKeySource("my_rsa_private2.bin", true);
    p_privateKey.Load(privateKeySource);
    std::string iv("0123456789012345");
    RandomPool randPool;
    randPool.IncorporateEntropy((unsigned char*)iv.c_str(), iv.size());
    RSAES<OAEP<SHA256>>::Decryptor decryptor(p_privateKey);
    bool loggedIn = false;
    while (true) {
        if (!loggedIn) { 
            int choice;
            recv(nsfd, &choice, sizeof(choice), 0);
            //std::cout<<"recieved choice:"<<choice<<std::endl;
            char username[1000];
            recv(nsfd, username, sizeof(username), 0);
            //std::cout<<"recieved username:"<<username<<std::endl;
            char password[1000];
            int sz=recv(nsfd, password, sizeof(password), 0);
            //std::cout<<"recieved password:"<<password<<std::endl;

            
            std::string decryptedUsername = username;
            std::string hashedPassword = password;

            std::string decrypted;
            StringSource(username, true, new HexDecoder(new PK_DecryptorFilter(
                randPool, decryptor, new StringSink(decrypted))));
            decrypted = decrypted.substr(0, decrypted.find('\0')); // Remove null terminator from decrypted string

            if (choice == 1) { // Signup
                if (userExists(decrypted)) {
                    send(nsfd, "Username already exists!", sizeof("Username already exists!"), 0);
                    sleep(1);
                } else {
                    storeCredentials(decrypted, hashedPassword);
                    send(nsfd, "Signup successful!", sizeof("Signup successful!"), 0);
                     sleep(1);
                }
            } else if (choice == 2) { // Login
                if (!userExists(decrypted)) {
                    send(nsfd, "User does not exist!", sizeof("User does not exist!"), 0);
                     sleep(1);
                } else if (authenticateUser(decrypted, hashedPassword)) {
                    
                    loggedIn=true;
                    send(nsfd, "you are logged in", sizeof("you are logged in"), 0);
                     sleep(1);
                } else {
                    send(nsfd, "Incorrect password!", sizeof("Incorrect password!"), 0);
                     sleep(1);
                }
            }
        }
        else
        {
                std::cout<<"hii"<<std::endl;
           
                char name[1000]={'\0'}, date[1000]={'\0'}, to[1000]={'\0'}, from[1000]={'\0'};
                recv(nsfd, name, sizeof(name), 0);
                recv(nsfd, date, sizeof(date), 0);
                recv(nsfd, to, sizeof(to), 0);
                recv(nsfd, from, sizeof(from), 0);
                std::string ticketFilename,signatureFilename;
                ticketFilename=issueTicket(name, date, to, from); // Issue the ticket
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
                    //std::cout << line << std::endl;
                    send(nsfd, line.c_str(), sizeof(line), 0);
                    sleep(2);
                }
                ticketFile.close();
                
                while (std::getline(signatureFile, line2))
                {
                    //std::cout << line2 << std::endl;
                    send(nsfd, line2.c_str(), 256, 0);
                    sleep(2);
                }
                std::cout<<"successfully signed the recieved ticket and sent it back"<<std::endl;
                signatureFile.close();
                while(1);

        }
        
    }

    close(nsfd);
    return nullptr;
}

int main() {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);

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
