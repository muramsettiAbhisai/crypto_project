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

            char username[1000];
            recv(nsfd, username, sizeof(username), 0);
            char password[1000];
            int sz=recv(nsfd, password, sizeof(password), 0);

            
            std::string decryptedUsername = username;
            std::string hashedPassword = password;

            std::string decrypted;
            StringSource(username, true, new HexDecoder(new PK_DecryptorFilter(
                randPool, decryptor, new StringSink(decrypted))));
            decrypted = decrypted.substr(0, decrypted.find('\0')); // Remove null terminator from decrypted string

            if (choice == 1) { // Signup
                std::cout<<decrypted<<"\n";
                std::cout.flush();
                if (userExists(decrypted)) {
                    send(nsfd, "Username already exists! please login", sizeof("Username already exists! please login"), 0);
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
                    send(nsfd, "success", sizeof("success"), 0);
                     sleep(1);
                } else {
                    send(nsfd, "Incorrect password!", sizeof("Incorrect password!"), 0);
                     sleep(1);
                }
            }
        }
        else
        {
            std::cout<<"now you are logged IN";
            std::cout.flush();
            sleep(3);
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
    server_address.sin_addr.s_addr = INADDR_ANY;
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
