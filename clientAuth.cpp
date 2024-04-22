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
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

int main() {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        std::cerr << "Error creating socket" << std::endl;
        return -1;
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port = htons(8081);

    if (connect(sfd, reinterpret_cast<struct sockaddr*>(&server_address), sizeof(server_address)) == -1) {
        std::cerr << "Error connecting to server" << std::endl;
        close(sfd);
        return -1;
    }

    std::string iv("0123456789012345"); 
    RandomPool randPool;
    randPool.IncorporateEntropy((unsigned char*)iv.c_str(), iv.size());
    RSA::PublicKey p_publicKey;
    FileSource publicKeyFile("my_rsa_public2.bin", true);
    p_publicKey.Load(publicKeyFile);    
    
    RSAES<OAEP<SHA256>>::Encryptor  encryptor(p_publicKey); 
    bool loggedIn = false;
    while (true) {
        if(!loggedIn)
        {
            std::cout << "Choose an option:" << std::endl;
            std::cout << "1. Signup" << std::endl;
            std::cout << "2. Login" << std::endl;
            std::cout << "3. Exit" << std::endl;
            int choice;
            std::cin >> choice;
            std::cin.ignore(); // Ignore the newline character
            
            if (choice == 1 || choice == 2) {
                std::string username, password;
                std::cout << "Enter username: ";
                std::getline(std::cin, username);
                std::cout << "Enter password: ";
                std::getline(std::cin, password);
                
                std::string encryptedUsername, hashedPassword;
                StringSource(username, true, new PK_EncryptorFilter(randPool, encryptor, new HexEncoder(new StringSink(encryptedUsername))));
                SHA256 hash;
                StringSource(password, true, new HashFilter(hash, new StringSink(hashedPassword)));

                // Send choice, encrypted username, and hashed password to server
                send(sfd, &choice, sizeof(choice), 0);
                sleep(0.1);
                send(sfd, encryptedUsername.c_str(), encryptedUsername.size(), 0);
                sleep(0.1);
                send(sfd, hashedPassword.c_str(), hashedPassword.size(), 0);
                sleep(0.1);
                char response[1000];
                recv(sfd, response, sizeof(response), 0);
                if(strcmp(response,"success")==0)
                {
                    loggedIn=true;
                }
                std::cout<<response<<"\n";
            } else if (choice == 3) {
                break; // Exit the loop and close the socket
            } else {
                std::cout << "Invalid choice. Please try again." << std::endl;
            }
        }
        else
        {
            std::cout<<"yeah now you are loggedin\n";

        }
        
    }

    close(sfd);

    return 0;
}
