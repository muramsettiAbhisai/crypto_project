#include <crypto++/cryptlib.h>
#include <crypto++/hex.h>
#include <crypto++/rsa.h>
#include <crypto++/aes.h>
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
#include <bits/stdc++.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <pthread.h>

using namespace CryptoPP;
RSA::PublicKey p_publicKey;


void* handleClient(void* arg) {
    int nsfd = *((int*)arg);
    delete (int*)arg; // Free memory allocated for the argument
    
    
    int c = 0;
    int maxi = 3;

    while(1){
        c++;
        std::string ticketFilename= "receivedTicketFile";
        ticketFilename += std::to_string(c) + ".txt";
        std::string signatureFilename= "receivedSignatureFile";
        signatureFilename += std::to_string(c) + ".txt";
        std::ofstream ticketFile(ticketFilename);
        
        int bytes_received = 0;
        char buffer1[1000];
        int cnt = 0;

        while ((bytes_received = recv(nsfd, buffer1, sizeof(buffer1), 0)) > 0) {
            cnt++;
            if (cnt == 1) {
                std::cout << "ticket received through transmission is:" << std::endl;
                std::cout << "********************************" << std::endl;
            }
            ticketFile << buffer1 << std::endl;
            std::cout << buffer1 << std::endl;
            memset(buffer1, 0, sizeof(buffer1));
            if (cnt == 4) break;
        }
        ticketFile.close();
        
        std::ofstream signatureFile(signatureFilename.c_str());
        char buffer2[256];
        std::cout << "********************************" << std::endl;
        std::cout << "siganture file received through transmission is:" << std::endl;
        std::cout << "********************************" << std::endl;
        cnt = 0;
        while ((bytes_received = recv(nsfd, buffer2, sizeof(buffer2), 0)) > 0) {
            cnt++;
            signatureFile << buffer2 << std::endl;
            std::cout << buffer2 << std::endl;
            memset(buffer2, 0, sizeof(buffer2));
            if (cnt == 1) break;
        }
        signatureFile.close(); 
        char signer_buff[64];
        recv(nsfd, signer_buff, sizeof(signer_buff), 0);
        
        
        RSASS<PKCS1v15, SHA256>::Verifier verifier(p_publicKey);
        byte result = 0;
        SignatureVerificationFilter filter(verifier, new ArraySink(&result, sizeof(result)));
        FileSource msgFile(ticketFilename.c_str(), true);
        FileSource signFile(signatureFilename.c_str(), true, new HexDecoder);
        signFile.TransferTo(filter);
        msgFile.TransferTo(filter);
        filter.MessageEnd();
        
        std::cout << "********************************" << std::endl;
        SHA256 hash;
        std::string msg_hash;
        FileSource hashing(ticketFilename.c_str(), true, new HashFilter(hash, new HexEncoder(new StringSink(msg_hash))));
        std::cout << "hash obtained from decrypting signature file:\n" << msg_hash << std::endl;
        std::cout << "hash generated from recieved ticket file :\n" << signer_buff << std::endl;
        std::cout << "********************************" << std::endl;
        sleep(1);
        if (result)
        {
            std::cout << "both hashes are same" << std::endl;
            std::cout << "Successfully Verified Signature on File " << std::endl;
            send(nsfd,"Successfully Verified Signature on File",sizeof("Successfully Verified Signature on File"),0);
        }
        else
        {
            std::cout << "both hashes are different" << std::endl;
            std::cout << "Failed to Verify Signature on File " << std::endl; 
            send(nsfd,"Failed to Verify Signature on File ",sizeof("Failed to Verify Signature on File "),0);
        }
    }
    
    close(nsfd);
    
    return NULL;
}

int main() {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.2");
    server_address.sin_port = htons(8083);
    int reuse = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    bind(sfd, reinterpret_cast<struct sockaddr*>(&server_address), sizeof(server_address));
    listen(sfd, 5); 
    
    FileSource publicKeyFile("my_rsa_public2.bin", true);
    
    p_publicKey.Load(publicKeyFile);
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
