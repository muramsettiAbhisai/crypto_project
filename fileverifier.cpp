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
#include<bits/stdc++.h>
using namespace CryptoPP;
char message[10000000];
char signature[100000000];
std::set<std::string>st;

int main() {

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(8081);
    int reuse=1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    bind(sfd, reinterpret_cast<struct sockaddr*>(&server_address), sizeof(server_address));



    listen(sfd, 1); 
    
    int nsfd=accept(sfd,NULL,NULL);
    
    RSA::PublicKey p_publicKey;
    FileSource publicKeyFile("my_rsa_public2.bin", true);
    p_publicKey.Load(publicKeyFile);
    
    int c=0;
    int maxi=2;
    while(maxi--)
    {
        c++;
        std::string inputfile="received_msg_file";
        inputfile+=std::to_string(c)+".txt";
        std::string signaturefile="received_signature_file";
        signaturefile+=std::to_string(c)+".txt";
        std::fstream outfile1(inputfile.c_str(),std::ios::in | std::ios::out| std::ios::trunc);
         
        char receivedHash[64];
        recv(nsfd, receivedHash, sizeof(receivedHash), 0);
        
        
        int bytes_received=0;
        char buffer1[1000];
        int cnt=0;

        while ((bytes_received = recv(nsfd,buffer1,sizeof(buffer1),0)) > 0) 
        {
            cnt++;
            if(cnt==1)
            {
                std::cout<<"ticket recieved through transmission is:"<<std::endl;
                std::cout<<"**************************"<<std::endl;
            }
            outfile1<<buffer1<<std::endl;
            std::cout<<buffer1<<std::endl;
            memset(buffer1, 0, sizeof(buffer1));
            if(cnt==4)break;
        }  
        outfile1.close();
                   
        std::fstream outfile2(signaturefile.c_str(),std::ios::in | std::ios::out| std::ios::trunc);
        
      
        char buffer2[256];
        std::cout<<"***********"<<std::endl;
        cnt=0;
        while ((bytes_received = recv(nsfd, buffer2, sizeof(buffer2), 0)) > 0) 
        {
            cnt++;
            outfile2<<buffer2<<std::endl;
            // std::cout<<buffer2<<std::endl;
            memset(buffer2, 0, sizeof(buffer2));
            if(cnt==1)break;
        } 
        outfile2.close(); 
              
        RSASS<PKCS1v15, SHA256>::Verifier  verifier(p_publicKey);
        byte result = 0;
        SignatureVerificationFilter     filter(verifier, new ArraySink(&result, sizeof(result)));
        FileSource  msgFile(inputfile.c_str(), true);
        FileSource  signFile(signaturefile.c_str(), true, new HexDecoder);
        std::string hashValue;
        SHA256 sha256;
        FileSource  kk(inputfile.c_str(), true, new HashFilter(sha256, new HexEncoder(new StringSink(hashValue))));
        std::cout << "actual hash value by signer: " << receivedHash << std::endl;
        std::cout << " Hash Value of by verifier :" << hashValue << std::endl;
        signFile.TransferTo(filter);
        msgFile.TransferTo(filter);
        filter.MessageEnd();

        // Verify result if verification is OK or not
        std::cout << "********************************" << std::endl;
        if (result)
            std::cout << "Successfully Verified Signature on File " << std::endl;
        else
            std::cout << "Failed to Verify Signature on File " << std::endl;        
        std::cout<<std::endl;
    }
    
    
return 0;    
}
