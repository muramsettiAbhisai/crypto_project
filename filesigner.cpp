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
    
    std::string iv("0123456789012345"); // A 128 bit IV 16 bytes
    RandomPool randPool;
    randPool.IncorporateEntropy((unsigned char*)iv.c_str(), iv.size());

    RSA::PrivateKey p_privateKey;
    FileSource privateKeySource("my_rsa_private2.bin", true);
    p_privateKey.Load(privateKeySource);
   
   
    RSASS<PKCS1v15, SHA256>::Signer signer(p_privateKey);
    int maxi=2;   
    while(maxi--)
    {
        std::string inputfile;
        std::cout<<"enter file name"<<std::endl;
        std::getline(std::cin,inputfile);
        
        std::string signaturefile="signature.txt";
        FileSource(inputfile.c_str(), true, new SignerFilter(randPool, signer, new HexEncoder(new FileSink(signaturefile.c_str()))));
        std::ifstream inputFile(inputfile.c_str(),std::ios::in);
        std::ifstream signatureFile(signaturefile.c_str(),std::ios::in);
        if (!signatureFile) {
            std::cerr << "Error: Failed to create signature file" << std::endl;
            return -1;
        }
        std::string hashValue;
         SHA256 sha256;
        FileSource  kk(inputfile.c_str(), true, new HashFilter(sha256, new HexEncoder(new StringSink(hashValue))));
        send(sfd, hashValue.c_str(), hashValue.size(), 0);

        std::cout<<"do you want to change any field of document\nEnter : 1 to edit  0 to not edit"<<std::endl;
        int choice;
        std::cin>>choice;
        if(choice==1)
        {
            int ch;
          std::ifstream editfile(inputfile.c_str(),std::ios::in);
          if(!editfile.is_open())std::cout<<"error in opening file"<<std::endl;
          std::vector<std::string> lines;
          std::string line;
          std::cout<<"this is the original tikcet"<<std::endl;
          std::cout<<"**************************"<<std::endl;
          while (std::getline(editfile, line))
          {
              std::cout<<line<<std::endl;
              lines.push_back(line);
          } 
          std::cout<<"**************************"<<std::endl;
          editfile.close();  
            std::cout<<"choose which field you want to change\nEnter : 1 to edit name  2 to edit date  3 to edit from place  4 to to place"<<std::endl;
          std::cin>>ch;
          std::cin.ignore();
          std::cout<<"your choice is :"<<ch<<std::endl;
          std::string change;
          std::string edit;
          std::cout<<"enter the  new value of field"<<std::endl;
          std::getline(std::cin,change);
          

          if(ch==1)
          {
              edit+="NAME : "+change;
              lines[ch-1]=edit;
          }
          if(ch==2)
          {
              edit+="DATE : "+change;
              lines[ch-1]=edit;
          }
          if(ch==3)
          {
             edit+="FROM : "+change;
             lines[ch-1]=edit;
          }
          if(ch==4)
          {
             edit+="TO   : "+change;
             lines[ch-1]=edit;
          }
          std::ofstream writefile(inputfile.c_str(),std::ios::trunc);
          if(!writefile.is_open())std::cout<<"error in opening file"<<std::endl;
          std::cout<<"this is the modified ticket"<<std::endl;
          std::cout<<"**************************"<<std::endl;
          for(const auto& updatedLine : lines) 
          {
             std::cout<<updatedLine<<std::endl;
             writefile<< updatedLine <<std::endl;
          }
          std::cout<<"**************************"<<std::endl;
          writefile.close();
        }
        
        
        std::string line;
        std::cout<<"modified tikcet is in transmission:"<<std::endl;
        std::cout<<"**************************"<<std::endl;
        while (std::getline(inputFile, line))
        {
            std::cout << line << std::endl;
            send(sfd, line.c_str(), sizeof(line), 0);
            sleep(2);
        }
        std::cout<<"**************************"<<std::endl;
        sleep(2);
        std::string line2;
        while (std::getline(signatureFile, line2))
        {
            // std::cout<<line2<<std::endl;
            send(sfd, line2.c_str(),256, 0);
            sleep(2);
        }
        if(choice==0)std::cin.ignore();
        
    }
    

    return 0;
/*
NAME : CH.SAI ASHISH REDDY
DATE : 27-30-2024
FROM : HYDERABAD
TO   : KAZIPET
*/
}

