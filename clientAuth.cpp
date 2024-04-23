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
                sleep(1);
                send(sfd, encryptedUsername.c_str(), encryptedUsername.size(), 0);
                sleep(1);
                send(sfd, hashedPassword.c_str(), hashedPassword.size(), 0);
                char response[1000];
                recv(sfd, response, sizeof(response), 0);
                if(strcmp(response,"you are logged in")==0)
                {
                    loggedIn=true;
                }
                std::cout<<response<<"\n";
                std::cout.flush();
            } else if (choice == 3) {
                break; // Exit the loop and close the socket
            } else {
                std::cout << "Invalid choice. Please try again." << std::endl;
            }
        }
        else
        {
            std::string kk;
            std::cout<<"enter command(get_ticket / verify_ticket)"<<std::endl;
            std::getline(std::cin, kk);
            if(kk=="get_ticket")
            {
                std::string buff;
                std::cout<<"enter name\n";
                std::getline(std::cin, buff);
                send(sfd,buff.c_str(),buff.size(),0);
                sleep(1);
                std::cout<<"enter date of journey\n";
                std::getline(std::cin, buff);
                send(sfd,buff.c_str(),buff.size(),0);
                sleep(1);
                std::cout<<"enter to address\n";
                std::getline(std::cin, buff);
                sleep(1);
                send(sfd,buff.c_str(),buff.size(),0);
                std::cout<<"enter from address\n";
                sleep(1);
                std::getline(std::cin, buff);
                send(sfd,buff.c_str(),buff.size(),0);
                char response[1000];
                std::ofstream ticketFile("tikcetFile.txt");
                std::ofstream signatureFile("signatureFile.txt");
                int bytes_received=0;
                char buffer1[1000];
                int cnt=0;
                while ((bytes_received = recv(sfd,buffer1,sizeof(buffer1),0)) > 0) 
                {
                    cnt++;
                    if(cnt==1)
                    {
                        std::cout<<"ticket recieved from signer is:"<<std::endl;
                        std::cout<<"**************************"<<std::endl;
                    }
                    ticketFile<<buffer1<<std::endl;
                    std::cout<<buffer1<<std::endl;
                    memset(buffer1, 0, sizeof(buffer1));
                    if(cnt==4)break;
                } 
                std::cout<<"***********"<<std::endl; 
                ticketFile.close();
                
                char buffer2[256];
                std::cout<<"recieved signature:"<<std::endl;
                cnt=0;
                while ((bytes_received = recv(sfd, buffer2,256, 0)) > 0) 
                {
                    cnt++;
                    signatureFile<<buffer2<<std::endl;
                    std::cout<<buffer2<<std::endl;
                    memset(buffer2, 0, sizeof(buffer2));
                    if(cnt==1)break;
                } 
                std::cout<<"***********"<<std::endl;
                signatureFile.close(); 
                                                              

            }
            else if(kk=="verify_ticket")
            {
                int sfd_2 = socket(AF_INET, SOCK_STREAM, 0);
                if (sfd_2 == -1) {
                    std::cerr << "Error creating socket" << std::endl;
                    return -1;
                }

                struct sockaddr_in server_address_2;
                memset(&server_address, 0, sizeof(server_address_2));
                server_address_2.sin_family = AF_INET;
                server_address_2.sin_addr.s_addr = inet_addr("127.0.0.2");
                server_address_2.sin_port = htons(8083);

                if (connect(sfd_2, reinterpret_cast<struct sockaddr*>(&server_address_2), sizeof(server_address_2)) == -1) {
                    std::cerr << "Error connecting to server" << std::endl;
                    close(sfd_2);
                    return -1;
                }
                SHA256 hash;
                std::string msg_hash;
                FileSource hashing("tikcetFile.txt", true, new HashFilter(hash,new HexEncoder(new StringSink(msg_hash))));
                std::cout<<"do you want to change any field of ticket\nEnter : 1 to edit  0 to not edit"<<std::endl;
                int choice;
                std::cin>>choice;
                if(choice==1)
                {
                  int ch;
                  
                  std::ifstream editfile("tikcetFile.txt");
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
                  std::ofstream writefile("tikcetFile.txt");
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
                 
                //std::string line;
                if(choice==1)
                std::cout<<"modified tikcet is  transmitted for verification"<<std::endl;
                else
                std::cout<<"Original tikcet is transmitted for verification"<<std::endl;
                std::ifstream ticketFile("tikcetFile.txt");
                std::ifstream signatureFile("signatureFile.txt");
                //std::cout<<"sending"<<std::endl;
                std::string line,line2;
                while (std::getline(ticketFile, line))
                {
                    //std::cout << line << std::endl;
                    send(sfd_2, line.c_str(), sizeof(line), 0);
                    sleep(2);
                }
                ticketFile.close();
                sleep(2);
                while (std::getline(signatureFile, line2))
                {
                    //std::cout << line2 << std::endl;
                    send(sfd_2, line2.c_str(), 256, 0);
                    sleep(2);
                }
                sleep(2);
                signatureFile.close();
                send(sfd_2,msg_hash.c_str(),64,0); 
                char result[100];
                recv(sfd_2,result,sizeof(result),0);
                std::cout<<result<<std::endl;
            }



        }
        
    }

    close(sfd);

    return 0;
}
