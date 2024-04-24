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
    #include <sstream>
    #include <string>
    #include <fstream>
    using namespace CryptoPP;
    //for server public key
    std::string iv("0123456789012345"); 
    RandomPool randPool;
    RSA::PublicKey p_publicKey;

    // for client private key
    RSA::PrivateKey p_privateKey;

    std::atomic<int> ticketCounter(-1); 

    std::string RSAEncrypt(const std::string& plainText) {
    
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
    int main() {

        randPool.IncorporateEntropy((unsigned char*)iv.c_str(), iv.size());
        FileSource privateKeySource("my_rsa_private1.bin", true);
        p_privateKey.Load(privateKeySource);



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
    
    
        
        char publicKeyBuffer[4096]; 
        int bytesReceived = recv(sfd, publicKeyBuffer, sizeof(publicKeyBuffer), 0);
        if (bytesReceived <= 0) {
            std::cerr << "Error receiving public key from server" << std::endl;
        }
        std::string publicKeyString(publicKeyBuffer, bytesReceived);
        StringSource publicKeySource(publicKeyString, true);
        p_publicKey.Load(publicKeySource);  

        std::ifstream publicKeyFile("my_rsa_public1.bin", std::ios::binary);
        std::stringstream publicKeyStream;
        publicKeyStream << publicKeyFile.rdbuf();
        std::string publicKey = publicKeyStream.str();
        send(sfd, publicKey.c_str(), publicKey.size(), 0);  
        
        
        bool loggedIn = false;
        std::string ticketFilename,signatureFilename;
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
                    std::cout << "Sending " << (choice == 1 ? "signup" : "login") << " request to the server..." << std::endl;
                    std::string  hashedPassword;
                    
                    std::string encryptedUsername = RSAEncrypt(username);
                    SHA256 hash;
                    StringSource(password, true, new HashFilter(hash, new StringSink(hashedPassword)));
                    send(sfd, &choice, sizeof(choice), 0);
                    sleep(1);
                    send(sfd, encryptedUsername.c_str(), encryptedUsername.size(), 0);
                    sleep(1);
                    send(sfd, hashedPassword.c_str(), hashedPassword.size(), 0);
                    char response[1000];
                    recv(sfd, response, sizeof(response), 0);
                    std::string response1 = response;
                    response1 = decrypt(response1);
                    if(strcmp(response1.c_str(),"you are logged in")==0)
                    {
                        loggedIn=true;
                    }
                    std::cout<<response1<<"\n";
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
                std::cout<<"enter command(get_ticket / verify_ticket/log_out)"<<std::endl;
                std::getline(std::cin, kk);
                send(sfd,kk.c_str(),sizeof(kk),0);
                sleep(1);
                if(kk=="get_ticket")
                {
                    std::string buff;
                    std::cout<<"enter name\n";
                    std::getline(std::cin, buff);
                    buff = RSAEncrypt(buff);
                    send(sfd,buff.c_str(),buff.size(),0);
                    sleep(1);
                    std::cout<<"enter date of journey\n";
                    std::getline(std::cin, buff);
                    buff = RSAEncrypt(buff);
                    send(sfd,buff.c_str(),buff.size(),0);
                    sleep(1);
                    std::cout<<"enter to address\n";
                    std::getline(std::cin, buff);
                    buff = RSAEncrypt(buff);
                    sleep(1);
                    send(sfd,buff.c_str(),buff.size(),0);
                    std::cout<<"enter from address\n";
                    sleep(1);
                    std::getline(std::cin, buff);
                    buff = RSAEncrypt(buff);
                    send(sfd,buff.c_str(),buff.size(),0);
                    char response[1000];
                    int ticketID = ticketCounter.fetch_add(1); 
                    ticketFilename="user_ticket_"+std::to_string(ticketCounter)+".txt";
                    signatureFilename="user_signature_"+std::to_string(ticketCounter)+".txt";
                    std::ofstream ticketFile(ticketFilename.c_str());
                    std::ofstream signatureFile(signatureFilename.c_str());
                    int bytes_received=0;
                    char buffer1[1000];
                    int cnt=0;
                    std::string name="user_ticket_"+std::to_string(ticketCounter);
                    while ((bytes_received = recv(sfd,buffer1,sizeof(buffer1),0)) > 0) 
                    {
                        std::string temp  =  buffer1;
                        temp =  decrypt(temp);

                        cnt++;
                        if(cnt==1)
                        {
                           std::cout<<"ticket- "<<name<<" recieved from signer is:"<<std::endl;
                            std::cout<<"**************************"<<std::endl;
                        }
                        ticketFile<<temp.c_str()<<std::endl;
                        std::cout<<temp.c_str()<<std::endl;
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
                    std::string input;
                    std::cout<<"enter ticket name you want to verify"<<std::endl;
                    std::getline(std::cin,input);
                    input+=".txt";
                    ticketFilename=input;
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
                    FileSource hashing(ticketFilename.c_str(), true, new HashFilter(hash,new HexEncoder(new StringSink(msg_hash))));
                    std::cout<<"do you want to change any field of ticket\nEnter : 1 to edit  0 to not edit"<<std::endl;
                    int choice;
                    std::cin>>choice;
                    if(choice==1)
                    {
                    int ch;
                    
                    std::ifstream editfile(ticketFilename.c_str());
                    if(!editfile.is_open())std::cout<<"error in opening file"<<std::endl;
                    std::vector<std::string> lines;
                    std::string line;
                    std::cout<<"this is the original ticket"<<std::endl;
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
                    std::ofstream writefile(ticketFilename.c_str());
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
                    std::cout<<"modified ticket is  transmitted for verification"<<std::endl;
                    else
                    std::cout<<"Original ticket is transmitted for verification"<<std::endl;
                    std::ifstream ticketFile(ticketFilename.c_str());
                    std::ifstream signatureFile(signatureFilename.c_str());
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
                    if(choice==0)std::cin.ignore();
                }
                else if(kk=="log_out")
                {
                    loggedIn=0;
                    
                }


            }
            
        }

        close(sfd);

        return 0;
    }
