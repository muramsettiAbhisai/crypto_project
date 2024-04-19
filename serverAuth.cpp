#include <iostream>
#include <string>
#include <map>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>


using namespace CryptoPP;

std::map<std::string,std::string> userMap;
std::string removePadding(const std::string& input) {
    size_t paddingSize = static_cast<size_t>(input[input.length() - 1]);
    return input.substr(0, input.length() - paddingSize);
}

std::string decryptDES(const std::string& ciphertext) {
    std::string plaintext;
    ECB_Mode<DES>::Decryption decryptor;
    unsigned char key[DES::DEFAULT_KEYLENGTH];
    std::memcpy(key, "01234567", DES::DEFAULT_KEYLENGTH);
    decryptor.SetKey(key, DES::DEFAULT_KEYLENGTH);
     
    StringSource(ciphertext, true,new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
    plaintext = removePadding(plaintext);
    return plaintext;
}



void storeCredentials(const std::string& decryptedUsername, const std::string& hashedPassword) {
 
    userMap[decryptedUsername] = hashedPassword;
}





int main() {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(8081);

    bind(sfd, reinterpret_cast<struct sockaddr*>(&server_address), sizeof(server_address));
      

    listen(sfd, 3); 
      

    int nsfd = accept(sfd,NULL,NULL);
    
    
    char username[1000000];
    recv(nsfd, username, sizeof(username), 0);
    char password[1000000];
    recv(nsfd, password, sizeof(password), 0);
    
    std::cout<<"recieved encrypted username:"<<username<<std::endl;
   
    std::cout<<"recieved hashedpwd:"<<password<<std::endl;
    
    std::string encryptedUsername = username;
    
    std::string decryptedUsername= decryptDES(username);
    
    std::cout<<"decrypted username:"<<decryptedUsername<<std::endl;
    
    std::string hashedPassword = password;
   
    storeCredentials(decryptedUsername, hashedPassword);
   
    for(auto it:userMap)
    {
       std::cout<<it.first<<"->"<<it.second<<std::endl;
     
    }

    close(nsfd);
    close(sfd);

    return 0;
}
