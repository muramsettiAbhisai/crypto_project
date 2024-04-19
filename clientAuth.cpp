#include <bits/stdc++.h>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <crypto++/sha.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sstream>
#include <unistd.h>

using namespace CryptoPP;

std::string addPadding(const std::string& input, size_t blockSize) {
    size_t paddingSize = blockSize - (input.size() % blockSize);
    char paddingChar = static_cast<char>(paddingSize);
    std::string paddedInput = input + std::string(paddingSize, paddingChar);
    return paddedInput;
}

std::string encryptDES(const std::string& input) {
    std::string ciphertext;
    ECB_Mode<DES>::Encryption encryptor;
    unsigned char key[DES::DEFAULT_KEYLENGTH];
    std::memcpy(key, "01234567", DES::DEFAULT_KEYLENGTH);
    encryptor.SetKey(key, DES::DEFAULT_KEYLENGTH);
     std::string paddedInput = addPadding(input, CryptoPP::DES::BLOCKSIZE);
    StringSource(paddedInput, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
    return ciphertext;
}

std::string hash_to_string(const unsigned char *value, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length - 1; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(value[i]) << ":";
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(value[length - 1]);
    return ss.str();
}



std::string sha256(std::string& password) {
    std::string digest;
    SHA256 hash;
    hash.Update(reinterpret_cast<const byte*>(password.data()), password.size());
    digest.resize(hash.DigestSize());
    hash.Final(reinterpret_cast<byte*>(&digest[0])); 
    digest=hash_to_string(reinterpret_cast<byte*>(digest.data()), hash.DigestSize());  
    std::cout<<"hash is: "<<digest<<std::endl;
    return digest;     
}
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
    
    std::string username, password;
    std::cout << "Enter username: "<<std::endl;
    std::getline(std::cin,username);
    std::cout << "Enter password: "<<std::endl;
    std::cin >> password;

    std::string encryptedUsername = encryptDES(username);
    std::cout<<"encryptedUsername is:"<<encryptedUsername<<std::endl;
    std::string hashedPassword = sha256(password);
    
    send(sfd, encryptedUsername.c_str(), encryptedUsername.size(), 0);
    sleep(1);
    send(sfd, hashedPassword.c_str(), hashedPassword.size(), 0);
 
    shutdown(sfd, SHUT_RDWR);

    return 0;
}

