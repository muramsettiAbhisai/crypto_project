#include <iostream>
#include <fstream>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/files.h>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    
    InvertibleRSAFunction p_privateKey;
    p_privateKey.Initialize(rng, 1024);

    
    RSA::PublicKey p_publicKey(p_privateKey);

    // Save private key to file
    
        FileSink privateKeyFile("my_rsa_private2.bin");
        p_privateKey.DEREncode(privateKeyFile);
    

    // Save public key to file
    
        FileSink publicKeyFile("my_rsa_public2.bin");
        p_publicKey.DEREncode(publicKeyFile);
    

    return 0;
}

