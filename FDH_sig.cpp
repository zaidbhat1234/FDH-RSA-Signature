//
//  FDH_sig.cpp
//  RSA
//
//  Created by Zaid Bhat on 09/02/19.
//  Copyright © 2019 Zaid Bhat. All rights reserved.
//

#include "FDH_sig.hpp"
#include <iostream>
#include <math.h>
#include <gmpxx.h>
#include <primesieve.hpp>
#include <math.h>
#include <time.h>
#include <string.h>
#include <chrono>
#include <thread>
#include <functional>
#include <cryptlib.h>
#include <iomanip>

#include <fstream>
#include "FDH_ver_sig.hpp"
#include <sha.h>
#include "filters.h"
#include "base64.h"
#include <hex.h>

#include "integer.h"
#include "osrng.h"
#include "nbtheory.h"
#include "hrtimer.h"

using namespace std;

using namespace CryptoPP;






string SHA256_(string data)
{
    CryptoPP::byte const* pbData = ( CryptoPP::byte*) data.data();
    unsigned int nDataLen = data.size();
    CryptoPP::byte abDigest[CryptoPP::SHA256::DIGESTSIZE];
    
    CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);
    
    return string((char*)abDigest);
}
mpz_class power_1(mpz_class x, mpz_class y, mpz_class p)
{
    mpz_class res = 1;      // Initialize result
    
    x = x % p;  // Update x if it is more than or
    // equal to p
    
    while (y > 0)
    {
        // If y is odd, multiply x with result
        if (y%2!=0)
            res = (res*x) % p;
        
        // y must be even now
        y = y>>1; // y = y/2
        x = (x*x) % p;
    }
    return res;
}



string FDH_(string message){
    
     FILE *ptrrsa = fopen("rsapub.txt", "r");
    int l=0;
    fscanf(ptrrsa, "%d",&l);
    //cout<<"LENGTH OF CYCLES= "<<l;
    fclose(ptrrsa);
    l=l/77;
   // cout<<"LENGTH OF CYCLES= "<<l;
    
    string c[16]={"1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16"};
    
    string final="";
    std::stringstream stream;
    string output;
    int h;
    for (h=0; h<l; h++) {
        
        message.append(c[h]);
        //cout<<message;
        
        
        CryptoPP::SHA256 hash;
        CryptoPP::byte digest[ CryptoPP::SHA256::DIGESTSIZE ];
        // string message = "abcdefgh";         //the message that needs to be hashed to 256 bits.
        
        hash.CalculateDigest( digest, reinterpret_cast< CryptoPP::byte*>(&message[0]), message.length() );
        
        CryptoPP::HexEncoder encoder;
        output="";
        encoder.Attach( new CryptoPP::StringSink( output ) );
        encoder.Put( digest, sizeof(digest) );
        encoder.MessageEnd();
        //cout<<"FINAL:"<<final<<'\n';
        final.append(output);
        //cout<<"FINAL:"<<final<<'\n';
        message.erase(message.length()-1,1);
        
        
        //cout<<message;
    }
    return final;
}


mpz_class FDH_sig_gen(string message ,FILE *ptr){
    
    
         //cout<<"CONTENT :"<<'\n'<<message.c_str();
    
   // cout<<message;
    string final = "";
    std::stringstream stream;
    final = FDH_(message);   //function for full domain hash
    final.erase(final.length()-1,1);
    
    mpz_class hash_int;
    stream<<final;
    stream>>std::hex>>hash_int; //used to store the string of hex as int into gmp class
    //cout<<"hash int:"<<hash_int<<'\n';
    
    
    
    int length;
    fscanf(ptr,"%d",&length);
    //cout<<"LENGTH"<<length;
    char temp_a[length];
    fscanf(ptr,"%s",temp_a);
    mpz_class a;
    a =temp_a;
   // cout<<'\n'<<a;
    fscanf(ptr,"%d",&length);
    //cout<<"LENGTH"<<length;
    char temp_n[length];
    fscanf(ptr,"%s",temp_n);
    mpz_class n;
    n =temp_n;
    
    
    
    mpz_class sig_hash =  power_1(hash_int, a, n);
    
    string temp_f = sig_hash.get_str();
    char temp_h[temp_f.length()];
    strcpy(temp_h, temp_f.c_str());
    fprintf(ptr, "%ld %s ",temp_f.length(),temp_h);
    
    
    
    return sig_hash;
}


