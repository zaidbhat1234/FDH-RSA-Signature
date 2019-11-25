//
//  FDH_ver_sig.cpp
//  RSA
//
//  Created by Zaid Bhat on 09/02/19.
//  Copyright © 2019 Zaid Bhat. All rights reserved.
//

#include "FDH_ver_sig.hpp"
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

#include <sha.h>
#include "filters.h"
#include "base64.h"
#include <hex.h>

#include "integer.h"
#include "osrng.h"
#include "nbtheory.h"
#include "hrtimer.h"
#include "FDH_sig.hpp"
#include "FDH_sig.hpp"

using namespace std;

using namespace CryptoPP;

mpz_class power1_(mpz_class x, mpz_class y, mpz_class p)
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

void FDH_ver_signature_(FILE *ptr){
    
   
    int length;
    fscanf(ptr,"%d",&length);
    //cout<<"LENGTH"<<length;
     char temp__[length];
    fscanf(ptr,"%s",temp__);
    mpz_class sig_hash;
    sig_hash =temp__;
    
    //cout<<"SIG"<<sig_hash;
    fscanf(ptr,"%d",&length);
   
    char temp_b[length];
    fscanf(ptr,"%s",temp_b);
    mpz_class b;
    b =temp_b;
    
    
    
    fscanf(ptr,"%d",&length);
    
    char temp_n[length];
    //cout<<"HAHAHHAH"<<length;
    fscanf(ptr,"%s",temp_n);
    mpz_class n;
    n =temp_n;
    
    //cout<<"N is:"<<n;
    fclose(ptr);
    std::ifstream ifs("SampleTextFile_10kb.txt");
    std::string message( (std::istreambuf_iterator<char>(ifs) ),
                        (std::istreambuf_iterator<char>()    ) );
  
   //
   // cout<<"hashsig"<<temp__;
   
 //   fscanf(ptr, "%s",temp__);
   
   // cout<<message;
    string final = "";
    std::stringstream stream;
    final = FDH_(message);   //function for full domain hash
    final.erase(final.length()-1,1);
    mpz_class hash_int;
    stream<<final;
    stream>>std::hex>>hash_int; //used to store the string of hex as int into gmp class
    // cout<<"hash int:"<<hash_int<<'\n';
    
    
    mpz_class sig_hash_ver = power1_(sig_hash, b, n);
    //sig_hash_ver= sig_hash_ver^r_h;
    if(sig_hash_ver==hash_int){
        cout<<"VERIFIED THE SIGNED MESSAGE PRODUCED WITH HASH"<<'\n';
    }
    else
        cout<<"not verified hash"<<'\n';
    
}
