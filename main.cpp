//
//  main.cpp
//  Rsa_Fdh_signing
//
//  Created by Zaid Bhat on 18/02/19.
//  Copyright © 2019 Zaid Bhat. All rights reserved.
//

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
#include<stdlib.h>
#include <fstream>

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
#include "FDH_sig.hpp"
#include "FDH_ver_sig.hpp"

#include "Gen_dec_key.hpp"
#include "Gen_prime.hpp"



int main() {
 
    
    
    FILE *ptrP = fopen("Primep.txt", "w");
    FILE *ptrQ = fopen("Primeq.txt", "w");
    
    
    
    
    int length;
    mpz_class p =   Gen_prime(1024,1,ptrP);
    
    mpz_class q = Gen_prime(1024,2,ptrQ);
    fclose(ptrP);
    fclose(ptrQ);
    
    std::ifstream ifs("SampleTextFile_10kb.txt");
    std::string message( (std::istreambuf_iterator<char>(ifs) ),
                        (std::istreambuf_iterator<char>()    ) );
    //cout<<"CONTENT :"<<'\n'<<message.c_str();
    
    mpz_class x,y;
    //find b
    mpz_class n,phi;
    n=p*q;
    // cout<<"n is "<<n<<'\n';
    
    
    
    
    // FILE *ptrP,*ptrQ;
    
    ptrP = fopen("pub_key.txt", "w");
    ptrQ = fopen("pri_key.txt", "w");
    
    
    Gen_dec_key(ptrP, ptrQ);
    
    
    
    ptrP = fopen("pub_key.txt", "r");
    ptrQ = fopen("pri_key.txt", "r");
    fscanf(ptrP,"%d",&length);
    //cout<<"LENGTH"<<length;
    char temp_bb[length];
    fscanf(ptrP,"%s",temp_bb);
    mpz_class b;
    b =temp_bb;
    fscanf(ptrQ,"%d",&length);
    //cout<<"LENGTH"<<length;
    char temp_aa[length];
    fscanf(ptrQ,"%s",temp_aa);
    mpz_class a;
    a =temp_aa;
    
    fclose(ptrP);
    fclose(ptrQ);
    
    
    FILE *ptrrsa = fopen("rsapub.txt", "w"); //to store public values of RSA in order n , enc message, public key.
    
    
    
    string tem_f;
    char tem_n[tem_f.length()];
    tem_f = n.get_str();
    fprintf(ptrrsa, "%ld %s ",tem_f.length(),tem_n);
    
    fclose(ptrrsa);
    
    FILE *ptr = fopen("public.txt", "w");
    //to generate signed hash message and verify that. WRITE SEPERATE FUNCTION FOR THIS.
    
    FILE *ptr1= fopen("pub_fdh_gen_sig.txt", "w");
    
    
    string temp_f = a.get_str();
    char temp_a[temp_f.length()];
    strcpy(temp_a, temp_f.c_str());
    fprintf(ptr1, "%ld %s ",temp_f.length(),temp_a);
    
    
    temp_f = n.get_str();
    char temp_n[temp_f.length()];
    strcpy(temp_n, temp_f.c_str());
    fprintf(ptr1, "%ld %s ",temp_f.length(),temp_n);
    
    
    fclose(ptr1);
    ptr1 =fopen("pub_fdh_gen_sig.txt", "r");
    
    
    
    
    
    
    
    mpz_class sig_hash;
    
    
    
    ptr1 =fopen("pub_fdh_gen_sig.txt", "r");
    sig_hash =  FDH_sig_gen(message, ptr1);// generating hash signature
    
    fclose(ptr1);
    //cout<<"HDH"<<sig_hash;
    temp_f = sig_hash.get_str();
    char temp__[temp_f.length()];
    strcpy(temp__, temp_f.c_str());
    fprintf(ptr, "%ld %s ",temp_f.length(),temp__);
    
    temp_f = b.get_str();
    char temp_b[temp_f.length()];
    strcpy(temp_b, temp_f.c_str());
    fprintf(ptr, "%ld %s ",temp_f.length(),temp_b);
    
    temp_f = n.get_str();
    fprintf(ptr, "%ld %s ",temp_f.length(),temp_n);
    fprintf(ptr, "%ld %s ",message.length(),message.c_str());
    
    
    
    fclose(ptr);
    
    
    ptr = fopen("public.txt", "r");
    
    
    
    
    FDH_ver_signature_(ptr);  // function to verify hash signature
    
    
    
    fclose(ptr);
    
    
    
    
    
}
