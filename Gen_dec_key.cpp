//
//  Gen_dec_key.cpp
//  RSA
//
//  Created by Zaid Bhat on 10/02/19.
//  Copyright © 2019 Zaid Bhat. All rights reserved.
//

#include "Gen_dec_key.hpp"
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
using namespace std;

using namespace CryptoPP;

mpz_class gcdExtended1(mpz_class a, mpz_class b, mpz_class *x, mpz_class *y)
{
    // Base Case
    if (a == 0)
    {
        *x = 0;
        *y = 1;
        return b;
    }
    
    mpz_class x1, y1; // To store results of recursive call
    mpz_class gcd = gcdExtended1(b%a, a, &x1, &y1);
    
    // Update x and y using results of recursive
    // call
    *x = y1 - (b/a) * x1;
    *y = x1;
    
    return gcd;
}

mpz_class Gen_dec_key( FILE * ptr1,FILE *ptr2){
    
    
    
    mpz_class d;
     mpz_class x,y;
    
    int length;
    
    FILE *temp = fopen("Primep.txt", "r");
    
    fscanf(temp, "%d",&length);
   
    char p_[length];
    fscanf(temp, "%s",p_);
         mpz_class p;
     //
    std::stringstream ss;
    ss<<p_;
    ss>>p;
   // p=p_;
    fclose(temp);
  
    temp = fopen("Primeq.txt", "r");
    fscanf(temp, "%d",&length);
    char q_[length];
    fscanf(temp, "%s",q_);
    mpz_class q;
    std::stringstream ss1;
    ss1<<q_;
    ss1>>q;
  //  q=q_;
    
    mpz_class phi;
    phi = (p-1)*(q-1);
    mpz_class b =2 ;
    
    mpz_class gcd = gcdExtended1(b,phi,&x,&y);
    while(gcd!=1)
    {
        b++;
        gcd = gcdExtended1(b,phi,&x,&y);
    }
    
    mpz_class a = x;
    if(a<0){
        a=a+ phi;}
    
    string temp_f = b.get_str();
    char temp_b[temp_f.length()];
    strcpy(temp_b, temp_f.c_str());
    fprintf(ptr1, "%ld %s ",temp_f.length(),temp_b);
    
    temp_f = a.get_str();
    char temp_a[temp_f.length()];
    strcpy(temp_a, temp_f.c_str());
    fprintf(ptr2, "%ld %s ",temp_f.length(),temp_a);
    
    fclose(ptr1);
    fclose(ptr2);
    
    return d;
    
}
