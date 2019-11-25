//
//  Gen_prime.cpp
//  RSA
//
//  Created by Zaid Bhat on 09/02/19.
//  Copyright © 2019 Zaid Bhat. All rights reserved.
//

#include "Gen_prime.hpp"
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




mpz_class  Gen_prime(int size,int flag,FILE *ptr){
    /*
    FILE *ptr;
    
    if (flag ==1) {
       ptr =fopen("Primep.txt", "w");
    }
    else{
        ptr =fopen("Primeq.txt", "w");
    }
    */
    
    //not able to write to files like this, works when we pass the file pointers as arguments but gives mps_str error
    
    
   // ThreadUserTimer timer;
    AutoSeededRandomPool prng;
    Integer x;
    
   // timer.StartTimer();
    
    do {
        x.Randomize(prng, size);
    } while(!IsPrime(x));
    
   // double t = timer.ElapsedTimeAsDouble();
  // std::cout << "Time: " << t << " seconds" << std::endl;
    //std::cout << x << std::endl;
    string s1;
    mpz_class temp;
    
    stringstream s;
    s<<x;
    s>>s1;
    
    stringstream s11;
    s11<<x;
    s11>>temp;
    //cout<<temp;
    //cout<<'\n'<<s1;
   
    char s_p[s1.length()];
    strcpy(s_p, s1.c_str());
    
    
    fprintf(ptr, "%ld %s",s1.length(),s_p);
   
    return temp;
    
    
}
