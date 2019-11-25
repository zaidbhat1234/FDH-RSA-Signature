//
//  Gen_dec_key.hpp
//  RSA
//
//  Created by Zaid Bhat on 10/02/19.
//  Copyright © 2019 Zaid Bhat. All rights reserved.
//

#ifndef Gen_dec_key_hpp
#define Gen_dec_key_hpp

#include <stdio.h>
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
mpz_class Gen_dec_key( FILE * ptr1,FILE *ptr2);
mpz_class gcdExtended1(mpz_class a, mpz_class b, mpz_class *x, mpz_class *y);

#endif /* Gen_dec_key_hpp */
