//
//  Gen_prime.hpp
//  RSA
//
//  Created by Zaid Bhat on 09/02/19.
//  Copyright © 2019 Zaid Bhat. All rights reserved.
//

#ifndef Gen_prime_hpp
#define Gen_prime_hpp

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



mpz_class Gen_prime(int size, int flag,FILE *ptr);

#endif /* Gen_prime_hpp */
