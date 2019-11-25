//
//  FDH_sig.hpp
//  RSA
//
//  Created by Zaid Bhat on 09/02/19.
//  Copyright © 2019 Zaid Bhat. All rights reserved.
//

#ifndef FDH_sig_hpp
#define FDH_sig_hpp

#include <stdio.h>

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

string FDH_(string message);
string SHA256_(string data);
mpz_class power_1(mpz_class x, mpz_class y, mpz_class p);
mpz_class FDH_sig_gen(string message,FILE *ptr);
mpz_class power_1(mpz_class x, mpz_class y, mpz_class p);

#endif /* FDH_sig_hpp */
