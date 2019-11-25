//
//  FDH_ver_sig.hpp
//  RSA
//
//  Created by Zaid Bhat on 09/02/19.
//  Copyright © 2019 Zaid Bhat. All rights reserved.
//

#ifndef FDH_ver_sig_hpp
#define FDH_ver_sig_hpp
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

using namespace std;

using namespace CryptoPP;
#include <stdio.h>


void FDH_ver_signature_(FILE *ptr);
#endif /* FDH_ver_sig_hpp */
