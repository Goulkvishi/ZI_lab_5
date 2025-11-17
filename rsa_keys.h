#ifndef RSA_KEYS_H
#define RSA_KEYS_H

#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision;

const cpp_int P = cpp_int("53");
const cpp_int Q = cpp_int("59");

const cpp_int E = 3;

#endif
