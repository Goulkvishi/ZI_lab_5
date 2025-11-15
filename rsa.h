#ifndef RSA_H
#define RSA_H

#include <boost/multiprecision/cpp_int.hpp>
#include <string>
#include <vector>
#include <stdexcept>

using namespace boost::multiprecision;

struct RsaPublicKey {
    cpp_int e;
    cpp_int n;
};

struct RsaPrivateKey {
    cpp_int d;
    cpp_int n;
};

class RSA {
public:
    static void GenerateKeyPair(cpp_int p, cpp_int q, cpp_int e, RsaPublicKey& pub, RsaPrivateKey& pri);
    static cpp_int Encode(cpp_int message, const RsaPublicKey& key);
    static cpp_int Decode(cpp_int cipher, const RsaPrivateKey& key);
    static cpp_int Power(cpp_int a, cpp_int b, cpp_int m);
    static cpp_int GCD(cpp_int a, cpp_int b);
    static cpp_int FindNumber(cpp_int x, cpp_int m);
    static void DiophantEquation(cpp_int a, cpp_int b, cpp_int& x, cpp_int& y);
};

#endif
