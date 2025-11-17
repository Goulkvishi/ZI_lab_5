#include "rsa.h"
#include <boost/multiprecision/miller_rabin.hpp>

using namespace boost::multiprecision;

// Нахождение общего делителя
cpp_int RSA::GCD(cpp_int a, cpp_int b) {
    if (b == 0) return a;
    return GCD(b, a % b);
}

// Решение Диофантова уравнения a*x + b*y = 1
void RSA::DiophantEquation(cpp_int a, cpp_int b, cpp_int& x, cpp_int& y) {
    cpp_int a11 = 1, a12 = 0, a21 = 0, a22 = 1;

    while (true) {
        cpp_int r = a % b;
        if (r == 0) {
            x = a12;
            y = a22;
            return;
        }
        else {
            cpp_int q = a / b;
            cpp_int save12 = a12;
            cpp_int save22 = a22;
            a12 = a11 - save12 * q;
            a22 = a21 - save22 * q;
            a11 = save12;
            a21 = save22;
            a = b;
            b = r;
        }
    }
}

// Поиск числа y, такого что (x*y)%m == 1
cpp_int RSA::FindNumber(cpp_int x, cpp_int m) {
    cpp_int y, sux;
    DiophantEquation(m, x, sux, y);
    while (y < 0)
        y += m;
    return y;
}

// Вычисление (a в степени b)%m
cpp_int RSA::Power(cpp_int a, cpp_int b, cpp_int m) {
    cpp_int result = 1;
    a %= m;

    while (b > 0) {
        if (b % 2 == 1) {
            result = (result * a) % m;
        }
        a = (a * a) % m;
        b /= 2;
    }

    return result;
}

// Генерация пары ключей
void RSA::GenerateKeyPair(cpp_int p, cpp_int q, cpp_int e, RsaPublicKey& pub, RsaPrivateKey& pri) {
    if ((GCD(e, p - 1) != 1) || (GCD(e, q - 1) != 1)) {
        throw std::invalid_argument("GenerateKeyPair: Incorrect parameters\n");
    }
    
    pub.n = p * q;
    pri.n = p * q;
    pub.e = e;

    // Функция Эйлера
    cpp_int phi = (p - 1) * (q - 1);
    pri.d = FindNumber(e, phi);
}

// Шифрование: C = M^e mod n
cpp_int RSA::Encode(cpp_int message, const RsaPublicKey& key) {
    return Power(message, key.e, key.n);
}

// Дешифрование: M = C^d mod n
cpp_int RSA::Decode(cpp_int cipher, const RsaPrivateKey& key) {
    return Power(cipher, key.d, key.n);
}
