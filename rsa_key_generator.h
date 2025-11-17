#ifndef RSA_KEY_GENERATOR_H
#define RSA_KEY_GENERATOR_H

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/random.hpp>
#include <random>
#include <ctime>

using namespace boost::multiprecision;
using namespace boost::random;

class RSAKeyGenerator {
private:
    static mt19937 rng;

public:
    static cpp_int GenerateRandomBits(int bits_count) {
        cpp_int result = 0;

        int full_chunks = bits_count / 32;
        int remaining_bits = bits_count % 32;

        std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);

        for (int i = 0; i < full_chunks; i++) {
            result = (result << 32) | dist(rng);
        }

        if (remaining_bits > 0) {
            uint32_t mask = (1ULL << remaining_bits) - 1;
            result = (result << remaining_bits) | (dist(rng) & mask);
        }

        result |= (cpp_int(1) << (bits_count - 1));

        return result;
    }

    static bool IsPrime(const cpp_int& n, int k = 25) {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;

        return miller_rabin_test(n, k, rng);
    }

    static cpp_int GeneratePrime(int bits_count) {
        cpp_int candidate;
        int attempts = 0;

        do {
            candidate = GenerateRandomBits(bits_count);

            if (candidate % 2 == 0) {
                candidate++;
            }

            attempts++;

            if (IsPrime(candidate)) {
                return candidate;
            }

            if (attempts > 10000) {
                throw std::runtime_error("Не удалось сгенерировать простое число за 10000 попыток");
            }

        } while (true);

        return candidate;
    }

    static cpp_int gcd(cpp_int a, cpp_int b) {
        while (b != 0) {
            cpp_int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    static bool IsValidExponent(const cpp_int& e, const cpp_int& phi) {
        return gcd(e, phi) == 1;
    }

    static cpp_int GenerateExponent(const cpp_int& phi) {
        std::vector<cpp_int> common_e = {
            65537,
            257,
            17,
            3
        };

        for (const auto& e : common_e) {
            if (e < phi && IsValidExponent(e, phi)) {
                return e;
            }
        }

        cpp_int e_candidate = 65537;
        while (e_candidate < phi) {
            if (IsPrime(e_candidate) && IsValidExponent(e_candidate, phi)) {
                return e_candidate;
            }
            e_candidate += 2;
        }

        throw std::runtime_error("Не удалось найти подходящее e");
    }

    static void Seed(unsigned int seed = static_cast<unsigned int>(std::time(nullptr))) {
        rng.seed(seed);
    }
};

mt19937 RSAKeyGenerator::rng(static_cast<unsigned int>(std::time(nullptr)));

#endif
