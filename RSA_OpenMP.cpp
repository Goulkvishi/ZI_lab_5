#include <iostream>
#include <omp.h>
#include <ctime>
#include <vector>
#include <iomanip>
#include <cmath>
#include "rsa.h"
#include "rsa_keys.h"

using namespace std;
using namespace boost::multiprecision;

vector<cpp_int> GenerateMessages(int count, cpp_int max_value) {
    vector<cpp_int> messages;
    srand(time(NULL));
    for (int i = 0; i < count; i++) {
        cpp_int msg = 0;
        for (int j = 0; j < 10; j++) {
            msg = (msg << 30) + rand();
        }
        msg = msg % max_value;
        messages.push_back(msg);
    }
    return messages;
}

void SequentialEncryptDecrypt(const vector<cpp_int>& messages, const RsaPublicKey& pub, const RsaPrivateKey& pri, vector<bool>& results) {
    for (size_t i = 0; i < messages.size(); i++) {
        cpp_int encrypted = RSA::Encode(messages[i], pub);
        cpp_int decrypted = RSA::Decode(encrypted, pri);
        results[i] = (decrypted == messages[i]);
    }
}

void ParallelEncryptDecrypt(const vector<cpp_int>& messages, const RsaPublicKey& pub, const RsaPrivateKey& pri, vector<bool>& results, int num_threads) {
    omp_set_num_threads(num_threads);

#pragma omp parallel for
    for (int i = 0; i < (int)messages.size(); i++) {
        cpp_int encrypted = RSA::Encode(messages[i], pub);
        cpp_int decrypted = RSA::Decode(encrypted, pri);
        results[i] = (decrypted == messages[i]);
    }
}

int main() {
    setlocale(LC_CTYPE, "Russian_Russia.1251");

    cout << "=== Тестирование RSA с OpenMP ===" << endl << endl;

    cpp_int p = 29;
    cpp_int q = 19;
    cpp_int e = 47;

    vector<cpp_int> messages = { 19, 13, 30, 350, 500, 19, 13, 30, 350, 500 };
    int l = messages.size();

    RsaPublicKey publicKey;
    RsaPrivateKey privateKey;

    try {
        RSA::GenerateKeyPair(p, q, e, publicKey, privateKey);

        cout << "Открытый ключ (e, n): " << publicKey.e << ", " << publicKey.n << endl;
        cout << "Закрытый ключ (d, n): " << privateKey.d << ", " << privateKey.n << endl << endl;

        cout << "Исходное\tЗашифр.\t\tДешифр.\t\tКорректно?" << endl;
        cout << "==========================================================" << endl;

        vector<cpp_int> encrypted_results(l);
        vector<cpp_int> decrypted_results(l);
        vector<bool> status(l);

        #pragma omp parallel for
        for (int i = 0; i < l; i++) {
            cpp_int source = messages[i] % publicKey.n;
            cpp_int encrypted = RSA::Encode(source, publicKey);
            cpp_int decrypted = RSA::Decode(encrypted, privateKey);

            encrypted_results[i] = encrypted;
            decrypted_results[i] = decrypted;
            status[i] = (decrypted == source);
        }

        for (int i = 0; i < l; i++) {
            cpp_int source = messages[i] % publicKey.n;
            string ok_status = status[i] ? "ДА" : "НЕТ";
            cout << source << "\t\t" << encrypted_results[i] << "\t\t"
                << decrypted_results[i] << "\t\t" << ok_status << endl;
        }

        cout << "\nТест завершен успешно!" << endl;
    }
    catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }

    return 0;
}
