#include <iostream>
#include <omp.h>
#include <ctime>
#include <vector>
#include <iomanip>
#include <fstream>
#include <sstream>
#include "rsa.h"
#include "rsa_keys.h"

using namespace std;
using namespace boost::multiprecision;

vector<cpp_int> LoadMessagesFromFile(const string& filename, cpp_int max_value) {
    vector<cpp_int> messages;
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "Ошибка: не удалось открыть файл! " << filename << endl;
        return messages;
    }

    int count;
    file >> count;

    cout << "  Чтение " << count << " сообщений из файла " << filename << "..." << flush;

    for (int i = 0; i < count; i++) {
        cpp_int msg;
        file >> msg;

        if (msg >= max_value) {
            msg = msg % max_value;
            if (msg == 0) msg = 1;
        }

        messages.push_back(msg);
    }

    file.close();
    cout << " OK" << endl;
    return messages;
}


pair<int, double> SequentialEncryptDecrypt(const vector<cpp_int>& messages, const RsaPublicKey& pub, const RsaPrivateKey& pri) {
    int correct_count = 0;
    double start = omp_get_wtime();

    for (size_t i = 0; i < messages.size(); i++) {
        cpp_int encrypted = RSA::Encode(messages[i], pub);
        cpp_int decrypted = RSA::Decode(encrypted, pri);

        if (decrypted == messages[i]) {
            correct_count++;
        }
    }

    double end = omp_get_wtime();
    double time_ms = (end - start) * 1000;

    return { correct_count, time_ms };
}

pair<int, double> ParallelEncryptDecrypt(const vector<cpp_int>& messages, const RsaPublicKey& pub, const RsaPrivateKey& pri, int num_threads) {
    int correct_count = 0;
    omp_set_num_threads(num_threads);

    double start = omp_get_wtime();

#pragma omp parallel for reduction(+:correct_count)
    for (int i = 0; i < (int)messages.size(); i++) {
        cpp_int encrypted = RSA::Encode(messages[i], pub);
        cpp_int decrypted = RSA::Decode(encrypted, pri);

        if (decrypted == messages[i]) {
            correct_count++;
        }
    }

    double end = omp_get_wtime();
    double time_ms = (end - start) * 1000;

    return { correct_count, time_ms };
}

int main() {
    setlocale(LC_CTYPE, "Russian_Russia.1251");

    cout << "=== Тестирование RSA с OpenMP ===" << endl << endl;

    RSAKeyGenerator::Seed();

    cout << "Генерация p (1024 бит)..." << flush;
    cpp_int p = RSAKeyGenerator::GeneratePrime(1024);
    cout << " OK (" << p.str().length() << " разрядов) \np= " << p << endl;

    cout << "Генерация q (1024 бит)..." << flush;
    cpp_int q = RSAKeyGenerator::GeneratePrime(1024);
    cout << " OK (" << q.str().length() << " разрядов) \nq= " << q << endl;

    cpp_int phi = (p - 1) * (q - 1);
    cout << "Генерация e..." << flush;
    cpp_int e = RSAKeyGenerator::GenerateExponent(phi);
    cout << " OK" << endl << endl;

    RsaPublicKey publicKey;
    RsaPrivateKey privateKey;

    try {
        cout << "Генерация ключей RSA..." << endl;
        RSA::GenerateKeyPair(p, q, e, publicKey, privateKey);

        cout << "  Размер модуля n: " << publicKey.n.str().length() << " разрядов" << endl;
        cout << "  Открытый ключ: \ne=" << publicKey.e << ", \nn=" << publicKey.n << endl;
        cout << "  Закрытый ключ: \nd=" << privateKey.d << ", \nn=" << privateKey.n << endl << endl;

        vector<string> test_files = {
            "test_data_small.txt",
            "test_data_medium.txt",
            "test_data_large.txt"
        };
        int thread_count = 8;

        cout << left << setw(18) << "Размер набора"
            << setw(16) << "Посл.(мс)"
            << setw(14) << "Парал.(мс)"
            << setw(12) << "Ускорение"
            << setw(12) << "Корректность" << endl;

        cout << string(72, '=') << endl;

        for (const string& filename : test_files) {
            cout << "\n" << filename << endl;

            vector<cpp_int> messages = LoadMessagesFromFile(filename, publicKey.n);

            if (messages.empty()) {
                cerr << "Ошибка: не удалось загрузить данные из файла!" << endl;
                continue;
            }

            // Последовательное выполнение
            cout << "  Последовательное выполнение..." << flush;
            pair<int, double> seq_result = SequentialEncryptDecrypt(messages, publicKey, privateKey);
            int seq_correct = seq_result.first;
            double seq_time = seq_result.second;
            cout << " OK" << endl;

            // Параллельное выполнение
            double parallel_time;
            int parallel_correct;

            cout << "  OpenMP с " << thread_count << " потоками..." << flush;
            pair<int, double> par_result = ParallelEncryptDecrypt(messages, publicKey, privateKey, thread_count);
            parallel_time = par_result.second;
            parallel_correct = par_result.first;
            cout << " OK" << endl;

            cout << left << setw(18) << messages.size()
                << fixed << setprecision(1)
                << setw(16) << seq_time;

            cout << setw(14) << parallel_time;

            double speedup = (parallel_time > 0) ? (seq_time / parallel_time) : 0;
            cout << setw(12) << ("x" + to_string(speedup).substr(0, 4));

            bool all_correct = (seq_correct == (int)messages.size());
            if (parallel_correct != (int)messages.size()) {
                all_correct = false;
                break;
            }

            string correct_str = all_correct ? "OK" : "ОШИБКА";
            cout << setw(12) << correct_str << endl;
        }

        cout << "\n" << string(72, '=') << endl;
        cout << "\nТестирование завершено." << endl;

    }
    catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }

    return 0;
}
