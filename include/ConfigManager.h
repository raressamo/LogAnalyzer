#pragma once
#include <string>

// SINGLETON accesibil prin getInstance()
class ConfigManager {
private:
    int bruteForceThreshold; // nr minim de tentative brute force
    int bruteForceWindow; // intervalul in secunde
    std::string authLogPath;
    std::string accessLogPath;

    // constructorul e private ca sa nu mearga ConfigManager cm;
    explicit ConfigManager(const std::string& configPath);

    // parseaza o linie din config.txt si seteaza valoarea corespunzatoare
    void parseLine(const std::string& line);

public:
    // copy si move dezactivate deoarece nu are sens sa copiezi un Singleton
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    ConfigManager(ConfigManager&&) = delete;
    ConfigManager& operator=(ConfigManager&&) = delete;

    // punctul unic de acces la instanta
    static ConfigManager& getInstance(const std::string& configPath = "data/config.txt");

    // getteri pentru setari
    int getBruteForceThreshold() const;
    int getBruteForceWindow() const;
    const std::string& getAuthLogPath() const;
    const std::string& getAccessLogPath() const;
};
