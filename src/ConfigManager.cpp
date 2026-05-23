#include "ConfigManager.h"
#include "Exceptions.h"
#include <fstream>
#include <sstream>

// constructorul private
ConfigManager::ConfigManager(const std::string& configPath)
    : bruteForceThreshold(5), bruteForceWindow(60),
      authLogPath("data/auth.log"), accessLogPath("data/access.log") {
    // valorile de mai sus sunt de fallback, daca o linie e invalida foloseste astea

    std::ifstream file(configPath);
    if (!file.is_open())
        throw ParseException("Cannot open config file: " + configPath);

    std::string line;
    while (std::getline(file, line))
        parseLine(line);
}

// parseaza o singura linie din config.txt
void ConfigManager::parseLine(const std::string& line) {
    if (line.empty() || line[0] == '#')
        return;

    // cautam '=' care separa cheia de valoare
    auto eqPos = line.find('=');
    if (eqPos == std::string::npos)
        return;

    std::string key   = line.substr(0, eqPos);
    std::string value = line.substr(eqPos + 1);

    if (key == "brute_force_threshold")
        bruteForceThreshold = std::stoi(value);
    else if (key == "brute_force_window")
        bruteForceWindow = std::stoi(value);
    else if (key == "auth_log_path")
        authLogPath = value;
    else if (key == "access_log_path")
        accessLogPath = value;
}

// instanta statica locala
ConfigManager& ConfigManager::getInstance(const std::string& configPath) {
    static ConfigManager instance(configPath);
    return instance;
}

int ConfigManager::getBruteForceThreshold() const { return bruteForceThreshold; }
int ConfigManager::getBruteForceWindow() const { return bruteForceWindow; }
const std::string& ConfigManager::getAuthLogPath() const { return authLogPath; }
const std::string& ConfigManager::getAccessLogPath() const { return accessLogPath; }
