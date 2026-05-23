#pragma once
#include <stdexcept>
#include <string>

// fisier de log nu poate fi deschis sau formatul este total invalid
class ParseException : public std::runtime_error {
public:
    // std::runtime_error are deja un constructor cu mesaj
    explicit ParseException(const std::string& message)
        : std::runtime_error("Parse error: " + message) {}
};

// o linie specifica are format care nu poate fi parsat
class InvalidLogFormatException : public std::runtime_error {
public:
    explicit InvalidLogFormatException(const std::string& line)
        : std::runtime_error("Invalid log format: " + line) {}
};
