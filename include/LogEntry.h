#pragma once // alternativa ifndef
#include <string>
#include <chrono>

// clasa abstracta de baza pentru AuthLogEntry si pentru AccessLogEntry
class LogEntry {
protected:
    // atribute accesibile doar din clasele derivate
    std::string ip; // IP sursa log
    std::chrono::system_clock::time_point timestamp; // TIMP sursa log

public:
    // constructor (IP + TIMESTAMP), toate clasele derivate il apeleaza in lista de initializare
    LogEntry(const std::string& ip, std::chrono::system_clock::time_point timestamp);

    // default = generat automat de compilator
    // virtual = cauta destructorul real al obiectului, nu al pointerului
    virtual ~LogEntry() = default;

    // getteri
    const std::string& getIP() const;
    std::chrono::system_clock::time_point getTimestamp() const;

    // metode virtuale
    virtual std::string getSeverity() const = 0; // returneaza grad de risc al logului
    virtual void display() const = 0; // afiseaza logul formatat
};
