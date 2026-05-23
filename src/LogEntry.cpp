#include "LogEntry.h"

// constructor cu liste de initializare
LogEntry::LogEntry(const std::string& ip, std::chrono::system_clock::time_point timestamp)
    : ip(ip), timestamp(timestamp) {} // GOL deoarece toata treaba o face lista de initializare

// referinta const la string pentru a evita copierea inutila a IP-ului
const std::string& LogEntry::getIP() const {
    return ip;
}

// TIMESTAMP returnat prin valoare deoarece std::chrono::time_point se copiaza eficient
std::chrono::system_clock::time_point LogEntry::getTimestamp() const {
    return timestamp;
}

// getSeverity() si display() nu sunt aici, sunt in clasele derivate AuthLogEntry si AccessLogEntry
