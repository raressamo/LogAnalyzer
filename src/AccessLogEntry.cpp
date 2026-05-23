#include "AccessLogEntry.h"
#include <iostream>
#include <sstream>
#include <iomanip>

AccessLogEntry::AccessLogEntry(const std::string& ip,
                               std::chrono::system_clock::time_point timestamp,
                               const std::string& method,
                               const std::string& path,
                               int statusCode,
                               const std::string& userAgent)
    : LogEntry(ip, timestamp), method(method), path(path),
      statusCode(statusCode), userAgent(userAgent) {}

const std::string& AccessLogEntry::getMethod() const { return method; }
const std::string& AccessLogEntry::getPath() const { return path; }
int AccessLogEntry::getStatusCode() const { return statusCode; }
const std::string& AccessLogEntry::getUserAgent() const { return userAgent; }

// severitatea bazata pe status code (2xx = ok, 3xx = redirect, 4xx = eroare, 5xx eroare)
std::string AccessLogEntry::getSeverity() const {
    if (statusCode >= 500) return "ERROR";
    if (statusCode >= 400) return "WARNING";
    if (statusCode >= 300) return "INFO";
    return "INFO";
}

// afiseaza log-ul formatat
void AccessLogEntry::display() const {
    std::time_t t = std::chrono::system_clock::to_time_t(timestamp);
    std::tm tm = *std::localtime(&t);

    std::cout << "[" << getSeverity() << "] "
              << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << " "
              << "HTTP | IP: " << ip
              << " | " << method << " " << path
              << " | Status: " << statusCode
              << "\n";
}

// HELPER 1 — parseaza timestamp din formatul apache2 [23/May/2026:00:12:21 +0000]
std::optional<std::chrono::system_clock::time_point>
AccessLogEntry::parseTimestamp(const std::string& token) {
    // salt peste '['
    std::string clean = token.substr(1);

    std::tm tm = {};
    std::istringstream tss(clean);
    // %d/%b/%Y:%H:%M:%S — %b = luna abreviata in engleza
    tss >> std::get_time(&tm, "%d/%b/%Y:%H:%M:%S");
    if (tss.fail()) return std::nullopt;

    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
}

// HELPER 2 — extrage metoda si calea din request-ul dintre ghilimele
// "GET /path HTTP/1.1"
void AccessLogEntry::extractRequestParts(const std::string& request,
                                         std::string& method, std::string& path) {
    // istringstream il sparge in tokeni separati de spatiu
    std::istringstream ss(request);
    std::string proto; // nu ma intereseaza dar trebuie citit sa nu ramana in stream
    ss >> method >> path >> proto;
    // method = "GET"
    // path = "/path"
    // proto = "HTTP/1.1"
}

// IP - - [timestamp +0000] "METHOD path HTTP/x" STATUS bytes "referer" "user-agent"
std::optional<AccessLogEntry> AccessLogEntry::parse(const std::string& line) {
    std::istringstream ss(line);
    std::string ip, dash1, dash2, timestampToken, tzToken, requestToken;
    int statusCode, bytes;
    std::string referer, userAgent;

    // citim token cu token in ordinea din format
    ss >> ip >> dash1 >> dash2 >> timestampToken >> tzToken;
    // timestampToken = "[23/May/2026:00:12:21"
    // tzToken = "+0000]"

    // request-ul e intre ghilimele — getline cu delimitator '"' il extrage complet
    ss.ignore(); // sarim peste spatiul de dupa tzToken
    std::getline(ss, requestToken, '"'); // sarim peste primul '"'
    std::getline(ss, requestToken, '"'); // luam continutul pana la al doilea '"'

    ss >> statusCode >> bytes;

    // user agent la fel, intre ghilimele
    ss.ignore();
    std::getline(ss, referer, '"');
    std::getline(ss, referer, '"');
    ss.ignore();
    std::getline(ss, userAgent, '"');
    std::getline(ss, userAgent, '"');

    // daca linia e invalida dam nullopt
    if (ss.fail() || ip.empty()) return std::nullopt;

    // trimit timestamp la helper
    auto timestamp = parseTimestamp(timestampToken);
    if (!timestamp) return std::nullopt;

    // trimit requestul la helper
    std::string method = "UNKNOWN", path = "/";
    extractRequestParts(requestToken, method, path);

    // construiesc obiectul
    return AccessLogEntry(ip, *timestamp, method, path, statusCode, userAgent);
}
