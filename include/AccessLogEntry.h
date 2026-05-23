#pragma once
#include "LogEntry.h"
#include <string>
#include <optional>

// AccessLogEntry = o linie din access.log
class AccessLogEntry : public LogEntry {
private:
    std::string method; // GET, POST
    std::string path; // PATH /index.html
    int statusCode; // 200,400,404
    std::string userAgent; // cine a facut requestu

    // helpere private pentru parse
    static std::optional<std::chrono::system_clock::time_point> parseTimestamp(const std::string& token);
    static void extractRequestParts(const std::string& request, std::string& method, std::string& path);

public:
    AccessLogEntry(const std::string& ip,
                   std::chrono::system_clock::time_point timestamp,
                   const std::string& method,
                   const std::string& path,
                   int statusCode,
                   const std::string& userAgent);

    // getteri
    const std::string& getMethod() const;
    const std::string& getPath() const;
    int getStatusCode() const;
    const std::string& getUserAgent() const;

    // override = implementarea metodelor pur virtuale din LogEntry
    std::string getSeverity() const override;
    void display() const override;

    // parseaza o linie din access.log si returneaza un AccessLogEntry sau nullopt
    static std::optional<AccessLogEntry> parse(const std::string& line);
};
