#include "FilterStrategy.h"
#include <algorithm>

// SeverityFilter
SeverityFilter::SeverityFilter(const std::string& severity)
    : severity(severity) {}

std::vector<std::shared_ptr<AuthLogEntry>>
SeverityFilter::apply(const std::vector<std::shared_ptr<AuthLogEntry>>& entries) const {
    std::vector<std::shared_ptr<AuthLogEntry>> result;
    // std::copy_if copiaza doar elementele pentru care lambda returneaza true
    std::copy_if(entries.begin(), entries.end(), std::back_inserter(result), // back_inserter e un push_back automat
        [this](const std::shared_ptr<AuthLogEntry>& e) {
            return e->getSeverity() == severity;
        }); // functie lambda definita pe loc pentru a accesa severity din interior
    return result;
}

std::vector<std::shared_ptr<AccessLogEntry>>
SeverityFilter::apply(const std::vector<std::shared_ptr<AccessLogEntry>>& entries) const {
    std::vector<std::shared_ptr<AccessLogEntry>> result;
    std::copy_if(entries.begin(), entries.end(), std::back_inserter(result),
        [this](const std::shared_ptr<AccessLogEntry>& e) {
            return e->getSeverity() == severity;
        });
    return result;
}

std::string SeverityFilter::name() const {
    return "SeverityFilter(" + severity + ")";
}

// IPFilter
IPFilter::IPFilter(const std::string& ip)
    : targetIP(ip) {}

std::vector<std::shared_ptr<AuthLogEntry>>
IPFilter::apply(const std::vector<std::shared_ptr<AuthLogEntry>>& entries) const {
    std::vector<std::shared_ptr<AuthLogEntry>> result;
    std::copy_if(entries.begin(), entries.end(), std::back_inserter(result),
        [this](const std::shared_ptr<AuthLogEntry>& e) {
            return e->getIP() == targetIP;
        });
    return result;
}

std::vector<std::shared_ptr<AccessLogEntry>>
IPFilter::apply(const std::vector<std::shared_ptr<AccessLogEntry>>& entries) const {
    std::vector<std::shared_ptr<AccessLogEntry>> result;
    std::copy_if(entries.begin(), entries.end(), std::back_inserter(result),
        [this](const std::shared_ptr<AccessLogEntry>& e) {
            return e->getIP() == targetIP;
        });
    return result;
}

std::string IPFilter::name() const {
    return "IPFilter(" + targetIP + ")";
}

// StatusCodeFilter
StatusCodeFilter::StatusCodeFilter(int code)
    : statusCode(code) {}

// lista goala deoarece la SSH nu se aplica
std::vector<std::shared_ptr<AuthLogEntry>>
StatusCodeFilter::apply(const std::vector<std::shared_ptr<AuthLogEntry>>& entries) const {
    return {};
}

std::vector<std::shared_ptr<AccessLogEntry>>
StatusCodeFilter::apply(const std::vector<std::shared_ptr<AccessLogEntry>>& entries) const {
    std::vector<std::shared_ptr<AccessLogEntry>> result;
    std::copy_if(entries.begin(), entries.end(), std::back_inserter(result),
        [this](const std::shared_ptr<AccessLogEntry>& e) {
            return e->getStatusCode() == statusCode;
        });
    return result;
}

std::string StatusCodeFilter::name() const {
    return "StatusCodeFilter(" + std::to_string(statusCode) + ")";
}
