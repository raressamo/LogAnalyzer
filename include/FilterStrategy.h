#pragma once
#include "AuthLogEntry.h"
#include "AccessLogEntry.h"
#include <memory>
#include <vector>
#include <string>

// STRATEGY PATTERN
class IFilterStrategy {
public:
    virtual ~IFilterStrategy() = default;

    // apply() pe AuthLogEntry returneaza logurile SSH care trec filtrul
    virtual std::vector<std::shared_ptr<AuthLogEntry>>
    apply(const std::vector<std::shared_ptr<AuthLogEntry>>& entries) const = 0;

    // apply() pe AccessLogEntry returneaza logurile Apache care trec filtrul
    virtual std::vector<std::shared_ptr<AccessLogEntry>>
    apply(const std::vector<std::shared_ptr<AccessLogEntry>>& entries) const = 0;

    // numele strategiei, folosit in meniu pentru a afisa filtrul activ
    virtual std::string name() const = 0;
};

// filtreaza dupa nivelul de severitate
class SeverityFilter : public IFilterStrategy {
private:
    std::string severity; // "ERROR", "WARNING", "INFO"
public:
    explicit SeverityFilter(const std::string& severity);

    std::vector<std::shared_ptr<AuthLogEntry>>
    apply(const std::vector<std::shared_ptr<AuthLogEntry>>& entries) const override;

    std::vector<std::shared_ptr<AccessLogEntry>>
    apply(const std::vector<std::shared_ptr<AccessLogEntry>>& entries) const override;

    std::string name() const override;
};

// filtreaza dupa IP-ul sursa
class IPFilter : public IFilterStrategy {
private:
    std::string targetIP;
public:
    explicit IPFilter(const std::string& ip);

    std::vector<std::shared_ptr<AuthLogEntry>>
    apply(const std::vector<std::shared_ptr<AuthLogEntry>>& entries) const override;

    std::vector<std::shared_ptr<AccessLogEntry>>
    apply(const std::vector<std::shared_ptr<AccessLogEntry>>& entries) const override;

    std::string name() const override;
};

// filtreaza doar logurile Apache dupa codul HTTP (nu se functioneaza la SSH)
class StatusCodeFilter : public IFilterStrategy {
private:
    int statusCode;
public:
    explicit StatusCodeFilter(int code);

    std::vector<std::shared_ptr<AuthLogEntry>>
    apply(const std::vector<std::shared_ptr<AuthLogEntry>>& entries) const override;

    std::vector<std::shared_ptr<AccessLogEntry>>
    apply(const std::vector<std::shared_ptr<AccessLogEntry>>& entries) const override;

    std::string name() const override;
};
