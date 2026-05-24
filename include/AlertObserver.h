#pragma once
#include "AuthLogEntry.h"
#include <string>
#include <memory>
#include <vector>

class IAlertObserver {
public:
    virtual ~IAlertObserver() = default;

    // apelat de AlertSystem cand se detecteaza brute force
    virtual void onAlert(const std::string& ip, int attempts) = 0;
};

class ConsoleAlertObserver : public IAlertObserver {
public:
    void onAlert(const std::string& ip, int attempts) override;
};
