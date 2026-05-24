#include "AlertObserver.h"
#include <iostream>

void ConsoleAlertObserver::onAlert(const std::string& ip, int attempts) {
    std::cout << "\n[BRUTE FORCE ALERT] IP: " << ip
              << " | Tentative: " << attempts << "\n";
}
