#pragma once
#include "AlertObserver.h"
#include "AuthLogEntry.h"
#include "ConfigManager.h"
#include "Repository.h"
#include <vector>
#include <memory>
#include <map>

class AlertSystem {
private:
    // weak_ptr in loc de shared_ptr deoarece alertsystem nu detine observatorii, doar se uita la ei
    std::vector<std::weak_ptr<IAlertObserver>> observers;

    // numarul de tentative esuate per IP
    std::map<std::string, int> failedAttempts;

    int threshold; // din ConfigManager
    int window; // intervalul in secunde

public:
    AlertSystem();

    // subscribe/unsubscribe pentru gestionarea observatorilor
    void subscribe(std::shared_ptr<IAlertObserver> observer);

    // analizeaza toate logurile SSH si notifica pentru brute force
    void analyze(const Repository<AuthLogEntry>& repo);

private:
    // notifica toti observatorii activi (weak_ptr valid)
    void notify(const std::string& ip, int attempts);
};
