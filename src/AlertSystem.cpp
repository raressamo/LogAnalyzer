#include "AlertSystem.h"

AlertSystem::AlertSystem() {
    threshold = ConfigManager::getInstance().getBruteForceThreshold();
    window = ConfigManager::getInstance().getBruteForceWindow();
}

// adauga un observator in lista ca weak_ptr
void AlertSystem::subscribe(std::shared_ptr<IAlertObserver> observer) {
    observers.push_back(observer);
}

// parcurge toate logurile SSH si numara tentativele esuate per IP
// daca un IP depaseste threshold-ul, notifica observatorii
void AlertSystem::analyze(const Repository<AuthLogEntry>& repo) {
    failedAttempts.clear();

    for (const auto& entry : repo.getAll()) {
        // numaram doar evenimentele de tip esec
        if (entry->getEvent() == AuthLogEntry::AuthEvent::FailedPassword ||
            entry->getEvent() == AuthLogEntry::AuthEvent::InvalidUser) {
            failedAttempts[entry->getIP()]++;
        }
    }

    // verificam care IP-uri au depasit threshold-ul
    for (const auto& [ip, count] : failedAttempts) {
        if (count >= threshold)
            notify(ip, count);
    }
}

// notifica toti observatorii valizi
// lock() pe weak_ptr returneaza un shared_ptr valid sau nullptr daca observatorul a fost distrus
void AlertSystem::notify(const std::string& ip, int attempts) {
    for (auto& weakObs : observers) {
        if (auto obs = weakObs.lock())
            obs->onAlert(ip, attempts);
    }
}
