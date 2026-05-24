#include "AlertSystem.h"
#include <algorithm>

AlertSystem::AlertSystem() {
    threshold = ConfigManager::getInstance().getBruteForceThreshold();
    window = ConfigManager::getInstance().getBruteForceWindow();
}

// adauga un observator in lista ca weak_ptr
void AlertSystem::subscribe(std::shared_ptr<IAlertObserver> observer) {
    observers.push_back(observer);
}

// gaseste numarul maxim de tentative dintr-un interval
int AlertSystem::maxAttemptsInWindow(std::vector<std::chrono::system_clock::time_point> times) const {
    std::sort(times.begin(), times.end());
    int maxCount = 0;
    for (size_t i = 0; i < times.size(); ++i) {
        int count = 1;
        for (size_t j = i + 1; j < times.size(); ++j) {
            // duration_cast<seconds> calculeaza diferenta in secunde intre doua time_point
            auto diff = std::chrono::duration_cast<std::chrono::seconds>(times[j] - times[i]).count();
            if (diff <= window)
                count++;
            else
                break; // lista e sortata, deci iesim
        }
        maxCount = std::max(maxCount, count);
    }
    return maxCount;
}

// parcurge toate logurile SSH si grupeaza tentativele esuate per IP cu timestamp-urile lor
// daca un IP depaseste, notifica observaorii
void AlertSystem::analyze(const Repository<AuthLogEntry>& repo) {
    // lista de timestamp-uri ale tentativelor esuate
    std::map<std::string, std::vector<std::chrono::system_clock::time_point>> attemptTimes;

    for (const auto& entry : repo.getAll()) {
        if (entry->getEvent() == AuthLogEntry::AuthEvent::FailedPassword ||
            entry->getEvent() == AuthLogEntry::AuthEvent::InvalidUser) {
            attemptTimes[entry->getIP()].push_back(entry->getTimestamp());
        }
    }

    // verificam care IP-uri au depasit threshold-ul
    for (auto& [ip, times] : attemptTimes) {
        int maxInWindow = maxAttemptsInWindow(times);
        if (maxInWindow >= threshold)
            notify(ip, maxInWindow);
    }
}

// notifica toti observatorii valizi
void AlertSystem::notify(const std::string& ip, int attempts) {
    for (auto& weakObs : observers) {
        if (auto obs = weakObs.lock())
            obs->onAlert(ip, attempts);
    }
}
