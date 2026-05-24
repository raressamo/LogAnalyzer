#include "LogAnalyzer.h"
#include "Exceptions.h"
#include <fstream>
#include <iostream>
#include <map>

LogAnalyzer::LogAnalyzer()
    : strategy(std::make_unique<SeverityFilter>("ERROR")) {}
// default este sa afiseze doar ERROR

// citeste auth.log linie cu linie si parseaza fiecare linie
void LogAnalyzer::loadAuthLog(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        throw ParseException("Cannot open auth log: " + path);

    authRepo.clear();
    std::string line;
    while (std::getline(file, line)) {
        auto entry = AuthLogEntry::parse(line);
        if (entry)
            authRepo.add(std::make_shared<AuthLogEntry>(*entry));
    }
    std::cout << "Loaded " << authRepo.count() << " SSH log entries.\n";
}

// citeste access.log linie cu linie si parseaza fiecare linie
void LogAnalyzer::loadAccessLog(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        throw ParseException("Cannot open access log: " + path);

    accessRepo.clear();
    std::string line;
    while (std::getline(file, line)) {
        auto entry = AccessLogEntry::parse(line);
        if (entry)
            accessRepo.add(std::make_shared<AccessLogEntry>(*entry));
    }
    std::cout << "Loaded " << accessRepo.count() << " HTTP log entries.\n";
}

// inlocuieste strategia curenta cu una noua
// unique_ptr vechi e distrus automat si memoria e eliberata
void LogAnalyzer::setStrategy(std::unique_ptr<IFilterStrategy> newStrategy) {
    strategy = std::move(newStrategy);
    std::cout << "Filter set to: " << strategy->name() << "\n";
}

void LogAnalyzer::printActiveFilter() const {
    std::cout << "Active filter: " << strategy->name() << "\n";
}

// afiseaza toate logurile SSH
void LogAnalyzer::printAllAuth() const {
    std::cout << "\n=== SSH Logs (" << authRepo.count() << " entries) ===\n";
    printAll(authRepo);
}

// afiseaza toate logurile Apache
void LogAnalyzer::printAllAccess() const {
    std::cout << "\n=== HTTP Logs (" << accessRepo.count() << " entries) ===\n";
    printAll(accessRepo);
}

// aplica strategia curenta pe ambele repository si afiseaza rezultatele
void LogAnalyzer::printFiltered() const {
    auto authResults   = strategy->apply(authRepo.getAll());
    auto accessResults = strategy->apply(accessRepo.getAll());

    std::cout << "\n=== Filtered SSH [" << strategy->name() << "] ("
              << authResults.size() << " results) ===\n";
    for (const auto& e : authResults) e->display();

    std::cout << "\n=== Filtered HTTP [" << strategy->name() << "] ("
              << accessResults.size() << " results) ===\n";
    for (const auto& e : accessResults) e->display();
}

// statistici generale despre logurile incarcate
void LogAnalyzer::printStats() const {
    std::cout << "\n=== Statistics ===\n";
    std::cout << "SSH  entries : " << authRepo.count() << "\n";
    std::cout << "HTTP entries : " << accessRepo.count() << "\n";

    // numara SSH dupa severitate folosind countIf din Repository<T>
    size_t sshErrors   = authRepo.countIf([](const std::shared_ptr<AuthLogEntry>& e) {
        return e->getSeverity() == "ERROR"; });
    size_t sshWarnings = authRepo.countIf([](const std::shared_ptr<AuthLogEntry>& e) {
        return e->getSeverity() == "WARNING"; });

    std::cout << "SSH  ERROR   : " << sshErrors << "\n";
    std::cout << "SSH  WARNING : " << sshWarnings << "\n";

    // top 5 IP-uri cu cele mai multe tentative esuate SSH
    std::map<std::string, int> ipCount;
    for (const auto& e : authRepo.getAll())
        if (e->getSeverity() == "ERROR")
            ipCount[e->getIP()]++;

    std::cout << "\nTop failed SSH IPs:\n";
    // sortam dupa count descrescator
    std::vector<std::pair<std::string, int>> sorted(ipCount.begin(), ipCount.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    int shown = 0;
    for (const auto& [ip, count] : sorted) {
        std::cout << "  " << ip << " : " << count << " attempts\n";
        if (++shown == 5) break;
    }

    // HTTP stats
    size_t http404 = accessRepo.countIf([](const std::shared_ptr<AccessLogEntry>& e) {
        return e->getStatusCode() == 404; });
    size_t http200 = accessRepo.countIf([](const std::shared_ptr<AccessLogEntry>& e) {
        return e->getStatusCode() == 200; });

    std::cout << "\nHTTP 200 OK  : " << http200 << "\n";
    std::cout << "HTTP 404     : " << http404 << "\n";
}

void LogAnalyzer::addObserver(std::shared_ptr<IAlertObserver> observer) {
    alertSystem.subscribe(observer);
}

// ruleaza analiza brute force si notifica observatorii
void LogAnalyzer::runAlertAnalysis() {
    std::cout << "\n=== Running Brute Force Analysis ===\n";
    alertSystem.analyze(authRepo);
    std::cout << "Analysis complete.\n";
}
