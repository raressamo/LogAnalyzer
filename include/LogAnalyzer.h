#pragma once
#include "Repository.h"
#include "AuthLogEntry.h"
#include "AccessLogEntry.h"
#include "FilterStrategy.h"
#include "AlertSystem.h"
#include <string>
#include <memory>

// orchestratorul
class LogAnalyzer {
private:
    Repository<AuthLogEntry> authRepo; // ssh
    Repository<AccessLogEntry> accessRepo; // apache2

    // unique_ptr deoarece LogAnalyzer detine exclusiv strategia curenta
    std::unique_ptr<IFilterStrategy> strategy;

    AlertSystem alertSystem;

public:
    LogAnalyzer();

    // incarca si parseaza fisierele de log
    void loadAuthLog(const std::string& path);
    void loadAccessLog(const std::string& path);

    // schimba strategia de filtrare la runtime
    void setStrategy(std::unique_ptr<IFilterStrategy> newStrategy);

    // afiseaza filtrul activ curent
    void printActiveFilter() const;

    // afisare
    void printAllAuth() const;
    void printAllAccess() const;
    void printFiltered() const;

    // statistici
    void printStats() const;

    // Observer pentru alerte
    void addObserver(std::shared_ptr<IAlertObserver> observer);
    void runAlertAnalysis();
};
