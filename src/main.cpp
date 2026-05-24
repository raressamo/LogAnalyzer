#include "LogAnalyzer.h"
#include "ConfigManager.h"
#include "AlertObserver.h"
#include "FilterStrategy.h"
#include "Exceptions.h"
#include <iostream>
#include <memory>
#include <limits>

// goleste buffer-ul de input dupa citire
void clearInput() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void printMenu(const LogAnalyzer& /* analyzer */) {
    std::cout << "\n=============================\n";
    std::cout << "       LOG ANALYZER\n";
    std::cout << "=============================\n";
    std::cout << "1. Load log files\n";
    std::cout << "2. Show all SSH logs\n";
    std::cout << "3. Show all HTTP logs\n";
    std::cout << "4. Apply filter\n";
    std::cout << "5. Change filter\n";
    std::cout << "6. Statistics\n";
    std::cout << "7. Brute force analysis\n";
    std::cout << "8. Show config\n";
    std::cout << "0. Exit\n";
    std::cout << "=============================\n";
    std::cout << "Choice: ";
}

// submeniu pentru schimbarea filtrului
void changeFilterMenu(LogAnalyzer& analyzer) {
    std::cout << "\n--- Change Filter ---\n";
    std::cout << "1. Severity filter (ERROR / WARNING / INFO)\n";
    std::cout << "2. IP filter\n";
    std::cout << "3. HTTP Status code filter\n";
    std::cout << "Choice: ";

    int choice;
    std::cin >> choice;
    clearInput();

    if (choice == 1) {
        std::cout << "Severity (ERROR / WARNING / INFO): ";
        std::string sev;
        std::cin >> sev;
        clearInput();
        analyzer.setStrategy(std::make_unique<SeverityFilter>(sev));
    } else if (choice == 2) {
        std::cout << "IP address: ";
        std::string ip;
        std::cin >> ip;
        clearInput();
        analyzer.setStrategy(std::make_unique<IPFilter>(ip));
    } else if (choice == 3) {
        std::cout << "Status code: ";
        int code;
        std::cin >> code;
        clearInput();
        analyzer.setStrategy(std::make_unique<StatusCodeFilter>(code));
    } else {
        std::cout << "Invalid choice.\n";
    }
}

int main() {
    try {
        // initializeaza Singleton cu fisierul de configurare
        auto& config = ConfigManager::getInstance("data/config.txt");

        LogAnalyzer analyzer;

        // cream observatorul si il inregistram 
        // shared_ptr (main si AlertSystem)
        auto consoleObserver = std::make_shared<ConsoleAlertObserver>();
        analyzer.addObserver(consoleObserver);

        // incarcam automat fisierele din config la pornire
        try {
            analyzer.loadAuthLog(config.getAuthLogPath());
            analyzer.loadAccessLog(config.getAccessLogPath());
        } catch (const ParseException& e) {
            std::cout << "Warning: " << e.what() << "\n";
            std::cout << "You can load files manually from the menu.\n";
        }

        int choice = -1;
        while (choice != 0) {
            printMenu(analyzer);
            std::cin >> choice;
            clearInput();

            try {
                switch (choice) {
                    case 1:
                        // Repository<T>
                        analyzer.loadAuthLog(config.getAuthLogPath());
                        analyzer.loadAccessLog(config.getAccessLogPath());
                        break;
                    case 2:
                        analyzer.printAllAuth();
                        break;
                    case 3:
                        analyzer.printAllAccess();
                        break;
                    case 4:
                        analyzer.printActiveFilter();
                        analyzer.printFiltered();
                        break;
                    case 5:
                        changeFilterMenu(analyzer);
                        break;
                    case 6:
                        // printAll si countIf
                        analyzer.printStats();
                        break;
                    case 7:
                        analyzer.runAlertAnalysis();
                        break;
                    case 8:
                        // ConfigManager
                        std::cout << "\n=== Config ===\n";
                        std::cout << "Auth log    : " << config.getAuthLogPath() << "\n";
                        std::cout << "Access log  : " << config.getAccessLogPath() << "\n";
                        std::cout << "BF threshold: " << config.getBruteForceThreshold() << "\n";
                        std::cout << "BF window   : " << config.getBruteForceWindow() << "s\n";
                        break;
                    case 0:
                        std::cout << "Goodbye.\n";
                        break;
                    default:
                        std::cout << "Invalid option.\n";
                }
            } catch (const std::exception& e) {
                std::cout << "Error: " << e.what() << "\n";
            }
        }

    } catch (const std::exception& e) {
        std::cout << "Fatal error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
