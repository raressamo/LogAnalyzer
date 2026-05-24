# Log Analyzer

Aplicatie C++20 care analizeaza log-uri reale de server: tentative de brute force SSH din `/var/log/auth.log` si trafic HTTP din `/var/log/apache2/access.log`.

## Ce face aplicatia

- Incarca si parseaza log-uri SSH si HTTP din fisiere locale
- Detecteaza atacuri brute force: IP-uri care au depasit un numar de autentificari esuate intr-o fereastra de timp configurabila
- Filtreaza log-uri dupa severitate, IP sau HTTP status code (schimbabil la runtime)
- Afiseaza statistici: top 5 IP-uri atacatoare, distributie HTTP 200/404, erori SSH
- Notifica prin consola cand se detecteaza un atac (pattern Observer)

## Compilare si rulare

```bash
g++ -std=c++20 -Wall -Wextra -Iinclude src/*.cpp -o LogAnalyzer
```

Proiectul foloseste **C++20 concepts** (`Loggable` in `include/Repository.h`) pentru a constrange template-ul `Repository<T>` la tipuri care implementeaza `getIP()`, `getSeverity()` si `display()`.

Fisierele de log se configureaza in `data/config.txt`:
```
brute_force_threshold=5
brute_force_window=60
auth_log_path=data/auth.log
access_log_path=data/access.log
```

## Structura proiectului

```
LogAnalyzer/
├── include/        # Header files
├── src/            # Implementari
└── data/           # config.txt (log-urile nu sunt in repo)
```

## Design patterns implementate

### Singleton — `ConfigManager`
`include/ConfigManager.h`, `src/ConfigManager.cpp`

Citeste `data/config.txt` o singura data la pornire. Instanta unica accesibila global fara variabile globale (thread-safe de la C++11 in sus).

```cpp
auto& config = ConfigManager::getInstance("data/config.txt");
config.getBruteForceThreshold();
```

### Strategy — `IFilterStrategy`
`include/FilterStrategy.h`, `src/FilterStrategy.cpp`

Filtrul activ se poate schimba la runtime fara sa modifici `LogAnalyzer`. Cele trei filtre (`SeverityFilter`, `IPFilter`, `StatusCodeFilter`) implementeaza aceeasi interfata.

```cpp
analyzer.setStrategy(std::make_unique<IPFilter>("192.168.1.1"));
analyzer.printFiltered(); // aplica filtrul curent
```

### Observer — `IAlertObserver` + `AlertSystem`
`include/AlertObserver.h`, `include/AlertSystem.h`, `src/AlertSystem.cpp`

`AlertSystem` notifica toti observatorii inregistrati cand detecteaza un IP suspect. Observatorii sunt tinuti ca `weak_ptr` pentru a evita cicluri de ownership.

```cpp
auto observer = std::make_shared<ConsoleAlertObserver>();
analyzer.addObserver(observer); // AlertSystem il tine ca weak_ptr
```

## Concepte C++ folosite

| Concept | Unde |
|---|---|
| Template class + C++20 concept (`Loggable`) | `include/Repository.h` |
| Template functions (`printAll`, `countIf`, `findIf`) | `include/Repository.h` |
| `unique_ptr` (ownership exclusiv) | strategie in `LogAnalyzer` |
| `shared_ptr` (ownership partajat) | log entries in `Repository<T>` |
| `weak_ptr` (observare fara ownership) | observatori in `AlertSystem` |
| `std::optional` (parse care poate esua) | `AuthLogEntry::parse()`, `AccessLogEntry::parse()` |
| `enum class` | `AuthLogEntry::AuthEvent` |
| `std::chrono` (timestamps, fereastra de timp) | `AlertSystem::maxAttemptsInWindow()` |
| Exceptii custom | `include/Exceptions.h` |
| `std::copy_if`, `std::sort` cu lambda | `FilterStrategy.cpp`, `LogAnalyzer.cpp` |

## Ierarhia de clase

```
LogEntry (abstract)
├── AuthLogEntry   — evenimente SSH (FailedPassword, InvalidUser, ...)
└── AccessLogEntry — cereri HTTP (metoda, path, status code, user-agent)

IFilterStrategy (abstract)
├── SeverityFilter
├── IPFilter
└── StatusCodeFilter

IAlertObserver (abstract)
└── ConsoleAlertObserver
```
