#pragma once
#include "LogEntry.h"
#include <string>
#include <optional>

// AuthLogEntry reprezinta o linie din /var/log/auth.log
class AuthLogEntry : public LogEntry {
public:
    // tipurile de evenimente ssh
    // scriere explicita (AuthEvent::FailedPassword)
    enum class AuthEvent {
        FailedPassword,
        InvalidUser,
        ConnectionClosed,
        AcceptedPassword,
        Other
    };

private:
    // atributele specifice ce nu exista in LogEntry
    std::string username; // userul incercat
    int port; // portul de pe care vine conexiunea
    AuthEvent event; // tipul evenimentului

    // helpere private pentru parse
    // static (nu au nevoie de un obiect AuthLogEntry ca sa functioneze)
    static std::optional<std::chrono::system_clock::time_point> parseTimestamp(const std::string& line);
    static void extractUserIpPort(const std::string& line, const std::string& keyword,
                                  std::string& username, std::string& ip, int& port);
    static void extractConnectionClosed(const std::string& line, std::string& ip, int& port);

public:
    // constructor care primeste toate datele necesare
    AuthLogEntry(const std::string& ip,
                 std::chrono::system_clock::time_point timestamp,
                 const std::string& username,
                 int port,
                 AuthEvent event);

    // getteri pentru atributele specifice
    const std::string& getUsername() const;
    int getPort() const;
    AuthEvent getEvent() const;

    // metodele virtuale din LogEntry
    // override = compilatorul verifica ca suprascrie o metoda virtuala din clasa de baza
    std::string getSeverity() const override;
    void display() const override;

    // metoda statica (parseaza o linie din auth.log - returneaza un AuthLogEntry construit)
    // std::optional<AuthLogEntry> returneaza ori un obiect valid, ori nullopt daca nu e formatul ok
    static std::optional<AuthLogEntry> parse(const std::string& line);
};
