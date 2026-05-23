#include "AuthLogEntry.h"
#include <iostream>
#include <sstream>
#include <iomanip>

// constructorul (LogEntry + atributele proprii)
AuthLogEntry::AuthLogEntry(const std::string& ip,
                           std::chrono::system_clock::time_point timestamp,
                           const std::string& username,
                           int port,
                           AuthEvent event)
    : LogEntry(ip, timestamp), username(username), port(port), event(event) {}

const std::string& AuthLogEntry::getUsername() const { return username; }
int AuthLogEntry::getPort() const { return port; }
AuthLogEntry::AuthEvent AuthLogEntry::getEvent() const { return event; }

// determina nivelul de severitate pe baza tipului de eveniment
std::string AuthLogEntry::getSeverity() const {
    switch (event) {
        case AuthEvent::FailedPassword:   return "ERROR";
        case AuthEvent::InvalidUser:      return "ERROR";
        case AuthEvent::ConnectionClosed: return "WARNING";
        case AuthEvent::AcceptedPassword: return "INFO";
        default:                          return "INFO";
    }
}

// afiseaza logul formatat in cmd (diferit de AccessLogEntry::display())
void AuthLogEntry::display() const {
    // convertire timestamp in timp local
    std::time_t t = std::chrono::system_clock::to_time_t(timestamp);
    std::tm tm = *std::localtime(&t);

    std::cout << "[" << getSeverity() << "] "
              << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << " "
              << "SSH | IP: " << ip
              << " | User: " << username
              << " | Port: " << port
              << "\n";
}

// HELPER 1 - parseaza timestamp-ul
std::optional<std::chrono::system_clock::time_point>
AuthLogEntry::parseTimestamp(const std::string& line) {
    // std::istringstream = citim din string ca dintr-un stream
    std::istringstream ss(line);
    std::string timestampStr;
    ss >> timestampStr;
    // timestampStr = 2026-05-23T06:37:38.754187+00:00

    // CUT tot ce este dupa punct ('.')
    auto dotPos = timestampStr.find('.'); // pozitia primului punct in string
    if (dotPos != std::string::npos)
        timestampStr = timestampStr.substr(0, dotPos); // taie tot ce e dupa punct ("2026-05-23T06:37:38")

    // get_time asteapta formatul "%Y-%m-%d %H:%M:%S" cu spatiu intre, iar eu am T, facem din T un ' '
    if (timestampStr.size() <= 10)
        return std::nullopt;
    timestampStr[10] = ' ';
    // "2026-05-23 06:37:38"

    std::tm tm = {}; // structura goala pentru data si ora desfacute
    std::istringstream tss(timestampStr); // stream nou din timestampStr
    tss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S"); // get_time citeste din tss si baga in tm
    if (tss.fail()) return std::nullopt; // fallback daca nu e ok

    // structura tm o face in numar de secunde -> acel numar il face time_point, folosit in LogEntry
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
}

// HELPER 2 - parseaza "KEYWORD USER from IP port PORT"
// FailedPassword, InvalidUser, AcceptedPassword
void AuthLogEntry::extractUserIpPort(const std::string& line, const std::string& keyword,
                                     std::string& username, std::string& ip, int& port) {
    auto fromPos = line.find(" from ");
    auto portPos = line.find(" port ");
    if (fromPos == std::string::npos || portPos == std::string::npos)
        return; // protectie pentru liniile malformate

    // USER = intre keyword si " from"
    auto userStart = line.find(keyword) + keyword.size();
    username = line.substr(userStart, fromPos - userStart);
    // IP = intre "from " si " port"
    ip = line.substr(fromPos + 6, portPos - fromPos - 6);
    // PORT = dupa "port " (stoi face stringul "49398 ssh2" in integer si da cut la spatiu)
    port = std::stoi(line.substr(portPos + 6));
}

// HELPER 3 - parser pentru "Connection closed by [INVALID USER] USER IP port PORT"
void AuthLogEntry::extractConnectionClosed(const std::string& line, std::string& ip, int& port) {
    auto portPos = line.find(" port ");
    if (portPos == std::string::npos) return;

    // IP-ul e ultimul str inainte de " port "
    auto spaceBeforeIP = line.rfind(' ', portPos - 1);
    ip = line.substr(spaceBeforeIP + 1, portPos - spaceBeforeIP - 1);
    port = std::stoi(line.substr(portPos + 6));
}

// main parser
std::optional<AuthLogEntry> AuthLogEntry::parse(const std::string& line) {
    // liniile care nu au sshd nu sunt loguri ssh
    if (line.find("sshd") == std::string::npos)
        return std::nullopt;

    auto timestamp = parseTimestamp(line);
    if (!timestamp) return std::nullopt;

    std::string username = "unknown";
    std::string ip = "unknown";
    int port = 0;
    AuthEvent event = AuthEvent::Other;

    // != std::string::npos = inseamna ca a gasit ceva (cand caut ceva in string, find returneaza npos)
    // ordinea conteaza "Failed password for invalid user" trebuie verificat inainte de "Failed password for"
    if (line.find("Failed password for invalid user") != std::string::npos) {
        event = AuthEvent::FailedPassword;
        extractUserIpPort(line, "invalid user ", username, ip, port);
    } else if (line.find("Failed password for") != std::string::npos) {
        event = AuthEvent::FailedPassword;
        // "Failed password for USER from IP port PORT" (user existent deja)
        extractUserIpPort(line, "Failed password for ", username, ip, port);
    } else if (line.find("Invalid user") != std::string::npos) {
        event = AuthEvent::InvalidUser;
        // "Invalid user USER from IP port PORT"
        extractUserIpPort(line, "Invalid user ", username, ip, port);
    } else if (line.find("Accepted password for") != std::string::npos) {
        event = AuthEvent::AcceptedPassword;
        // "Accepted password for USER from IP port PORT"
        extractUserIpPort(line, "Accepted password for ", username, ip, port);
    } else if (line.find("Connection closed") != std::string::npos) {
        event = AuthEvent::ConnectionClosed;
        // "Connection closed by [INVALID USER] USER IP port PORT"
        extractConnectionClosed(line, ip, port);
    } else {
        // linie sshd dar tip necunoscut, o ignora
        return std::nullopt;
    }

    // construim si returnam obiectul AuthLogEntry
    return AuthLogEntry(ip, *timestamp, username, port, event);
}
