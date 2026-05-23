#pragma once
#include <vector>
#include <memory>
#include <algorithm>
#include <concepts>

// (C++20) - Loggable
// T trebuie sa satisfaca cerinte pentru a fi folosit cu un template
template <typename T>
concept Loggable = requires(const T& t) {
    { t.getIP() }       -> std::convertible_to<std::string>; // ceva convertibil la string
    { t.getSeverity() } -> std::convertible_to<std::string>; // ceva convertibil la string
    { t.display() }; // poate fi apelat fara nimic
};

// Repository = container pentru obiectele TIP T
// shared_ptr<T> = ownership shared intre repository si rezultatele filtrarii
template <Loggable T>
class Repository {
private:
    std::vector<std::shared_ptr<T>> entries;

public:
    // adauga un entry in repository
    void add(std::shared_ptr<T> entry) {
        entries.push_back(std::move(entry));
    }

    // returneaza toate entry-urile
    const std::vector<std::shared_ptr<T>>& getAll() const {
        return entries;
    }

    // numarul total de entry-uri
    size_t count() const {
        return entries.size();
    }

    // sterge toate entry-urile
    void clear() {
        entries.clear();
    }

    // findIf = functie template membra
    // ia un Predicat si returneaza entry-urile unde predicatul e true
    template <typename Predicate>
    std::vector<std::shared_ptr<T>> findIf(Predicate pred) const {
        std::vector<std::shared_ptr<T>> result;
        // std::copy_if copiaza in result doar elementele pentru care pred returneaza true
        std::copy_if(entries.begin(), entries.end(),
                     std::back_inserter(result), pred);
        return result;
    }

    // countIf = functie template membra
    // numara cate entry-uri satisfac predicatul
    template <typename Predicate>
    size_t countIf(Predicate pred) const {
        return std::count_if(entries.begin(), entries.end(), pred);
    }
};

// FUNCTII TEMPLATE LIBERE care lucreaza cu orice Repository<T>
// pot fi folosite cu orice tip Loggable

// printAll — afiseaza toate entry-urile dintr-un repository
template <Loggable T>
void printAll(const Repository<T>& repo) {
    for (const auto& entry : repo.getAll())
        entry->display();
}

// printFiltered — afiseaza doar entry-urile care satisfac predicatul
template <Loggable T, typename Predicate>
void printFiltered(const Repository<T>& repo, Predicate pred) {
    auto results = repo.findIf(pred);
    for (const auto& entry : results)
        entry->display();
}
