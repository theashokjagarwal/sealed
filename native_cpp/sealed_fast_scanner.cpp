// SEALED Native C++17 Streaming PII & Secret Scanner
// Zero external dependencies. Constant-memory line streaming for multi-GB datasets.
// Build: g++ -std=c++17 -O2 -Wall -Wextra -o sealed_fast_scanner sealed_fast_scanner.cpp

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct Finding {
    std::string kind;
    std::string file;
    size_t line;
    std::string masked;
};

static bool luhn_valid(const std::string& raw) {
    std::string digits;
    digits.reserve(raw.size());
    for (char c : raw) {
        if (std::isdigit(static_cast<unsigned char>(c))) {
            digits.push_back(c);
        }
    }
    if (digits.size() < 13 || digits.size() > 19) {
        return false;
    }
    int sum = 0;
    bool alt = false;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        int d = *it - '0';
        if (alt) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        alt = !alt;
    }
    return (sum % 10) == 0;
}

static std::string json_escape(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 8);
    for (char c : input) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

static bool is_inside_root(const fs::path& root, const fs::path& target) {
    std::error_code ec;
    fs::path canon_root = fs::weakly_canonical(root, ec);
    if (ec) return false;
    fs::path canon_target = fs::weakly_canonical(target, ec);
    if (ec) return false;
    auto r_str = canon_root.string();
    auto t_str = canon_target.string();
    return t_str.rfind(r_str, 0) == 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: sealed_fast_scanner <project_directory>\n";
        return 2;
    }

    fs::path target_dir(argv[1]);
    std::error_code ec;
    if (!fs::exists(target_dir, ec) || !fs::is_directory(target_dir, ec)) {
        std::cerr << "[FATAL] Target directory does not exist: " << argv[1] << "\n";
        return 2;
    }

    fs::path canon_root = fs::canonical(target_dir, ec);
    if (ec) {
        std::cerr << "[FATAL] Failed to canonicalize root: " << ec.message() << "\n";
        return 2;
    }

    std::vector<fs::path> files;
    for (auto it = fs::recursive_directory_iterator(canon_root, ec);
         it != fs::recursive_directory_iterator() && !ec;
         it.increment(ec)) {
        const auto& p = it->path();
        if (it->is_directory(ec)) {
            auto name = p.filename().string();
            if (name == ".git" || name == "target" || name == "node_modules") {
                it.disable_recursion_pending();
            }
            continue;
        }
        if (it->is_symlink(ec) && !is_inside_root(canon_root, p)) {
            std::cerr << "[FATAL SECURITY VIOLATION] Symlink escape detected: " << p << "\n";
            return 2;
        }
        if (it->is_regular_file(ec)) {
            files.push_back(p);
        }
    }

    std::sort(files.begin(), files.end());

    const std::regex card_re(R"(\b(?:\d[ -]*?){13,19}\b)");
    const std::regex ssn_re(R"(\b\d{3}-\d{2}-\d{4}\b)");
    const std::regex key_re(R"((?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}))");

    std::vector<Finding> findings;
    for (const auto& file_path : files) {
        std::ifstream fh(file_path);
        if (!fh.is_open()) continue;

        std::string rel = fs::relative(file_path, canon_root, ec).generic_string();
        std::string line;
        size_t line_no = 0;

        while (std::getline(fh, line)) {
            ++line_no;
            std::smatch m;

            auto card_begin = std::sregex_iterator(line.begin(), line.end(), card_re);
            auto card_end = std::sregex_iterator();
            for (auto i = card_begin; i != card_end; ++i) {
                std::string raw = i->str();
                if (luhn_valid(raw)) {
                    std::string digits;
                    for (char c : raw) if (std::isdigit(static_cast<unsigned char>(c))) digits.push_back(c);
                    std::string masked = digits.substr(0, 4) + "****" + digits.substr(digits.size() - 4);
                    findings.push_back({"payment_card", rel, line_no, masked});
                }
            }

            if (std::regex_search(line, m, ssn_re)) {
                std::string val = m.str();
                findings.push_back({"ssn", rel, line_no, "***-**-" + val.substr(val.size() - 4)});
            }

            if (std::regex_search(line, m, key_re)) {
                std::string val = m.str();
                findings.push_back({"secret_key", rel, line_no, val.substr(0, 7) + "...[REDACTED]"});
            }
        }
    }

    std::cout << "{\n  \"engine\": \"sealed-cpp17-fast-scanner\",\n";
    std::cout << "  \"files_scanned\": " << files.size() << ",\n";
    std::cout << "  \"findings_count\": " << findings.size() << ",\n";
    std::cout << "  \"findings\": [\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        std::cout << "    {\"kind\": \"" << json_escape(f.kind)
                  << "\", \"file\": \"" << json_escape(f.file)
                  << "\", \"line\": " << f.line
                  << ", \"masked\": \"" << json_escape(f.masked) << "\"}"
                  << (i + 1 < findings.size() ? "," : "") << "\n";
    }
    std::cout << "  ]\n}\n";

    return findings.empty() ? 0 : 1;
}
