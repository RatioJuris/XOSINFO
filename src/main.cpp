/*
 * XOSINFO - Cross-Platform System Information CLI Wrappers
 * Author: Ratio Juris
 * Website: https://github.com
 * Purpose: Judicial, legal, and forensic system state capture via unified wrapper.
 * Language: C++17 or higher
 */

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include <array>
#include <map>
#include <algorithm>
#include <cctype>
#include <stdexcept>

// Program Metadata Context
constexpr const char* XOSINFO_VERSION = "1.0";
constexpr const char* XOSINFO_COPYRIGHT = "(c) 2026 Ratio Juris. All rights reserved.";
constexpr const char* XOSINFO_PURPOSE = "Judicial, legal, and forensic system state capture via Windows systeminfo processing.";

// Trims leading and trailing whitespace from string targets
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// Executes a background shell pipeline command and reads output text
std::string executeCommand(const std::string& cmd) {
    std::array<char, 256> buffer;
    std::string result;
    
    try {
#ifdef _WIN32
        FILE* pipePtr = _popen(cmd.c_str(), "r");
#else
        FILE* pipePtr = popen(cmd.c_str(), "r");
#endif
        if (!pipePtr) {
            throw std::runtime_error("Pipe initialization failure (popen failed).");
        }

#ifdef _WIN32
        std::unique_ptr<FILE, decltype(&_pclose)> pipe(pipePtr, _pclose);
#else
        std::unique_ptr<FILE, decltype(&pclose)> pipe(pipePtr, pclose);
#endif

        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
    } 
    catch (const std::exception& e) {
        throw std::runtime_error(std::string("Execution stream disrupted: ") + e.what());
    }
    catch (...) {
        throw std::runtime_error("Unknown critical hardware exception inside executeCommand.");
    }

    return result;
}

// Parses raw text output from systeminfo into structured key-value maps
std::map<std::string, std::string> parseSystemInfo(const std::string& rawOutput) {
    std::map<std::string, std::string> infoMap;
    std::stringstream ss(rawOutput);
    std::string line;
    std::string currentKey = "";

    while (std::getline(ss, line)) {
        size_t colonPos = line.find(':');
        
        if (colonPos != std::string::npos) {
            std::string key = trim(line.substr(0, colonPos));
            std::string value = trim(line.substr(colonPos + 1));
            
            // Filter nested block structures or array lists (e.g. Network Card logs or hotfix iterations)
            if (!key.empty() && line.find("   ") != 0) { 
                currentKey = key;
                infoMap[currentKey] = value;
            } else if (!currentKey.empty()) {
                infoMap[currentKey] += "\n" + trim(line);
            }
        } else if (!currentKey.empty() && !trim(line).empty()) {
            infoMap[currentKey] += " " + trim(line);
        }
    }
    return infoMap;
}

// Escapes raw values for structured JSON format standard validation
std::string escapeJSON(const std::string& str) {
    std::ostringstream ss;
    for (char c : str) {
        switch (c) {
            case '"':  ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b"; break;
            case '\f': ss << "\\f"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:   ss << c; break;
        }
    }
    return ss.str();
}

// Escapes special character entities for valid structural XML layout
std::string escapeXML(const std::string& str) {
    std::ostringstream ss;
    for (char c : str) {
        switch (c) {
            case '&':  ss << "&amp;"; break;
            case '<':  ss << "&lt;"; break;
            case '>':  ss << "&gt;"; break;
            case '"':  ss << "&quot;"; break;
            case '\'': ss << "&apos;"; break;
            default:   ss << c; break;
        }
    }
    return ss.str();
}

// Dynamically transforms system property spaces into snake_case elements for valid XML tag nodes
std::string makeXMLTagName(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
        if (std::isalnum(c)) return (char)std::tolower(c);
        return '_';
    });
    if (str.empty() || std::isdigit(str)) {
        str = "property_" + str;
    }
    return str;
}

// Renders interactive tool onboarding interface splash structure and parameters list
void printWelcomeMenu(const std::string& exeName, const std::map<std::string, std::string>& infoMap) {
    std::cout << "Welcome to " << exeName << " v" << XOSINFO_VERSION << "\n";
    std::cout << XOSINFO_COPYRIGHT << "\n\n";
    std::cout << "CLI / Automated Mode Profiles:\n";
    std::cout << "  * " << exeName << " all -> Formats snapshot to JSON layout.\n";
    std::cout << "  * " << exeName << " xml -> Serializes configuration to XML format layout.\n\n";
    
    std::cout << "Interactive Mode Active:\n";
    std::cout << "  Type any valid property name from the list below to view its state value.\n";
    std::cout << "  Type \"all\" or \"xml\" anytime to execute structural conversions.\n";
    std::cout << "  Type \"exit\" to close this window session loop.\n\n";
    
    std::cout << "=========================================================\n";
    std::cout << " ALL AVAILABLE SYSTEM PARAMETERS FOUND ON THIS MACHINE:\n";
    std::cout << "=========================================================\n";
    
    int index = 1;
    for (const auto& pair : infoMap) {
        std::cout << "  [" << index++ << "] " << pair.first << "\n";
    }
    std::cout << "=========================================================\n\n";
}

// Routes and process target parameter extraction requests
void evaluateAndPrintParameter(const std::string& targetedParameter, const std::map<std::string, std::string>& parsedDataMap) {
    if (targetedParameter == "all") {
        std::cout << "{\n";
        for (auto mapIterator = parsedDataMap.begin(); mapIterator != parsedDataMap.end(); ++mapIterator) {
            std::cout << "  \"" << escapeJSON(mapIterator->first) << "\": \"" 
                      << escapeJSON(mapIterator->second) << "\"";
            if (std::next(mapIterator) != parsedDataMap.end()) {
                std::cout << ",";
            }
            std::cout << "\n";
        }
        std::cout << "}\n";
    } 
    else if (targetedParameter == "xml") {
        std::cout << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        std::cout << "<system_state_capture>\n";
        for (const auto& systemProperty : parsedDataMap) {
            std::string formattedTag = makeXMLTagName(systemProperty.first);
            std::cout << "  <" << formattedTag << " attribute_key=\"" << escapeXML(systemProperty.first) << "\">" 
                      << escapeXML(systemProperty.second) << "</" << formattedTag << ">\n";
        }
        std::cout << "</system_state_capture>\n";
    } 
    else {
        std::string userQueryKey = targetedParameter;
        std::transform(userQueryKey.begin(), userQueryKey.end(), userQueryKey.begin(), ::tolower);
        
        bool matchDiscovered = false;
        for (const auto& systemProperty : parsedDataMap) {
            std::string currentPropertyKey = systemProperty.first;
            std::transform(currentPropertyKey.begin(), currentPropertyKey.end(), currentPropertyKey.begin(), ::tolower);
            
            if (currentPropertyKey == userQueryKey) {
                std::cout << "\n>>> " << systemProperty.first << ":\n" << systemProperty.second << "\n\n";
                matchDiscovered = true;
                break;
            }
        }
        
        if (!matchDiscovered) {
            std::cout << "\n[!] Parameter '" << targetedParameter << "' not found. Type 'all' to see available keys.\n\n";
        }
    }
}

int main(int argc, char* argv[]) {
    std::string fullPath = (argc > 0 && argv[0]) ? argv[0] : "xosinfo.exe";
    size_t lastSlash = fullPath.find_last_of("\\/");
    std::string programName = (lastSlash == std::string::npos) ? fullPath : fullPath.substr(lastSlash + 1);

    try {
        // Collect raw configurations early to dynamically populate menu parameter options
        std::string rawData = executeCommand("systeminfo");
        auto parsedDataMap = parseSystemInfo(rawData);

        // Fallback: If no direct command arguments are fed via CLI launch interactive prompt
        if (argc < 2) {
            printWelcomeMenu(programName, parsedDataMap);
            
            std::string inputBuffer;
            while (true) {
                std::cout << "Enter Parameter > ";
                if (!std::getline(std::cin, inputBuffer)) {
                    break; 
                }
                
                std::string processedInput = trim(inputBuffer);
                if (processedInput.empty()) {
                    continue;
                }
                
                std::string exitCheck = processedInput;
                std::transform(exitCheck.begin(), exitCheck.end(), exitCheck.begin(), ::tolower);
                if (exitCheck == "exit") {
                    std::cout << "Closing secure system state interface loop.\n";
                    break;
                }
                
                evaluateAndPrintParameter(processedInput, parsedDataMap);
            }
            return 0;
        }

        // Direct Execution Branch (e.g. program.exe all)
        std::string targetedParameter = argv[1];
        evaluateAndPrintParameter(targetedParameter, parsedDataMap);

    } 
    catch (const std::exception& errorObject) {
        std::cerr << "Pipeline Fatal Failure: " << errorObject.what() << "\n";
        return 1;
    }
    catch (...) {
        std::cerr << "Pipeline Fatal Failure: Unhandled non-standard runtime error exception occurred.\n";
        return 1;
    }
    
    return 0;
}
