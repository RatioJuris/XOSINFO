/*
 * XOSINFO - Cross-Platform System Information CLI
 * Author: Ratio Juris
 * Website: https://ratiojuris.github.io/XOSINFO/
 * Purpose: Judicial, legal, and forensic system state capture.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

#if defined(_WIN32)
    #include <windows.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "iphlpapi.lib")
#elif defined(__linux__) || defined(__APPLE__)
    #include <sys/utsname.h>
    #include <unistd.h>
    #include <ifaddrs.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/statvfs.h>
#endif

#if defined(__APPLE__)
    #include <sys/types.h>
    #include <sys/sysctl.h>
    #include <net/if_dl.h>
#elif defined(__linux__)
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <sys/sysinfo.h>
#endif

// Utility: Escape strings for JSON compliance
std::string escapeJson(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else o << c;
    }
    return o.str();
}

// Utility: Get current UTC timestamp
std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&now_c), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string getHostName() {
    char hostname[256];
#if defined(_WIN32)
    DWORD size = sizeof(hostname);
    if (GetComputerNameA(hostname, &size)) return hostname;
#else
    if (gethostname(hostname, sizeof(hostname)) == 0) return hostname;
#endif
    return "Unknown";
}

std::string getNetworkInterfaces() {
    std::stringstream ss;
    ss << "[\n";
    bool first = true;

#if defined(_WIN32)
    ULONG outBufLen = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO *)malloc(outBufLen);
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (!first) ss << ",\n";
            ss << "      {\n"
               << "        \"description\": \"" << escapeJson(pAdapter->Description) << "\",\n"
               << "        \"mac_address\": \"";
            for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                if (i == (pAdapter->AddressLength - 1))
                    ss << std::hex << std::setfill('0') << std::setw(2) << (int)pAdapter->Address[i];
                else
                    ss << std::hex << std::setfill('0') << std::setw(2) << (int)pAdapter->Address[i] << ":";
            }
            ss << "\",\n"
               << "        \"ip_address\": \"" << pAdapter->IpAddressList.IpAddress.String << "\"\n"
               << "      }";
            first = false;
            pAdapter = pAdapter->Next;
        }
    }
    if (pAdapterInfo) free(pAdapterInfo);

#elif defined(__linux__) || defined(__APPLE__)
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != -1) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) continue;
            
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip, INET_ADDRSTRLEN);
            
            std::string mac = "Unknown";
            #if defined(__APPLE__)
                // Mac OS MAC Address extraction logic could go here via AF_LINK
            #elif defined(__linux__)
                int fd = socket(AF_INET, SOCK_DGRAM, 0);
                struct ifreq ifr;
                strcpy(ifr.ifr_name, ifa->ifa_name);
                if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                    char macStr[18];
                    unsigned char* m = (unsigned char*)ifr.ifr_hwaddr.sa_data;
                    sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
                    mac = macStr;
                }
                close(fd);
            #endif

            if (!first) ss << ",\n";
            ss << "      {\n"
               << "        \"interface\": \"" << escapeJson(ifa->ifa_name) << "\",\n"
               << "        \"ip_address\": \"" << ip << "\",\n"
               << "        \"mac_address\": \"" << mac << "\"\n"
               << "      }";
            first = false;
        }
        freeifaddrs(ifaddr);
    }
#endif
    ss << "\n    ]";
    return ss.str();
}

std::string getSystemInfoJson() {
    long cpuCores = 0;
    long long totalRamBytes = 0;
    std::string osName = "Unknown";
    std::string arch = "Unknown";
    std::string buildVersion = "Unknown";
    long uptimeSeconds = 0;

#if defined(_WIN32)
    osName = "Windows";
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    cpuCores = sysInfo.dwNumberOfProcessors;
    
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    totalRamBytes = memInfo.ullTotalPhys;
    arch = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x86_64" : "x86";
    uptimeSeconds = GetTickCount64() / 1000;
#elif defined(__linux__) || defined(__APPLE__)
    struct utsname buffer;
    if (uname(&buffer) == 0) {
        #if defined(__APPLE__)
            osName = "macOS";
        #else
            osName = buffer.sysname;
        #endif
        arch = buffer.machine;
        buildVersion = buffer.release;
    }
    cpuCores = sysconf(_SC_NPROCESSORS_ONLN);

    #if defined(__linux__)
        struct sysinfo info;
        if (sysinfo(&info) == 0) {
            totalRamBytes = (long long)info.totalram * info.mem_unit;
            uptimeSeconds = info.uptime;
        }
    #elif defined(__APPLE__)
        int mib[2] = { CTL_HW, HW_MEMSIZE };
        size_t length = sizeof(totalRamBytes);
        sysctl(mib, 2, &totalRamBytes, &length, NULL, 0);
        
        struct timeval boottime;
        size_t len = sizeof(boottime);
        int mibTime[2] = { CTL_KERN, KERN_BOOTTIME };
        if (sysctl(mibTime, 2, &boottime, &len, NULL, 0) != -1) {
            uptimeSeconds = time(NULL) - boottime.tv_sec;
        }
    #endif
#endif

    std::stringstream json;
    json << "{\n"
         << "  \"metadata\": {\n"
         << "    \"tool\": \"XOSINFO\",\n"
         << "    \"author\": \"Ratio Juris\",\n"
         << "    \"website\": \"https://ratiojuris.github.io/XOSINFO/\",\n"
         << "    \"capture_timestamp_utc\": \"" << getCurrentTimestamp() << "\"\n"
         << "  },\n"
         << "  \"host\": {\n"
         << "    \"hostname\": \"" << escapeJson(getHostName()) << "\",\n"
         << "    \"os_name\": \"" << osName << "\",\n"
         << "    \"os_build_version\": \"" << escapeJson(buildVersion) << "\",\n"
         << "    \"architecture\": \"" << arch << "\",\n"
         << "    \"system_uptime_seconds\": " << uptimeSeconds << "\n"
         << "  },\n"
         << "  \"hardware\": {\n"
         << "    \"cpu_cores\": " << std::dec << cpuCores << ",\n"
         << "    \"total_ram_bytes\": " << totalRamBytes << "\n"
         << "  },\n"
         << "  \"network\": " << getNetworkInterfaces() << "\n"
         << "}\n";
         
    return json.str();
}

int main(int argc, char* argv[]) {
    std::string outputFile = "";

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            outputFile = argv[i + 1];
            i++;
        }
    }

    std::string jsonOutput = getSystemInfoJson();

    if (!outputFile.empty()) {
        std::ofstream outFile(outputFile);
        if (outFile.is_open()) {
            outFile << jsonOutput;
            outFile.close();
            std::cout << "Forensic system info written to " << outputFile << "\n";
        } else {
            std::cerr << "Error: Unable to write to file " << outputFile << "\n";
            return 1;
        }
    } else {
        std::cout << jsonOutput << "\n";
    }

    return 0;
}
