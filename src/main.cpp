/*
 * XOSINFO - Cross-Platform System Information CLI
 * Author: Ratio Juris
 * Website: https://github.io
 * Purpose: Judicial, legal, and forensic system state capture.
 * Language: C++17 or higher
 * Version: 1.0
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <memory>
#include <algorithm>
#include <cstdint>
#include <iterator>

#if defined(_WIN32)
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "ws2_32.lib")
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
    #include <mach/mach.h>
#elif defined(__linux__)
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <sys/sysinfo.h>
#endif

// Global Metadata Constants
constexpr const char* XOSINFO_VERSION = "1.0";
constexpr const char* XOSINFO_PURPOSE = "Judicial, legal, and forensic system state capture.";

// Structured models for predictable serialization
struct NetworkInterface {
    std::string name;
    std::string ipv4;
    std::string ipv6;
    std::string mac;
};

struct StorageVolume {
    std::string path;
    uint64_t totalBytes = 0;
    uint64_t freeBytes = 0;
    uint64_t availableBytes = 0;
};

struct MemoryState {
    uint64_t totalRamBytes = 0;
    uint64_t freeRamBytes = 0;
};

struct OperatingSystemInfo {
    std::string name;
    std::string release;
    std::string version;
    std::string architecture;
};

struct ForensicReport {
    std::string timestamp;
    std::string hostname;
    OperatingSystemInfo os;
    MemoryState memory;
    std::vector<StorageVolume> storage;
    std::vector<NetworkInterface> network;
};

// Utilities Namespace for safe transformations and JSON building
namespace Utils {
    std::string escapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            switch (c) {
                case '"':  o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b";  break;
                case '\f': o << "\\f";  break;
                case '\n': o << "\\n";  break;
                case '\r': o << "\\r";  break;
                case '\t': o << "\\t";  break;
                default:
                    if (static_cast<unsigned char>(c) < 32) {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        struct tm timeinfo;
#if defined(_WIN32)
        if (gmtime_s(&timeinfo, &now_c) != 0) return "UNKNOWN_TIME";
#else
        if (gmtime_r(&now_c, &timeinfo) == nullptr) return "UNKNOWN_TIME";
#endif
        ss << std::put_time(&timeinfo, "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }

    std::string serializeReport(const ForensicReport& report) {
        std::ostringstream json;
        json << "{\n";
        json << "  \"metadata\": {\n";
        json << "    \"tool\": \"XOSINFO\",\n";
        json << "    \"version\": \"" << escapeJson(XOSINFO_VERSION) << "\",\n";
        json << "    \"purpose\": \"" << escapeJson(XOSINFO_PURPOSE) << "\"\n";
        json << "  },\n";
        json << "  \"timestamp\": \"" << escapeJson(report.timestamp) << "\",\n";
        json << "  \"hostname\": \"" << escapeJson(report.hostname) << "\",\n";
        
        // OS Section
        json << "  \"os\": {\n";
        json << "    \"name\": \"" << escapeJson(report.os.name) << "\",\n";
        json << "    \"release\": \"" << escapeJson(report.os.release) << "\",\n";
        json << "    \"version\": \"" << escapeJson(report.os.version) << "\",\n";
        json << "    \"architecture\": \"" << escapeJson(report.os.architecture) << "\"\n";
        json << "  },\n";

        // Memory Section
        json << "  \"memory\": {\n";
        json << "    \"total_ram_bytes\": " << report.memory.totalRamBytes << ",\n";
        json << "    \"free_ram_bytes\": " << report.memory.freeRamBytes << "\n";
        json << "  },\n";

        // Storage Section
        json << "  \"storage\": [\n";
        for (size_t i = 0; i < report.storage.size(); ++i) {
            const auto& vol = report.storage[i];
            json << "    {\n";
            json << "      \"path\": \"" << escapeJson(vol.path) << "\",\n";
            json << "      \"total_bytes\": " << vol.totalBytes << ",\n";
            json << "      \"free_bytes\": " << vol.freeBytes << ",\n";
            json << "      \"available_bytes\": " << vol.availableBytes << "\n";
            json << "    }" << (i + 1 < report.storage.size() ? "," : "") << "\n";
        }
        json << "  ],\n";

        // Network Section
        json << "  \"network\": [\n";
        for (size_t i = 0; i < report.network.size(); ++i) {
            const auto& net = report.network[i];
            json << "    {\n";
            json << "      \"interface\": \"" << escapeJson(net.name) << "\",\n";
            json << "      \"ipv4\": \"" << escapeJson(net.ipv4) << "\",\n";
            json << "      \"ipv6\": \"" << escapeJson(net.ipv6) << "\",\n";
            json << "      \"mac_address\": \"" << escapeJson(net.mac) << "\"\n";
            json << "    }" << (i + 1 < report.network.size() ? "," : "") << "\n";
        }
        json << "  ]\n";
        json << "}\n";
        return json.str();
    }
}

// Low-level Platform Resolution Layer
class SystemDiscovery {
public:
    static std::string getHostName() {
        char buf[256] = {0};
#if defined(_WIN32)
        DWORD size = sizeof(buf);
        if (GetComputerNameA(buf, &size)) {
            return std::string(buf);
        }
#else
        if (gethostname(buf, sizeof(buf)) == 0) {
            return std::string(buf);
        }
#endif
        return "UNKNOWN_HOST";
    }

    static OperatingSystemInfo getOSInfo() {
        OperatingSystemInfo info;
#if defined(_WIN32)
        info.name = "Windows";
        info.release = "NT";
        info.version = "Unknown Version";
        info.architecture = "Unknown Arch";

        // Fetch basic architecture via environment or pointer sizes
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
            info.architecture = "x86_64";
        } else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
            info.architecture = "x86";
        } else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
            info.architecture = "arm64";
        }

        // Production configuration parsing of Windows Branding Registry
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char prodName[256] = {0};
            DWORD bufSize = sizeof(prodName);
            if (RegQueryValueExA(hKey, "ProductName", nullptr, nullptr, reinterpret_cast<LPBYTE>(prodName), &bufSize) == ERROR_SUCCESS) {
                info.version = std::string(prodName);
            }
            RegCloseKey(hKey);
        }
#else
        struct utsname buffer;
        if (uname(&buffer) == 0) {
            info.name = buffer.sysname;
            info.release = buffer.release;
            info.version = buffer.version;
            info.architecture = buffer.machine;
        } else {
            info.name = "POSIX-compliant Platform";
        }
#endif
        return info;
    }

    static MemoryState getMemoryState() {
        MemoryState state;
#if defined(_WIN32)
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            state.totalRamBytes = memInfo.ullTotalPhys;
            state.freeRamBytes = memInfo.ullAvailPhys;
        }
#elif defined(__linux__)
        struct sysinfo si;
        if (sysinfo(&si) == 0) {
            state.totalRamBytes = static_cast<uint64_t>(si.totalram) * si.mem_unit;
            state.freeRamBytes = static_cast<uint64_t>(si.freeram) * si.mem_unit;
        }
#elif defined(__APPLE__)
        int64_t totalRam = 0;
        size_t len = sizeof(totalRam);
        if (sysctlbyname("hw.memsize", &totalRam, &len, nullptr, 0) == 0) {
            state.totalRamBytes = totalRam;
        }
        
        vm_size_t pageSize;
        mach_port_t machPort = mach_host_self();
        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
        vm_statistics64_data_t vmStats;
        if (host_page_size(machPort, &pageSize) == KERN_SUCCESS &&
            host_statistics64(machPort, HOST_VM_INFO64, reinterpret_cast<host_info64_t>(&vmStats), &count) == KERN_SUCCESS) {
            state.freeRamBytes = static_cast<uint64_t>(vmStats.free_count) * pageSize;
        }
#endif
        return state;
    }

    static std::vector<StorageVolume> getStorageVolumes() {
        std::vector<StorageVolume> volumes;
#if defined(_WIN32)
        char driveBuffer[256] = {0};
        DWORD result = GetLogicalDriveStringsA(sizeof(driveBuffer), driveBuffer);
        if (result > 0 && result < sizeof(driveBuffer)) {
            char* drive = driveBuffer;
            while (*drive) {
                StorageVolume vol;
                vol.path = std::string(drive);
                
                ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
                if (GetDiskFreeSpaceExA(drive, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
                    vol.totalBytes = totalNumberOfBytes.QuadPart;
                    vol.freeBytes = totalNumberOfFreeBytes.QuadPart;
                    vol.availableBytes = freeBytesAvailable.QuadPart;
                    volumes.push_back(vol);
                }
                drive += strlen(drive) + 1;
            }
        }
#else
        // Fallback root target discovery for standard systems
        std::vector<std::string> searchPaths = {"/"};
#if defined(__linux__)
        // Add optional check paths if specific mounts are targeted
        searchPaths.push_back("/home");
#endif
        for (const auto& path : searchPaths) {
            struct statvfs vfs;
            if (statvfs(path.c_str(), &vfs) == 0) {
                StorageVolume vol;
                vol.path = path;
                vol.totalBytes = static_cast<uint64_t>(vfs.f_blocks) * vfs.f_frsize;
                vol.freeBytes = static_cast<uint64_t>(vfs.f_bfree) * vfs.f_frsize;
                vol.availableBytes = static_cast<uint64_t>(vfs.f_bavail) * vfs.f_frsize;
                volumes.push_back(vol);
            }
        }
#endif
        return volumes;
    }

    static std::vector<NetworkInterface> getNetworkInterfaces() {
        std::vector<NetworkInterface> list;
#if defined(_WIN32)
        ULONG outBufLen = 15000;
        std::unique_ptr<char[]> buffer(new char[outBufLen]);
        PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
        
        ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
        ULONG dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            buffer.reset(new char[outBufLen]);
            adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
            dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &outBufLen);
        }

        if (dwRetVal == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES curr = adapters; curr != nullptr; curr = curr->Next) {
                NetworkInterface net;
                net.name = curr->AdapterName; // Holds UUID format on Windows
                
                // Get MAC address
                if (curr->PhysicalAddressLength > 0) {
                    std::ostringstream macStr;
                    for (DWORD i = 0; i < curr->PhysicalAddressLength; ++i) {
                        macStr << std::hex << std::setw(2) << std::setfill('0') 
                               << static_cast<int>(curr->PhysicalAddress[i])
                               << (i + 1 < curr->PhysicalAddressLength ? ":" : "");
                    }
                    net.mac = macStr.str();
                }

                // Parse interface Addresses
                for (PIP_ADAPTER_UNICAST_ADDRESS addr = curr->FirstUnicastAddress; addr != nullptr; addr = addr->Next) {
                    char ipBuffer[100] = {0};
                    auto family = addr->Address.lpSockaddr->sa_family;
                    if (family == AF_INET) {
                        DWORD ipBufLen = sizeof(ipBuffer);
                        WSAAddressToStringA(addr->Address.lpSockaddr, addr->Address.iSockaddrLength, nullptr, ipBuffer, &ipBufLen);
                        net.ipv4 = ipBuffer;
                    } else if (family == AF_INET6) {
                        DWORD ipBufLen = sizeof(ipBuffer);
                        WSAAddressToStringA(addr->Address.lpSockaddr, addr->Address.iSockaddrLength, nullptr, ipBuffer, &ipBufLen);
                        net.ipv6 = ipBuffer;
                    }
                }
                list.push_back(net);
            }
        }
#else
        struct ifaddrs* interfaces = nullptr;
        // Exception safe wrapper pattern for getifaddrs
        if (getifaddrs(&interfaces) == 0) {
            for (struct ifaddrs* ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr) continue;

                // Find existing interface tracking item or register a new one
                auto it = std::find_if(list.begin(), list.end(), [&](const NetworkInterface& item) {
                    return item.name == ifa->ifa_name;
                });

                if (it == list.end()) {
                    NetworkInterface n;
                    n.name = ifa->ifa_name;
                    list.push_back(n);
                    it = std::prev(list.end());
                }

                char host[INET6_ADDRSTRLEN] = {0};
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    auto addr = &(reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr)->sin_addr);
                    if (inet_ntop(AF_INET, addr, host, sizeof(host))) {
                        it->ipv4 = host;
                    }
                } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                    auto addr = &(reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr)->sin6_addr);
                    if (inet_ntop(AF_INET6, addr, host, sizeof(host))) {
                        it->ipv6 = host;
                    }
                }
#if defined(__APPLE__)
                else if (ifa->ifa_addr->sa_family == AF_LINK) {
                    auto sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
                    if (sdl->sdl_alen > 0) {
                        std::ostringstream macStr;
                        unsigned char* ptr = reinterpret_cast<unsigned char*>(LLADDR(sdl));
                        for (int i = 0; i < sdl->sdl_alen; ++i) {
                            macStr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ptr[i])
                                   << (i + 1 < sdl->sdl_alen ? ":" : "");
                        }
                        it->mac = macStr.str();
                    }
                }
#elif defined(__linux__)
                // Linux socket interface resolution for physical address mapping
                int sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (sock >= 0) {
                    struct ifreq ifr;
                    std::size_t name_len = std::strlen(ifa->ifa_name);
                    if (name_len < sizeof(ifr.ifr_name)) {
                        std::strncpy(ifr.ifr_name, ifa->ifa_name, sizeof(ifr.ifr_name) - 1);
                        ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
                        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                            std::ostringstream macStr;
                            unsigned char* ptr = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
                            for (int i = 0; i < 6; ++i) {
                                macStr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ptr[i])
                                       << (i + 1 < 6 ? ":" : "");
                            }
                            it->mac = macStr.str();
                        }
                    }
                    close(sock);
                }
#endif
            }
            freeifaddrs(interfaces);
        }
#endif
        return list;
    }
};

int main(int argc, char* argv[]) {
    // Prevent standard stream synchronization performance overhead
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(nullptr);

    ForensicReport report;
    report.timestamp = Utils::getCurrentTimestamp();
    report.hostname = SystemDiscovery::getHostName();
    report.os = SystemDiscovery::getOSInfo();
    report.memory = SystemDiscovery::getMemoryState();
    report.storage = SystemDiscovery::getStorageVolumes();
    report.network = SystemDiscovery::getNetworkInterfaces();

    std::string output = Utils::serializeReport(report);

    // Write capture payload to standard stdout
    std::cout << output;

    // Optional forensic local file generation
    if (argc > 1) {
        std::string targetFile = argv[1];
        std::ofstream out(targetFile, std::ios::out | std::ios::trunc);
        if (out.is_open()) {
            out << output;
            out.close();
        } else {
            std::cerr << "\n[ERROR] Failed to securely write report to target location: " << targetFile << "\n";
            return 1;
        }
    }

    return 0;
}
