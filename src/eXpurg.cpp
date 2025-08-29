#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <sodium.h>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <limits.h>
#include <ctime>
#include <signal.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <aclapi.h>
#else
#include <linux/fs.h>
#include <linux/magic.h>
#include <sys/statfs.h>
#include <sys/acl.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

// Define error codes
#define EXIT_SUCCESS_CODE 0
#define EXIT_INVALID_FILE 1
#define EXIT_WRITE_FAILURE 2
#define EXIT_SYNC_FAILURE 3
#define EXIT_OPEN_FAILURE 4
#define EXIT_UNLINK_FAILURE 5
#define EXIT_STRICT_MODE 6
#define EXIT_SIGNAL_HANDLER_SETUP_FAILURE 7
#define EXIT_GENERAL_FAILURE 8

// Buffer size for write operations
#define BUFFER_SIZE 65536

// Defining ZFS_SUPER_MAGIC manually as it's not in all headers
#ifndef _WIN32
#define ZFS_SUPER_MAGIC 0x2fc12fc1
#endif

// Global variable for signal handler
volatile sig_atomic_t interrupted = 0;

void signal_handler(int sig) {
    (void)sig; // Silence unused parameter warning
    interrupted = 1;
}

class SecureEraser {
private:
    std::string filename;
    bool verbose;
    bool quiet;
    int passes;
    bool strict_mode;
    int error_code;
    off_t file_size;
    bool is_ssd;
    std::string fs_type;
    std::string parent_dir;
    bool use_sequential_only;
    time_t start_time;
    int current_pass;

    // Helper functions
    void log_info(const std::string& message) const {
        if (!quiet) {
            std::cout << "[eXpurg] INFO: " << message << std::endl;
        }
    }

    void log_warning(const std::string& message) const {
        if (!quiet) {
            std::cout << "[eXpurg] WARNING: " << message << std::endl;
        }
    }

    void log_error(const std::string& message) const {
        if (!quiet) {
            std::cerr << "[eXpurg] ERROR: " << message << std::endl;
        }
    }

    // Function to write to a file descriptor robustly
    bool robust_write(int fd, const void* buffer, size_t count) {
        ssize_t written_bytes = 0;
        const char* p = static_cast<const char*>(buffer);
        while (written_bytes < static_cast<ssize_t>(count)) {
            ssize_t result = write(fd, p + written_bytes, count - written_bytes);
            if (result == -1) {
                if (errno == EINTR) {
                    continue;
                }
                log_error("Write error: " + std::string(strerror(errno)));
                error_code = EXIT_WRITE_FAILURE;
                return false;
            }
            written_bytes += result;
        }
        return true;
    }

    // Function to seek in a file descriptor robustly
    off_t robust_lseek(int fd, off_t offset, int whence) {
        off_t new_offset;
        do {
            new_offset = lseek(fd, offset, whence);
        } while (new_offset == (off_t)-1 && errno == EINTR);

        if (new_offset == (off_t)-1) {
            log_error("Seek error: " + std::string(strerror(errno)));
            error_code = EXIT_GENERAL_FAILURE;
        }
        return new_offset;
    }

    // Function to securely wipe memory
    void secure_wipe_memory(void* buffer, size_t size) {
        if (sodium_init() == -1) {
            // If sodium_init fails, we wipe memory with memset
            memset(buffer, 0, size);
        } else {
            sodium_memzero(buffer, size);
        }
    }

    void secure_wipe_string(std::string& s) {
        secure_wipe_memory(&s[0], s.size());
    }

    // Cleans extended attributes
    bool clean_extended_attributes() {
#ifdef _WIN32
        log_warning("Extended attribute removal is not supported for Windows.");
        return true;
#else
        if (fs_type == "ntfs") {
            log_warning("Extended attribute removal is not supported on NTFS file systems.");
            return true;
        }

        ssize_t list_size = llistxattr(filename.c_str(), NULL, 0);
        if (list_size == -1) {
            if (errno != ENOTSUP && errno != ENODATA) {
                log_warning("Failed to list extended attributes: " + std::string(strerror(errno)));
                if (strict_mode) {
                    error_code = EXIT_UNLINK_FAILURE;
                    return false;
                }
            }
            return true;
        }

        std::vector<char> list_buffer(list_size);
        llistxattr(filename.c_str(), list_buffer.data(), list_size);

        for (char* name = list_buffer.data(); name < list_buffer.data() + list_size; name += strlen(name) + 1) {
            if (lremovexattr(filename.c_str(), name) == -1) {
                log_warning("Failed to remove extended attribute '" + std::string(name) + "': " + std::string(strerror(errno)));
                if (strict_mode) {
                    error_code = EXIT_UNLINK_FAILURE;
                    return false;
                }
            }
        }
        return true;
#endif
    }

    // Cleans ACLs (Access Control Lists)
    bool clean_acls() {
#ifdef _WIN32
        log_warning("ACL removal is not supported for Windows.");
        return true;
#else
        if (fs_type == "ntfs") {
            log_warning("ACL removal is not supported on NTFS file systems.");
            return true;
        }

        acl_t acl = acl_get_file(filename.c_str(), ACL_TYPE_ACCESS);
        if (acl == NULL) {
            if (errno != ENODATA) {
                log_warning("Failed to get ACLs: " + std::string(strerror(errno)));
                if (strict_mode) {
                    error_code = EXIT_UNLINK_FAILURE;
                    return false;
                }
            }
            return true;
        }
        
        acl_t empty_acl = acl_init(0);
        if (empty_acl == NULL) {
            log_warning("Failed to create empty ACL object. Cannot remove ACLs.");
            acl_free(acl);
            return true;
        }

        if (acl_set_file(filename.c_str(), ACL_TYPE_ACCESS, empty_acl) == -1) {
            log_warning("Failed to remove ACLs: " + std::string(strerror(errno)));
            if (strict_mode) {
                error_code = EXIT_UNLINK_FAILURE;
                return false;
            }
        }
        
        acl_free(acl);
        acl_free(empty_acl);
        return true;
#endif
    }

    // Checks for immutable flags
    bool handle_special_flags(int fd) {
#ifdef _WIN32
        log_warning("Special flag handling is not supported for Windows.");
        return true;
#else
        if (fs_type == "ntfs") {
            log_warning("Special flag handling is not supported on NTFS file systems.");
            return true;
        }
        
        unsigned int flags;
        if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == -1) {
            log_warning("Failed to get file system flags");
            return true;
        }

        if (flags & FS_IMMUTABLE_FL || flags & FS_APPEND_FL) {
            log_warning("File has immutable/append-only flags. Attempting to remove...");
            flags &= ~(FS_IMMUTABLE_FL | FS_APPEND_FL);
            if (ioctl(fd, FS_IOC_SETFLAGS, &flags) == -1) {
                log_error("Failed to remove immutable/append-only flags");
                if (strict_mode) {
                    error_code = EXIT_GENERAL_FAILURE;
                    return false;
                }
            }
        }
        return true;
#endif
    }

    // Overwrites data sequentially
    bool overwrite_sequential(int fd, std::vector<unsigned char>& buffer) {
        off_t bytes_to_write = file_size;
        off_t offset = 0;
        
        while (bytes_to_write > 0 && !interrupted) {
            size_t current_chunk_size = std::min(static_cast<off_t>(buffer.size()), bytes_to_write);
            
            randombytes_buf(buffer.data(), current_chunk_size);
            
            if (!robust_write(fd, buffer.data(), current_chunk_size)) {
                return false;
            }
            
            bytes_to_write -= current_chunk_size;
            offset += current_chunk_size;
        }
        
        if (robust_lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            return false;
        }
        return true;
    }

    // Overwrites data using SEEK_DATA
    bool overwrite_data_extents(int fd, std::vector<unsigned char>& buffer) {
#ifdef _WIN32
        log_warning("Optimized data extent overwrite is not supported for Windows.");
        return overwrite_sequential(fd, buffer);
#else
        if (fs_type == "ntfs") {
            log_warning("Optimized data extent overwrite is not supported on NTFS file systems.");
            return overwrite_sequential(fd, buffer);
        }
        
        off_t data_offset = 0;
        while (data_offset < file_size && !interrupted) {
            off_t hole_offset = robust_lseek(fd, data_offset, SEEK_HOLE);
            if (hole_offset == (off_t)-1) return false;

            off_t bytes_to_write = hole_offset - data_offset;
            if (bytes_to_write == 0) {
                break;
            }

            if (robust_lseek(fd, data_offset, SEEK_SET) == (off_t)-1) return false;

            while (bytes_to_write > 0 && !interrupted) {
                size_t current_chunk_size = std::min(static_cast<off_t>(buffer.size()), bytes_to_write);
                randombytes_buf(buffer.data(), current_chunk_size);
                if (!robust_write(fd, buffer.data(), current_chunk_size)) {
                    return false;
                }
                bytes_to_write -= current_chunk_size;
            }

            data_offset = robust_lseek(fd, hole_offset, SEEK_DATA);
            if (data_offset == (off_t)-1) {
                int err = errno;
                if (err == ENXIO || err == EINVAL) {
                    log_error("SEEK_DATA not supported by file system. Aborting optimized overwrite.");
                    return false;
                }
                log_error("Fatal seek error in data extent overwrite.");
                return false;
            }
        }
        return true;
#endif
    }

public:
    SecureEraser(const std::string& path, bool verb, bool quiet_mode, int num_passes, bool strict)
        : filename(path), verbose(verb), quiet(quiet_mode), passes(num_passes), strict_mode(strict),
          error_code(EXIT_SUCCESS_CODE), file_size(0), is_ssd(false), use_sequential_only(false) {
        size_t last_slash = filename.find_last_of('/');
        if (last_slash != std::string::npos) {
            parent_dir = filename.substr(0, last_slash);
        } else {
            parent_dir = ".";
        }
    }

    ~SecureEraser() {
        secure_wipe_string(filename);
        secure_wipe_string(parent_dir);
    }

    bool overwrite_file_multipass() {
        int fd = open(filename.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd == -1) {
            log_error("Failed to open file for writing: " + std::string(strerror(errno)));
            error_code = EXIT_OPEN_FAILURE;
            return false;
        }

        if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
            log_warning("File is locked by another process");
        }

        if (!handle_special_flags(fd)) {
            close(fd);
            return false;
        }
        
        struct stat st;
        if (fstat(fd, &st) == -1) {
            log_error("Failed to get file status.");
            close(fd);
            error_code = EXIT_INVALID_FILE;
            return false;
        }
        
        file_size = st.st_size;

        if (fchmod(fd, 0000) == -1) {
            log_warning("Failed to set restrictive permissions");
        }

        bool success = true;
        std::vector<unsigned char> buffer(BUFFER_SIZE);

        if (ftruncate(fd, file_size) != 0) {
            log_error("Failed to truncate file");
            close(fd);
            error_code = EXIT_WRITE_FAILURE;
            return false;
        }

        start_time = time(NULL);

        for (current_pass = 1; current_pass <= passes && !interrupted; current_pass++) {
            log_info("Secure pass " + std::to_string(current_pass) + "/" +
                     std::to_string(passes) + "...");

            if (robust_lseek(fd, 0, SEEK_SET) == (off_t)-1) {
                success = false;
                break;
            }

            if (file_size > 0) {
                if (use_sequential_only) {
                    success = overwrite_sequential(fd, buffer);
                } else {
                    success = overwrite_data_extents(fd, buffer);
                    if (!success) {
                        if (error_code == EXIT_GENERAL_FAILURE) {
                            log_warning("Optimized overwrite failed, falling back to sequential overwrite.");
                            use_sequential_only = true;
                            current_pass--; // Retry this pass with sequential overwrite
                            continue;
                        }
                    }
                }

                if (!success) break;
            }

            if (fdatasync(fd) == -1) {
                log_error("Data synchronization failed");
                error_code = EXIT_SYNC_FAILURE;
                success = false;
                break;
            }

            secure_wipe_memory(buffer.data(), buffer.size());

            if (interrupted) {
                success = false;
                break;
            }
        }

        if (success && !interrupted) {
            if (robust_lseek(fd, 0, SEEK_SET) == (off_t)-1) {
                success = false;
            } else {
                std::fill(buffer.begin(), buffer.end(), 0);
                off_t bytes_remaining = file_size;
                while (bytes_remaining > 0 && !interrupted) {
                    size_t bytes_to_write = std::min(buffer.size(), static_cast<size_t>(bytes_remaining));
                    if (!robust_write(fd, buffer.data(), bytes_to_write)) {
                        success = false;
                        break;
                    }
                    bytes_remaining -= bytes_to_write;
                }
                if (fdatasync(fd) == -1) {
                    log_error("Final synchronization failed");
                    error_code = EXIT_SYNC_FAILURE;
                    success = false;
                }
            }
        }

        secure_wipe_memory(buffer.data(), buffer.size());
        close(fd);
        return success && !interrupted;
    }

    bool brute_force_delete() {
        log_info("Attempting secure deletion...");

        if (fs_type != "ntfs" && !clean_extended_attributes() && strict_mode) return false;
        if (fs_type != "ntfs" && !clean_acls() && strict_mode) return false;

        std::string temp_name = generate_random_name();
        std::string new_path = parent_dir + "/" + temp_name;

        if (rename(filename.c_str(), new_path.c_str()) == 0) {
            sync_parent_dir();
        } else {
            log_warning("Failed to rename file");
            new_path = filename;
        }

        if (remove(new_path.c_str()) == 0) {
            sync_parent_dir();
            secure_wipe_string(temp_name);
            return true;
        } else {
            log_error("Failed to delete file after multiple attempts: " + std::string(strerror(errno)));
            error_code = EXIT_UNLINK_FAILURE;
            return false;
        }
    }

    bool is_cow_filesystem() const {
#ifdef _WIN32
        return false;
#else
        return fs_type == "btrfs" || fs_type == "zfs";
#endif
    }

    bool needs_special_warning() const {
        return is_ssd || is_cow_filesystem() || fs_type == "ntfs";
    }

    void show_security_warnings() const {
        if (fs_type == "ntfs") {
            log_warning("NTFS FILE SYSTEM DETECTED:");
            log_warning("Security metadata cleansing (ACLs, attributes) is not supported.");
            log_warning("Only data overwriting will be performed.");
        }
        if (is_ssd) {
            log_warning("SSD DETECTED: Multiple passes do not guarantee physical erasure on SSDs");
        }
        if (is_cow_filesystem()) {
            log_warning("COPY-ON-WRITE FILESYSTEM DETECTED: " + fs_type);
            log_warning("Physical erasure is not guaranteed on this file system.");
        }
        log_warning("GENERAL SECURITY LIMITATIONS:");
        log_warning("- File system journaling may retain data in logs");
        log_warning("- Page/SWAP cache may preserve fragments in RAM/disk");
        log_warning("- Automatic backups/snapshots may retain file copies");
        if (!strict_mode) {
            log_warning("STRICT MODE NOT ENABLED: Some security checks are disabled");
        }
    }

    // Main entry point for the erase process
    bool secure_erase() {
        if (!collect_file_info()) {
            return false;
        }

        if (strict_mode && needs_special_warning()) {
            log_error("Strict mode: Physical erasure is not guaranteed on SSD/COW/NTFS. Operation aborted.");
            error_code = EXIT_STRICT_MODE;
            return false;
        }

        show_security_warnings();
        
        bool overwrite_success = false;
        if (file_size == 0) {
            log_info("Empty file, proceeding with deletion");
            overwrite_success = true;
        } else {
            overwrite_success = overwrite_file_multipass();
            if (!overwrite_success) {
                if (interrupted) {
                    log_error("Operation interrupted by user on pass " +
                             std::to_string(current_pass) + "/" + std::to_string(passes));
                    log_warning("Residual data may remain on disk due to interruption");
                } else {
                    log_error("Overwrite failed on pass " +
                             std::to_string(current_pass) + "/" + std::to_string(passes) +
                             ". Attempting to delete the file anyway.");
                }
            }
        }

        bool delete_success = brute_force_delete();

        if (overwrite_success && delete_success) {
            log_info("Secure erasure completed successfully!");
            return true;
        } else {
            log_error("Secure erasure failed. The file may not have been completely erased.");
            return false;
        }
    }

    int get_error_code() const { return error_code; }

private:
    std::string generate_random_name() {
        const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string result;
        result.reserve(16);
        for (int i = 0; i < 16; ++i) {
            result += charset[randombytes_uniform(sizeof(charset) - 1)];
        }
        return result;
    }

    bool get_file_size(const std::string& path, off_t& size) {
        struct stat st;
        if (stat(path.c_str(), &st) != 0) {
            log_error("Failed to get file size");
            return false;
        }
        size = st.st_size;
        return true;
    }

    void sync_parent_dir() {
#ifdef _WIN32
        return;
#else
        int dir_fd = open(parent_dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dir_fd != -1) {
            fsync(dir_fd);
            close(dir_fd);
        }
#endif
    }
    
    bool collect_file_info() {
        if (access(filename.c_str(), F_OK) == -1) {
            log_error("File not found");
            error_code = EXIT_INVALID_FILE;
            return false;
        }

        struct stat st;
        if (lstat(filename.c_str(), &st) != 0) {
            log_error("Failed to get file information");
            error_code = EXIT_INVALID_FILE;
            return false;
        }

        if (S_ISDIR(st.st_mode)) {
            log_error("Cannot securely erase directories");
            error_code = EXIT_INVALID_FILE;
            return false;
        }

        if (!get_file_size(filename, file_size)) return false;

        is_ssd = detect_ssd();
        fs_type = detect_filesystem();

        if (verbose) {
            log_info("Starting secure erasure of: " + filename);
            log_info("Path: " + filename);
            log_info("Size: " + std::to_string(file_size) + " bytes");
            log_info("Secure passes: " + std::to_string(passes));
            log_info("Strict mode: " + std::string(strict_mode ? "Enabled" : "Disabled"));
            log_info("Quiet mode: " + std::string(quiet ? "Enabled" : "Disabled"));
            log_info("Media: " + std::string(is_ssd ? "SSD" : "HDD"));
            log_info("File system: " + fs_type);
        }

        if (strict_mode && needs_special_warning()) {
            log_error("Strict mode: Physical erasure is not guaranteed on SSD/COW/NTFS. Operation aborted.");
            error_code = EXIT_STRICT_MODE;
            return false;
        }
        return true;
    }

    std::string detect_filesystem() const {
#ifdef _WIN32
        return "ntfs";
#else
        struct statfs sfs;
        if (statfs(filename.c_str(), &sfs) != 0) {
            return "unknown";
        }
        switch (sfs.f_type) {
            case BTRFS_SUPER_MAGIC: return "btrfs";
            case ZFS_SUPER_MAGIC: return "zfs";
            case EXT4_SUPER_MAGIC: return "ext4";
            case F2FS_SUPER_MAGIC: return "f2fs";
            case 0x6e746673: // NTFS magic number
            case 0x5346544e: // NTFS_SB_MAGIC
                return "ntfs";
            default:
                std::ostringstream ss;
                ss << "unknown (" << std::hex << sfs.f_type << ")";
                return ss.str();
        }
#endif
    }

    bool detect_ssd() const {
#ifdef _WIN32
        log_warning("SSD detection is not supported for Windows.");
        return false;
#else
        struct stat st;
        if (lstat(filename.c_str(), &st) != 0) {
            return false;
        }
        std::string device_path = "/sys/dev/block/" + std::to_string(major(st.st_dev)) + ":" + std::to_string(minor(st.st_dev)) + "/queue/rotational";
        std::ifstream rotational_file(device_path);
        int rotational_value;
        if (rotational_file >> rotational_value) {
            return rotational_value == 0;
        }
        return false;
#endif
    }
};

#ifndef _WIN32
void show_system_info() {
    std::cout << "\n--- System Information ---" << std::endl;
    // Get OS info
    std::ifstream os_file("/etc/os-release");
    if (os_file.is_open()) {
        std::string line;
        while (std::getline(os_file, line)) {
            if (line.rfind("PRETTY_NAME=", 0) == 0) {
                std::string os_name = line.substr(13, line.length() - 14);
                std::cout << "Operating System: " << os_name << std::endl;
                break;
            }
        }
        os_file.close();
    } else {
        std::cout << "Operating System: Could not determine" << std::endl;
    }

    // Get Processor Info
    std::ifstream cpu_file("/proc/cpuinfo");
    if (cpu_file.is_open()) {
        std::string line;
        while (std::getline(cpu_file, line)) {
            if (line.rfind("model name", 0) == 0) {
                size_t colon_pos = line.find(':');
                std::string model = line.substr(colon_pos + 2);
                std::cout << "Processor: " << model << std::endl;
                break;
            }
        }
        cpu_file.close();
    } else {
        std::cout << "Processor: Could not determine" << std::endl;
    }

    // Get Memory Info
    std::ifstream mem_file("/proc/meminfo");
    if (mem_file.is_open()) {
        std::string line;
        while (std::getline(mem_file, line)) {
            if (line.rfind("MemTotal:", 0) == 0) {
                size_t space_pos = line.find(' ');
                std::string total_mem_str = line.substr(space_pos);
                std::istringstream iss(total_mem_str);
                int mem_kb;
                iss >> mem_kb;
                std::cout << "Total Memory: " << std::fixed << std::setprecision(2) << (mem_kb / 1024.0 / 1024.0) << " GB" << std::endl;
                break;
            }
        }
        mem_file.close();
    } else {
        std::cout << "Total Memory: Could not determine" << std::endl;
    }

    // Get Disk Info
    struct statfs sfs;
    if (statfs(".", &sfs) == 0) {
        double total_size_gb = (double)sfs.f_blocks * sfs.f_bsize / 1024.0 / 1024.0 / 1024.0;
        std::cout << "Total Disk Space: " << std::fixed << std::setprecision(2) << total_size_gb << " GB" << std::endl;
    } else {
        std::cout << "Total Disk Space: Could not determine" << std::endl;
    }

    std::cout << "------------------------------\n" << std::endl;
}
#else
void show_system_info() {
    std::cout << "--- System Information ---" << std::endl;
    std::cout << "Processor: Not supported for Windows" << std::endl;
    std::cout << "Total Memory: Not supported for Windows" << std::endl;
    std::cout << "Total Disk Space: Not supported for Windows" << std::endl;
    std::cout << "Operating System: Windows" << std::endl;
    std::cout << "------------------------------" << std::endl;
}
#endif

void print_help(const std::string& prog_name) {
    std::cout << "Usage: " << prog_name << " [OPTIONS] <file>" << std::endl;
    std::cout << "Securely erases files." << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help           Shows this help message and exits" << std::endl;
    std::cout << "  -v, --verbose        Enables verbose output during the erasure process" << std::endl;
    std::cout << "  -q, --quiet          Disables all output" << std::endl;
    std::cout << "  -p, --passes <num>   Number of overwrite passes (default: 20)" << std::endl;
    std::cout << "  -s, --strict         Aborts on non-guaranteed erasure (SSD/COW/NTFS)" << std::endl;
    std::cout << "\n--------------------------------------" << std::endl;
    std::cout << "Developed by: Víctor Duarte Melo" << std::endl;
    std::cout << "Date: August 29, 2025" << std::endl;
    std::cout << "License: MIT License" << std::endl;
    std::cout << "--------------------------------------" << std::endl;
    show_system_info();
}

int main(int argc, char** argv) {
    std::string filename;
    bool verbose = false;
    bool quiet = false;
    int passes = 20;
    bool strict_mode = false;
    
    std::vector<std::string> args(argv + 1, argv + argc);
    
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "-h" || args[i] == "--help") {
            print_help(argv[0]);
            return EXIT_SUCCESS_CODE;
        } else if (args[i] == "-v" || args[i] == "--verbose") {
            verbose = true;
        } else if (args[i] == "-q" || args[i] == "--quiet") {
            quiet = true;
        } else if (args[i] == "-s" || args[i] == "--strict") {
            strict_mode = true;
        } else if (args[i] == "-p" || args[i] == "--passes") {
            if (i + 1 < args.size()) {
                try {
                    passes = std::stoi(args[++i]);
                } catch (const std::exception& e) {
                    std::cerr << "Invalid argument for --passes: " << args[i] << std::endl;
                    return EXIT_GENERAL_FAILURE;
                }
            } else {
                std::cerr << "Missing argument for --passes" << std::endl;
                return EXIT_GENERAL_FAILURE;
            }
        } else {
            filename = args[i];
        }
    }

    if (filename.empty()) {
        std::cerr << "Error: No file specified." << std::endl;
        print_help(argv[0]);
        return EXIT_GENERAL_FAILURE;
    }

    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        std::cerr << "Error: Failed to set up signal handler." << std::endl;
        return EXIT_SIGNAL_HANDLER_SETUP_FAILURE;
    }

    SecureEraser eraser(filename, verbose, quiet, passes, strict_mode);

    if (eraser.secure_erase()) {
        if (!quiet) {
            std::cout << "Final status: success" << std::endl;
        }
        return EXIT_SUCCESS_CODE;
    } else {
        if (!quiet) {
            std::cout << "Final status: failure" << std::endl;
        }
        return eraser.get_error_code();
    }
}
