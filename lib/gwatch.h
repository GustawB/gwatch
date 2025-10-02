#include <iostream>
#include <fstream>
#include <unistd.h>
#include <vector>
#include <string.h>
#include <linux/elf.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/wait.h>

class ptrace_exception: public std::exception
{
private:
    std::string message;

public:
    ptrace_exception(std::string msg) : message(msg) {}

    virtual const char* what() const throw() {
        return message.c_str();
    }
};

class value_exception: public std::exception
{
private:
    std::string message;

public:
    value_exception(std::string msg) : message(msg) {}

    virtual const char* what() const throw() {
        return message.c_str();
    }
};

std::pair<int64_t, int8_t> get_variable_virt_addr_and_size(std::string file_name, std::string var_name) {
    std::ifstream file (file_name, std::ios::in|std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open binary\n";
        return std::pair(-1, -1);
    }

    Elf64_Ehdr header;
    file.read((char*)(&header), sizeof(header));

    file.seekg(header.e_shoff);

    const int shnum = header.e_shnum;
    Elf64_Shdr shdrs[shnum];

    file.read((char*)(&shdrs), shnum * header.e_shentsize);
    Elf64_Shdr symtab;
    bool was_symtab_found = false;
    int i = 0;
    while (i < shnum && !was_symtab_found) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab = shdrs[i];
            was_symtab_found = true;
        }
        ++i;
    }
    if (!was_symtab_found) {
        std::cerr << "Malformed elf does not contain symbol table\n";
        return std::pair(-1, -1);
    }

    Elf64_Shdr strtab = shdrs[symtab.sh_link];
    file.seekg(symtab.sh_offset);
    const int stnum = symtab.sh_size / sizeof(Elf64_Sym);
    Elf64_Sym symbols[stnum];

    file.read((char*)(&symbols), symtab.sh_size);
    for (int i = 0; i < stnum; ++i) {
        file.seekg(strtab.sh_offset + symbols[i].st_name);

        std::string result;
        char c;
        while (file.get(c)) {
            if (c == '\0') break;
            result.push_back(c);
        }
        if (result == var_name) {
            if (symbols[i].st_size != 4 && symbols[i].st_size != 8) {
                std::cerr << "Specified symbol has invalid size (expected 4 or 8)\n";
                return std::pair(-1, -1);
            }
            return std::pair(symbols[i].st_value, symbols[i].st_size);
        }
    }

    std::cerr << "Specified symbol not found\n";
    return std::pair(-1, -1);
}

template <typename T>
T read_var(int pid, int64_t var_addr) {
    T val;
    struct iovec local{ &val, sizeof(val) };
    struct iovec remote{ (void*)var_addr, sizeof(val) };

    ssize_t nread = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (nread != sizeof(val)) {
        throw value_exception("Failed to read symbol's value in the tracee program");
    } else {
        return val;
    }
}

int64_t get_load_address(pid_t pid, const std::string &binary_name) {
    std::ifstream maps_file("/proc/" + std::to_string(pid) + "/maps");

    std::string line;
    while (std::getline(maps_file, line)) {
        // Just find the first line
        if (line.find("test") != std::string::npos) {
            std::string result;
            int i = 0;
            while (line[i] != '-') {
                result.push_back(line[i]);
                ++i;
            }
            return std::stoll(result, nullptr, 16); 
        }
    }

    return -1; // not found
}

template <typename T>
std::pair<T, int64_t> initialize_debug_session(int pid, int64_t var_offset, int8_t var_size) {
    int64_t load_addr = get_load_address(pid, "test");
    if (load_addr < 0) {
        throw value_exception("Failed to get the load address of the symbol");
    }
    int64_t var_addr = var_offset + load_addr;

    long pres = ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[0]), var_addr);
    if (pres < 0) {
        perror("a");
        throw ptrace_exception("ptrace PTRACE_POKEUSER failed");
    }

    int64_t dr7 = (0b11 << 16) | 0b1;
    if (var_size == 4) {
        dr7 |= (0b11 << 18);
    } else if (var_size == 8) {
        dr7 |= (0b10 << 18);
    } else {
        throw value_exception("Failed to get the load address of the symbol");
    }

    pres = ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[7]), dr7);
    if (pres < 0) {
        throw ptrace_exception("ptrace PTRACE_POKEUSER failed");
    }

    T val = read_var<T>(pid, var_addr);

    pres = ptrace(PTRACE_CONT, pid, 0, 0);
    if (pres < 0) {
        throw ptrace_exception("ptrace PTRACE_CONT failed");
    }
    return std::pair(val, var_addr);
}

// Debug registers "trigger" just before the specified op.
// So, I single-step to see the result of this op (specifically,
// whether it modified the value or not).
template <typename T>
T handle_debug_reg_trigger(int pid, int64_t var_addr, T prev_val, std::string symbol_name) {
    int wstatus;
    long pres;

    pres = ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    if (pres < 0) {
        throw ptrace_exception("ptrace PTRACE_SINGLESTEP failed");
    }
    
    waitpid(pid, &wstatus, 0);
    if (WIFSTOPPED(wstatus)) {
        T val = read_var<T>(pid, var_addr);
        if (val == prev_val) {
            std::cout << '<' << symbol_name << ">   read    " << val << '\n';
        } else {
            std::cout << '<' << symbol_name << ">   write   " << prev_val << " -> " << val << '\n';
        }

        pres = ptrace(PTRACE_CONT, pid, 0, 0);
        if (pres < 0) {
            throw ptrace_exception("ptrace PTRACE_CONT failed");
        }
        return val;
    } else {
        throw ptrace_exception("Traced program is not stopped");
    }
}

template <typename T>
int trace_loop(int pid, int64_t var_offset, int8_t var_size, std::string symbol_name) {
    bool is_first = true;
    T val;
    int64_t var_addr;
    for (;;) {
        int wstatus;
        waitpid(pid, &wstatus, 0);

        if (WIFSTOPPED(wstatus)) {
            try {
                 if (WSTOPSIG(wstatus) == SIGTRAP) {
                    if (is_first) {
                        std::pair<T, int64_t> res = initialize_debug_session<T>(pid, var_offset, var_size);
                        val = res.first;
                        var_addr = res.second;
                        is_first = false;
                    } else {
                        val = handle_debug_reg_trigger<T>(pid, var_addr, val, symbol_name);   
                    }
                } else {
                    std::cerr << "Unexpected ptrace stop status\n";
                    return 1;
                }
            } catch (ptrace_exception& pe) {
                std::cerr << pe.what() << '\n';
                return 1;
            }
        } else if (WIFEXITED(wstatus)) {
            int code = WEXITSTATUS(wstatus);
            if (code != 0) {
                std::cerr << "Tracee execution failed\n";
            }
            return code;
        }
    }
}

int gwatch_main(int argc, char *argv[]) {
    if (argc < 5) {
        std::cout << "Usage: ./gwatch --var <symbol> --exec <path> [-- arg1 ... argN]\n";
        return 1;
    }

    bool exec_found = false;
    bool var_found = false;
    int params_idx = -1;
    std::string exec;
    std::string var;
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--var") {
            var_found = true;
        } else if (arg == "--exec") {
            exec_found = true;
        } else if (arg == "--") {
            params_idx = i;
            break;
        } else if (exec_found) {
            exec = arg;
            exec_found = false;
        } else if (var_found) {
            var = arg;
            var_found = false;
        }
    }
    if (exec.empty() || var.empty()) {
        std::cout << "Usage: ./gwatch --var <symbol> --exec <path> [-- arg1 ... argN]\n";
        return 1;
    }

    std::vector<char*> exec_argv { const_cast<char*>(exec.c_str()) };
    if (params_idx != -1) {
        for (int i = params_idx; i < argc; ++i) {
            exec_argv.push_back(argv[i]);
        }
    }
    exec_argv.push_back(nullptr);

    std::pair var_data = get_variable_virt_addr_and_size(exec, var);
    if (var_data.second == -1) {
        return 1;
    }

    int pid = fork();
    if (pid < 0) {
        std::cerr << "Fork failed\n";
        return 1;
    } else if (pid == 0) {
        // Child process
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execv(exec.c_str(), exec_argv.data());
    } else {
        // Parent process
        int res;
        if (var_data.second == 4) {
            res = trace_loop<int32_t>(pid, var_data.first, var_data.second, var);
        } else {
            res = trace_loop<int64_t>(pid, var_data.first, var_data.second, var);
        }

        return res;
    }

    return 0;
}