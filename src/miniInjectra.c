#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/uio.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>


int find_module_by_addr(pid_t pid, unsigned long addr)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE* f = fopen(maps_path, "r");
    if (!f)
    {
        perror("fopen maps");
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), f))
    {
        unsigned long start, end;
        char perms[5];
        char path[256] = {0};

        int fields = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &start, &end, perms, path);

        if (addr >= start && addr < end)
        {
            printf("    RIP 0x%lx is inside:\n", addr);
            printf("    module: %s\n", fields == 4 ? path : "[anonymous]");
            printf("    range : 0x%lx - 0x%lx\n", start, end);
            printf("    offset: 0x%lx\n", addr - start);
            
            fclose(f);
            return 0;
        }
    }
    
    fclose(f);
    printf("[-] Address 0x%lx not found in maps\n", addr);
    return -1;
}

unsigned long find_module_name(pid_t pid, const char* name)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE* f = fopen(maps_path, "r");
    if (!f)
    {
        perror("fopen maps");
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), f))
    {
        unsigned long start, end;
        char path[256] = {0};

        int fields = sscanf(line, "%lx-%lx %*s %*s %*s %*s %255[^\n]", &start, &end, path);

        if (fields == 3 && strstr(path, name))
        {
            fclose(f);
            return start;
        }
    }
    
    fclose(f);
    return 0;
}

long remote_call(pid_t pid, unsigned long func, long a1, long a2, long a3, long a4, long a5, long a6)
{
    struct user_regs_struct regs, saved;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_GETREGS");
        return -1;
    }

    memcpy(&saved, &regs, sizeof(regs));
    
    regs.rdi = a1;
    regs.rsi = a2;
    regs.rdx = a3;
    regs.rcx = a4;
    regs.r8  = a5;
    regs.r9  = a6;
    
    regs.rsp &= ~0xF;
    regs.rsp -= 8;
    long ret_addr = 0;

    process_vm_writev(pid, &(struct iovec){ &ret_addr, 8 }, 1, &(struct iovec){ (void*)regs.rsp, 8 }, 1, 0);
    regs.rip = func;
    regs.rax = 0;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_SETREGS");
        return -1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
    {
        perror("PTRACE_CONT");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status, __WALL);

    while (!WIFSTOPPED(status))
    {
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
        {
            perror("PTRACE_CONT");
            return -1;
        }

        waitpid(pid, &status, __WALL);
    }

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_GETREGS");
        return -1;
    }

    long ret = regs.rax;

    if(ptrace(PTRACE_SETREGS, pid, NULL, &saved) == -1)
    {
        perror("PTRACE_SETREGS");
        return -1;
    }

    return ret;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("Usage: %s <pid> <path_to_lib>\n", argv[0]);
        return 1;
    }

    printf("Hello in MiniInjectra!\n");

    pid_t pid = atoi(argv[1]); 

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
        perror("PTRACE_ATTACED");
        return 1;
    }
    
    printf("Attached to PID (%d)\n", pid);
    
    int status = 0;
    waitpid(pid, &status, 0); // тут мы ждем остановки процесса
    
    if (WIFSTOPPED(status))
    {
        printf("PID process stopped. Signal - %d \n", WSTOPSIG(status));
    }
    else
    {
        printf("Unexpected wait status!\n");
        return 1;
    }

    struct user_regs_struct regs;
    
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        printf("PTRACE_GETREGS");
        return 1;
    }

#if defined(__x86_64__)
    printf("RIP = 0x%lx\n", (unsigned long) regs.rip);
    printf("RSP = 0x%lx\n", (unsigned long) regs.rsp);
    printf("RAX = 0x%lx\n", (unsigned long) regs.rax);
#elif defined(__i386__)
    printf("EIP = 0x%lx\n", (unsigned long) regs.eip);
    printf("ESP = 0x%lx\n", (unsigned long) regs.esp);
    printf("EAX = 0x%lx\n", (unsigned long) regs.eax);
#else
# error "Unsupported architecture"
#endif

#if defined(__x86_64__)
    unsigned long ip = regs.rip;
#elif defined(__i386__)
    unsigned long ip = regs.eip;
#endif

    void* dlopen_local = dlsym(RTLD_NEXT, "dlopen");
    printf("local dlopen base = %p\n", dlopen_local);

    Dl_info info_dlopen;
    dladdr(dlopen_local, &info_dlopen);

    const char* dl_module_path = info_dlopen.dli_fname;
    const char* dl_module_name = strrchr(dl_module_path, '/');
    dl_module_name = dl_module_name ? dl_module_name + 1 : dl_module_path;

    unsigned long local_dl_module_base = find_module_name(getpid(), dl_module_name);
    printf("-[libdl] local base = 0x%lx\n", local_dl_module_base);
    unsigned long targer_dl_module_base = find_module_name(pid, dl_module_name);
    printf("-[libdl] target base = 0x%lx\n", targer_dl_module_base);

    unsigned long dlopen_offset = (unsigned long)dlopen_local - local_dl_module_base;
    printf("dlopen offset = 0x%lx\n", dlopen_offset);
    
    unsigned long remote_dlopen = targer_dl_module_base + dlopen_offset;
    printf("remote dlopen base = 0x%lx\n", remote_dlopen);

    
    void* mmap_local = dlsym(RTLD_NEXT, "mmap");
    printf("local mmap base = %p\n", mmap_local);
    
    Dl_info info_mmap;
    dladdr(mmap_local, &info_mmap);

    const char* mmap_module_path = info_mmap.dli_fname;
    const char* mmap_module_name = strrchr(mmap_module_path, '/');
    mmap_module_name = mmap_module_name ? mmap_module_name + 1 : mmap_module_path;

    unsigned long local_mmap_module_base = find_module_name(getpid(), mmap_module_name);
    printf("-[libc] local base = 0x%lx\n", local_mmap_module_base);
    unsigned long targer_mmap_module_base = find_module_name(pid, mmap_module_name);
    printf("-[libc] target base = 0x%lx\n", targer_mmap_module_base);
    
    unsigned long mmap_offset = (unsigned long)mmap_local - local_mmap_module_base;
    printf("mmap offset = 0x%lx\n", mmap_offset);

    unsigned long mmap_remote = targer_mmap_module_base + mmap_offset;
    printf("remote mmap base = 0x%lx\n", mmap_remote);

    void* remote_mem = NULL;

    struct user_regs_struct saved = regs;
    
    long mmap_ret = remote_call(pid, mmap_remote, 0, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    remote_mem = (void*)mmap_ret;

    if ((long)mmap_ret < 0) 
    {
        printf("[!] mmap failed: %ld\n", mmap_ret);
        return 1;
    }

    printf("[+] remote mmap = %p\n", remote_mem);

    void* remote_path_lib = remote_mem + 0x80; // + 16кб, теперь запишем путь сюда

    if (access(argv[2], F_OK) != 0)
    {
        printf("[-] Library file '%s' does not exist!\n", argv[2]);
        return 1;
    }

    const char* path_to_lib = argv[2]; //"/mnt/hdd/C/MiniInjectra/payload.so";

    struct iovec local_iov = 
    {
        .iov_base = (void*)path_to_lib,
        .iov_len  = strlen(path_to_lib) + 1
    };

    struct iovec remote_iov =
    {
        .iov_base = (void*)remote_path_lib,
        .iov_len  = strlen(path_to_lib) + 1
    };
    
    ssize_t written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);

    if (written <= 0)
    {
        perror("process_vm_writev");
    }

    long handle = remote_call(pid, remote_dlopen, (unsigned long)remote_path_lib, RTLD_NOW | RTLD_GLOBAL, 0, 0, 0, 0);

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/tmp/injectra.sock");

    int connected = 0;

    for (int i = 0; i < 500; ++i)
    {
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0)
        {
            connected = 1;
            break;
        }
        
        usleep(100000);
    }

    if (!connected)
    {
        printf("[-] Failed to connect to payload socket!\n");
        return 1;
    }
    
    char input_buf[512] = {0};

    while (1)
    {
        printf("injectra> ");

        fflush(stdout);
        
        if (!fgets(input_buf, sizeof(input_buf), stdin))
        {
            break;
        }

        if (strcmp(input_buf, "exit\n") == 0)
        {
            break;
        }

        write(sock, input_buf, strlen(input_buf));

        char reply_buf[1024] = {0};
        ssize_t n = read(sock, reply_buf, sizeof(reply_buf) - 1);

        if (n > 0)
        {
            printf("%s", reply_buf);
        }
        else
        {
            printf("[-] Failed to read from payload socket!\n");
            return 1;
        }
    }

    /*write(sock, "ping\n", 5);

    char buffer[256] = {0};
    ssize_t n = read(sock, buffer, sizeof(buffer) - 1);

    if (n > 0)
    {
        buffer[n] = '\0';
        printf("Received from payload: %.*s\n", (int)n, buffer);
    }
    else 
    {
        printf("[-] Failed to read from payload socket!\n");
        return 1;
    }*/

    printf("Press any key..\n");
    getchar();

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
    {
        perror("(PTRACE DETACH)\n");
        return 1;
    }

    printf("Detach clearly!\n");

    return 0;
}