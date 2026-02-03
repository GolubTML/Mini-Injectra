#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
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

static long remote_syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) 
{
    long ret;

    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;

    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n),
          "D"(a1),
          "S"(a2),
          "d"(a3),
          "r"(r10),
          "r"(r8),
          "r"(r9)
        : "rcx", "r11", "memory"
    );

    return ret;
}

void trampoline(void* arg)
{
    dlopen(arg, RTLD_NOW | RTLD_GLOBAL);
    return;
}

int main(int argc, char** argv)
{
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

    
    void* pthread_create_local = dlsym(RTLD_NEXT, "pthread_create");
    printf("local pthread_create base = %p\n", pthread_create_local);
    
    Dl_info info_pthread;
    dladdr(pthread_create_local, &info_pthread);

    const char* pthread_module_path = info_pthread.dli_fname;
    const char* pthread_module_name = strrchr(pthread_module_path, '/');
    pthread_module_name = pthread_module_name ? pthread_module_name + 1 : pthread_module_path;

    unsigned long local_pthread_module_base = find_module_name(getpid(), pthread_module_name);
    printf("-[libpthread] local base = 0x%lx\n", local_pthread_module_base);
    unsigned long targer_pthread_module_base = find_module_name(pid, pthread_module_name);
    printf("-[libpthread] target base = 0x%lx\n", targer_pthread_module_base);
    
    unsigned long pthread_create_offset = (unsigned long)pthread_create_local - local_pthread_module_base;
    printf("pthread_create offset = 0x%lx\n", pthread_create_offset);

    unsigned long pthread_create_remote = targer_pthread_module_base + pthread_create_offset;
    printf("remote pthread_create base = 0x%lx\n", pthread_create_remote);

    
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
    
#if defined(__x86_64__)
    regs.rax = 0;
    regs.rdi = 0;           // адресс
    regs.rsi = 0x1000;      // кол-во памяти мы хотим выделить
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.rcx = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8  = -1;
    regs.r9  = 0;

    regs.rsp &= ~0xF;
    regs.rsp -= 8;

    unsigned long fake_ret = saved.rip;
    process_vm_writev(pid, &(struct iovec){ &fake_ret, sizeof(fake_ret) }, 1, &(struct iovec){ (void*)regs.rsp, sizeof(fake_ret) }, 1, 0);
    
    regs.rip = mmap_remote; // прыжок

#endif
    
    if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_SETREGS");
        return 1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
    {
        perror("PTRACE_CONT");
        return 1;
    }

    waitpid(pid, &status, __WALL);

    if (WIFSIGNALED(status)) 
    {
        printf("[!] Target crashed by signal %d\n", WTERMSIG(status));
    }
    if (WIFSTOPPED(status)) 
    {
        printf("[*] Stopped by signal %d\n", WSTOPSIG(status));
    }


    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_GETREGS");
        return 1;
    }

    remote_mem = (void*)regs.rax;

    if ((long)regs.rax < 0) 
    {
        printf("[!] mmap failed: %ld\n", (long)regs.rax);
        return 1;
    }

    printf("[+] remote mmap = %p\n", remote_mem);

    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved) == -1)
    {
        perror("PTRACE_SETREGS");
        return 1;
    }

    // ну чтож, поехали использовать pthread_create
    /*
    Синтаксис:

        int pthread_create(
            pthread_t* thread,
            const pthread_attr_t* attr,
            void* (*start_routine)(void*),
            void* arg
        );

        Для начала, нужно получить адресс потока, и адресс пути к файлу
    */

    void* remote_thread_id = remote_mem + 0x200; // начало нашей ново выделенной памяти
    void* remote_path_lib = remote_mem + 0x80; // + 16кб, теперь запишем путь сюда
    void* trampoline_addr = remote_mem + 0x00; 

    const char* path_to_lib = "/mnt/hdd/C/MiniInjectra/payload.so";

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

    unsigned char trampoline_code[] = 
    {
        0x48, 0xC7, 0xC6, 0x02, 0x01, 0x00, 0x00,   // mov rsi, 0x102
        0x48, 0xB8,                                 // mov rax, imm64
        0,0,0,0,0,0,0,0,                            // dlopen addr
        0xFF, 0xD0,                                 // call rax
        0x48, 0x31, 0xC0,                           // xor rax, rax
        0xC3                                        // ret
    };

    *(uint64_t*)(trampoline_code + 10) = remote_dlopen;

    written = process_vm_writev(pid, &(struct iovec){ trampoline_code, sizeof(trampoline_code) }, 1, &(struct iovec){ trampoline_addr, sizeof(trampoline_code) }, 1, 0);

    if (written <= 0)
    {
        perror("process_vm_writev");
    }

    //а вот теперь pthread_create

#if defined(__x86_64__)
    regs.rdi = (unsigned long)remote_thread_id;
    regs.rsi = 0;
    regs.rdx = (unsigned long)trampoline_addr;
    regs.rcx = (unsigned long)remote_path_lib;

    regs.rsp &= ~0xF;
    regs.rsp -= 8;

    fake_ret = saved.rip;
    process_vm_writev(pid, &(struct iovec){ &fake_ret, sizeof(fake_ret) }, 1, &(struct iovec){ (void*)regs.rsp, sizeof(fake_ret) }, 1, 0);

    regs.rip = pthread_create_remote; // прыжок
#endif


    if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_SETREGS");
        return 1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
    {
        perror("PTRACE_CONT");
        return 1;
    }

    waitpid(pid, &status, __WALL);

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        perror("PTRACE_GETREGS");
        return 1;
    }

    printf("pthread_create return: %lld\n", regs.rax);

    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved) == -1)
    {
        perror("PTRACE_SETREGS");
        return 1;
    }

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