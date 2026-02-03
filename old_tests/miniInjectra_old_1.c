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

int addr_in_module(pid_t pid, unsigned long rip, const char* name)
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

        if (fields == 3 && rip >= start && rip < end && strstr(path, name))
        {
            fclose(f);
            return 1;
        }
    }
    
    fclose(f);
    return 0;
}

pid_t select_game_tid(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);

    DIR* d = opendir(path);
    if (!d)
    {
        perror("opendir task");
        return -1;
    }

    struct dirent* de;
    while ((de = readdir(d)))
    {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;

        printf("    TID %s\n", de->d_name);

        pid_t tid = atoi(de->d_name);

        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1)
            continue;

        int status = 0;
        waitpid(tid, &status, 0);

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, tid, NULL, &regs);

        if (addr_in_module(pid, regs.rip, "Terraria.bin.x86_64"))
        {
            closedir(d);
            return tid;
        }

        ptrace(PTRACE_DETACH, tid, NULL, NULL);
    }

    closedir(d);
    return -1;
}

int main(int argc, char** argv)
{
    printf("Hello in MiniInjectra!\n");

    pid_t pid = atoi(argv[1]); // получаем PID из строки

    
    /*if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
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
    }*/
    
    pid_t game_tid = select_game_tid(pid);

    if (game_tid == -1)
    {
        printf("Game threat not found");
        return 1;
    }

    printf("Game TID is: %d\n", game_tid);
    
    // тут мы должны получит регистры. Хм
    struct user_regs_struct regs;
    
    if (ptrace(PTRACE_GETREGS, game_tid, NULL, &regs) == -1)
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

    find_module_by_addr(pid, ip);

    void* dlopen_local = dlsym(RTLD_NEXT, "dlopen");
    printf("local dlopen base = %p\n", dlopen_local);
    void* dlerror_local = dlsym(RTLD_NEXT, "dlerror");


    Dl_info info;
    dladdr(dlopen_local, &info);

    const char* module_path = info.dli_fname;
    const char* module_name = strrchr(module_path, '/');
    module_name = module_name ? module_name + 1 : module_path;

    unsigned long local_module_base = find_module_name(getpid(), module_name);
    printf("libdl local base = 0x%lx\n", local_module_base);

    unsigned long targer_module_base = find_module_name(pid, module_name);
    printf("libdl target base = 0x%lx\n", targer_module_base);

    unsigned long dlopen_offset = (unsigned long)dlopen_local - local_module_base;
    printf("dlopen offset = 0x%lx\n", dlopen_offset);

    unsigned long dlerror_offset = (unsigned long)dlerror_local - local_module_base;
    
    unsigned long remote_dlopen = targer_module_base + dlopen_offset;
    printf("remote dlopen base = 0x%lx\n", remote_dlopen);
    
    unsigned long remote_dlerror = targer_module_base + dlerror_offset;

#if defined(__x86_64__)
    unsigned long remote_addr = regs.rsp - 0x400;
#elif defined(__i386__)
    unsigned long remote_addr = regs.esp - 0x400;
#endif

    // тест записи
    const char* test_msg = "/home/golub/.local/share/Steam/steamapps/common/Terraria/lib64/payload.so";

    struct iovec local_iov = 
    {
        .iov_base = (void*)test_msg,
        .iov_len  = strlen(test_msg) + 1
    };

    struct iovec remote_iov =
    {
        .iov_base = (void*)remote_addr,
        .iov_len  = strlen(test_msg) + 1
    };
    
    ssize_t written = process_vm_writev(game_tid, &local_iov, 1, &remote_iov, 1, 0);

    if (written <= 0)
    {
        perror("process_vm_writev");
    }

    // тест чтения

    char buffer[128] = {0};

    struct iovec local_read = 
    {
        .iov_base = buffer,
        .iov_len  = sizeof(buffer)
    };

    struct iovec remote_read =
    {
        .iov_base = (void*)remote_addr,
        .iov_len  = sizeof(buffer)
    };

    ssize_t read = process_vm_readv(game_tid, &local_read, 1, &remote_read, 1, 0);

    if (read <= 0)
    {
        perror("process_vm_readv");
    }
    else
    {
        printf("result back: %s\n", buffer);
    }

    struct user_regs_struct saved = regs; // пригодится

#if defined(__x86_64__)
    regs.rdi = remote_addr;
    regs.rsi = RTLD_NOW | RTLD_GLOBAL;

    regs.rsp &= ~0xF; // выравним вниз на 16 байт
    regs.rsp -= 8;

    unsigned long fake_ret = regs.rip;
    process_vm_writev(game_tid, &(struct iovec){ &fake_ret, sizeof(fake_ret) }, 1, &(struct iovec){ (void*)regs.rsp, sizeof(fake_ret) }, 1, 0);

    unsigned char int3 = 0xCC;
    process_vm_writev(
        game_tid,
        &(struct iovec){ &int3, 1 }, 1,
        &(struct iovec){ (void*)regs.rsp, 1 }, 1,
        0
    );


    regs.rip = remote_dlopen;

#elif defined(__i386__)
    regs.eip = remote_dlopen;
    regs.edi = remote_addr;
    regs.esi = RTLD_NOW | RTLD_GLOBAL;

    regs.esp &= ~0xF; // выравним вниз на 16 байт
    regs.esp -= 8;
    
    TODO: переделать
    
#endif

    if (ptrace(PTRACE_SETREGS, game_tid, NULL, &regs) == -1)
    {
        perror("PTRACE_SETREGS");
        return 1;
    }

    if (ptrace(PTRACE_CONT, game_tid, NULL, NULL) == -1)
    {
        perror("PTRACE_CONT");
        return 1;
    }

    int status = 0;
    waitpid(game_tid, &status, __WALL);

    if (!WIFSTOPPED(status))
    {
        printf("[-] Thread did not stop after CONT\n");
        return 1;
    }

    printf("[*] Thread stopped, signal = %d\n", WSTOPSIG(status));

    if (ptrace(PTRACE_GETREGS, game_tid, NULL, &regs) == -1)
    {
        perror("PTRACE_GETREGS");
        return 1;
    }

    if (regs.rax != 0)
    {
        printf("[+] DLOPEN sucess, handle = 0x%lx\n", regs.rax);
    }
    else
    {
        printf("[E] dlopen failed! handle = 0x%lx\n", regs.rax);
    }

    if (ptrace(PTRACE_SETREGS, game_tid, NULL, &saved) == -1)
    {
        perror("PTRACE_SETREGS");
        return 1;
    }

    /*struct user_regs_struct saved2 = regs;

    regs.rsp &= ~0xF;
    regs.rsp -= 8;

    fake_ret = saved.rip;
    process_vm_writev(
        pid,
        &(struct iovec){ &fake_ret, sizeof(fake_ret) }, 1,
        &(struct iovec){ (void*)regs.rsp, sizeof(fake_ret) }, 1,
        0
    );

    regs.rip = remote_dlerror;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    waitpid(pid, &status, 0);

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    unsigned long err_ptr = regs.rax;

    char errbuf[256] = {0};

    process_vm_readv(
        pid,
        &(struct iovec){ errbuf, sizeof(errbuf) }, 1,
        &(struct iovec){ (void*)err_ptr, sizeof(errbuf) }, 1,
        0
    );
    
    printf("[dlerror] %s\n", errbuf);

    ptrace(PTRACE_SETREGS, pid, NULL, &saved2);*/



    printf("Press any key..\n");
    getchar();

    if (ptrace(PTRACE_DETACH, game_tid, NULL, NULL) == -1)
    {
        perror("(PTRACE DETACH)\n");
        return 1;
    }

    printf("Detach clearly!\n");

    return 0;
}