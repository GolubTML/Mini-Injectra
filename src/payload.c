#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>

#define SOCK_PATH "/tmp/injectra.sock"

typedef void* (*mono_get_root_domain_t)(void);
typedef void* (*mono_thread_attach_t)(void*);
typedef void* (*mono_domain_get_assemblies_t)(void*, int*);
typedef void* (*mono_assembly_get_image_t)(void*);
typedef const char* (*mono_image_get_name_t)(void*);

mono_get_root_domain_t mono_get_root_domain;
mono_thread_attach_t mono_thread_attach;
mono_domain_get_assemblies_t mono_domain_get_assemblies;
mono_assembly_get_image_t mono_assembly_get_image;
mono_image_get_name_t mono_image_get_name;

void init_assemblies()
{
    void* handle = dlopen(NULL, RTLD_NOW);

    mono_get_root_domain = (mono_get_root_domain_t)dlsym(handle, "mono_get_root_domain");
    mono_thread_attach = (mono_thread_attach_t)dlsym(handle, "mono_thread_attach");
    mono_domain_get_assemblies = (mono_domain_get_assemblies_t)dlsym(handle, "mono_domain_get_assemblies");
    mono_assembly_get_image = (mono_assembly_get_image_t)dlsym(handle, "mono_assembly_get_image");
    mono_image_get_name = (mono_image_get_name_t)dlsym(handle, "mono_image_get_name");
}

void list_assemblies(int client)
{
    void* domain = mono_get_root_domain();
    mono_thread_attach(domain);

    int size;

    void** assemblies = (void**)mono_domain_get_assemblies(domain, &size);

    for (int i = 0; i < size; ++i)
    {
        void* image = mono_assembly_get_image(assemblies[i]);
        const char* name = mono_image_get_name(image);

        write(client, name, strlen(name));
        write(client, "\n", 1);
    }
}

void handle_command(int client, const char* command)
{
    if (strncmp(command, "ping", 4) == 0)
    {
        write(client, "pong\n", 5);
    }
    else if (strncmp(command, "modules", 7) == 0)
    {
        FILE* f = fopen("/proc/self/maps", "r");
        char line[256];

        while (fgets(line, sizeof(line), f))
        {
            write(client, line, strlen(line));
        }

        write(client, "\n", 1);
        fclose(f);
    }
    else if (strncmp(command, "tryusemono", 10) == 0)
    {
        void* handle = dlopen(NULL, RTLD_NOW);

        if (!handle)
        {
            write(client, "Mono lib is not available\n", 27);
            return;
        }

        void* (*mono_thread_attach_fn)(void*) = dlsym(handle, "mono_thread_attach");

        char* error = dlerror();
        if (error != NULL)
        {
            write(client, "Error: ", 7);
            write(client, error, strlen(error));
            write(client, "\n", 1);

            return;
        }
        else
        {
            write(client, "mono_thread_attach_fn found\n", 29);
        }
        
        void* (*mono_get_root_domain_fn)(void) = dlsym(handle, "mono_get_root_domain");

        error = dlerror();
        if (error != NULL)
        {
            write(client, "Error: ", 7);
            write(client, error, strlen(error));
            write(client, "\n", 1);

            return;
        }
        else
        {
            write(client, "mono_get_root_domain_fn found\n", 31);
        }

        void* domain = mono_get_root_domain_fn();

        if(!domain)
        {
            write(client, "Failed to get root domain\n", 27);
            return;
        }
        else
        {
            write(client, "Got root domain\n", 17);
        }

        mono_thread_attach_fn(domain);


        write(client, "Mono ready\n", 11);
    }
    else if (strncmp(command, "assemblies", 10) == 0)
    {
        list_assemblies(client);
    }
    else 
    {
        write(client, "Unknown command\n", 16);
    }
}

void wait_for_mono()
{
    while (!mono_get_root_domain)
    {
        void* handle = dlopen(NULL, RTLD_NOW);
        mono_get_root_domain = (mono_get_root_domain_t)dlsym(handle, "mono_get_root_domain");

        mono_thread_attach = (mono_thread_attach_t)dlsym(handle, "mono_thread_attach");

        mono_domain_get_assemblies = (mono_domain_get_assemblies_t)dlsym(handle, "mono_domain_get_assemblies");

        mono_assembly_get_image = (mono_assembly_get_image_t)dlsym(handle, "mono_assembly_get_image");

        mono_image_get_name = (mono_image_get_name_t)dlsym(handle, "mono_image_get_name");

        if (mono_get_root_domain && mono_thread_attach && mono_domain_get_assemblies && mono_assembly_get_image && mono_image_get_name)
        {
            break;
        }
        
        sleep(1);
    }

    void* domain = mono_get_root_domain();

    while (!(domain = mono_get_root_domain()))
    {
        sleep(1);
    }
    
    mono_thread_attach(domain);
}

void* server_thread(void* arg)
{

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCK_PATH);
    
    unlink(SOCK_PATH);

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);

    printf("[Injectra Payload] Server started.\n");

    while(1)
    {
        int client = accept(server_fd, NULL, NULL);

        while (1)
        {
            char buffer[256];
            ssize_t n = read(client, buffer, sizeof(buffer) - 1);

            if (n <= 0)
            {
                break;
            }

            handle_command(client, buffer);
        }
        
        close(client);
    }
}

__attribute__((constructor))
void init() 
{
    write(2, "Injectra payload build: " __DATE__ " " __TIME__ "\n", 50);

    pthread_t t;
    pthread_create(&t, NULL, server_thread, NULL);

    pthread_detach(t);
}
