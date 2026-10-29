#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>
#include <netdb.h>
#include <link.h>
#include <termios.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <spawn.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

static atomic_ulong progress;
static atomic_int running = 1;
static int block_fds[2], block_active, block_ok;
static pthread_t blocker;
static pthread_t busy_fork_threads[2];
static unsigned busy_fork_count;
static int busy_fork_active;
static atomic_int busy_fork_running, busy_fork_generation;
static atomic_ulong busy_fork_completed, busy_fork_marked, busy_fork_denied, busy_fork_allowed, busy_fork_errors;
static atomic_ulong busy_worker_completed[2], busy_worker_marked[2];
static const char *secret_path;
static int null_argv_image;
static void *protected_mapping=MAP_FAILED;
static size_t protected_mapping_length;
static char *saved_home, *saved_path, *saved_ca;
static int initial_flags[3];
static struct stat initial_streams[3], initial_cwd;
static int terminal_present;
static struct termios initial_terminal;
static pid_t initial_foreground;
static unsigned short port, dns_port;
static struct sockaddr_in cached_alias;
static struct sockaddr_in second_alias;
static int has_cached_alias, cached_alias_native_peer;
static int stream = -1;
static int preopened = -1, idle_stream = -1;
static int existing_request[2], existing_reply[2];
static pid_t existing_child;
static sigset_t initial_signals;
static volatile sig_atomic_t signal_count;
static int child_debugger_opt_in;
static int crash_report_fd=-1;
static void diagnostic_crash(int signal,siginfo_t *info,void *context){
    uintptr_t instruction=0,stack=0,frame=0;
#if defined(__x86_64__)
    instruction=(uintptr_t)((ucontext_t*)context)->uc_mcontext.gregs[REG_RIP];
    stack=(uintptr_t)((ucontext_t*)context)->uc_mcontext.gregs[REG_RSP];
    frame=(uintptr_t)((ucontext_t*)context)->uc_mcontext.gregs[REG_RBP];
#elif defined(__aarch64__)
    instruction=(uintptr_t)((ucontext_t*)context)->uc_mcontext.pc;
    stack=(uintptr_t)((ucontext_t*)context)->uc_mcontext.sp;
    frame=(uintptr_t)((ucontext_t*)context)->uc_mcontext.regs[29];
#else
    (void)context;
#endif
    uintptr_t record[6]={(uintptr_t)getpid(),(uintptr_t)signal,instruction,(uintptr_t)info->si_addr,stack,frame};
    ssize_t size;do{size=syscall(SYS_write,crash_report_fd,record,sizeof(record));}while(size<0 && errno==EINTR);
    if(size==(ssize_t)sizeof(record)){
        /* PR_SET_PTRACER is not inherited by fork. Only this opt-in disposable
           crashing child permits the harness debugger, without host changes. */
        syscall(SYS_prctl,PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
        syscall(SYS_kill,getpid(),SIGSTOP);
    }
}
static void application_signal(int signal){(void)signal;signal_count++;}
static void application_fork_child(void){
    if(child_debugger_opt_in)syscall(SYS_prctl,PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
    sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGUSR2);sigprocmask(SIG_BLOCK,&mask,NULL);sigemptyset(&initial_signals);sigprocmask(SIG_BLOCK,NULL,&initial_signals);
}

static void *sdk_handle;
static int find_sdk(struct dl_phdr_info *info,size_t size,void *unused){
    (void)size;(void)unused;if(!info->dlpi_name || !*info->dlpi_name)return 0;
    void *handle=dlopen(info->dlpi_name,RTLD_LAZY|RTLD_NOLOAD);if(!handle)return 0;
    if(dlsym(handle,"hh_agent_abi_version") && dlsym(handle,"hh_agent_resolve_name")){sdk_handle=handle;return 1;}
    dlclose(handle);return 0;
}
static int cache_issued_address(const char *hostname,struct sockaddr_in *destination){
    if(!sdk_handle)dl_iterate_phdr(find_sdk,NULL);
    if(!sdk_handle)return 0;
    typedef int (*resolve_fn)(const char*,unsigned,unsigned*,unsigned char*,size_t,size_t*);
    resolve_fn resolve=(resolve_fn)dlsym(sdk_handle,"hh_agent_resolve_name");
    unsigned family=0;unsigned char bytes[16]={0};size_t written=0;
    if(!resolve || resolve(hostname,4,&family,bytes,sizeof(bytes),&written)!=0 || family!=4 || written!=4)return 0;
    memset(destination,0,sizeof(*destination));destination->sin_family=AF_INET;destination->sin_port=htons(port);memcpy(&destination->sin_addr,bytes,4);
    return bytes[0]==198 && (bytes[1]==18 || bytes[1]==19) && destination->sin_addr.s_addr!=htonl(0xc6124d09);
}
static int cache_issued_name(void){
    if(!cache_issued_address("localhost",&cached_alias))return 0;
    has_cached_alias=1;
    typedef void (*collision_fn)(unsigned);
    collision_fn collision=(collision_fn)dlsym(RTLD_DEFAULT,"hh_fixture_set_issued_address");
    if(!collision)return 0;
    collision(cached_alias.sin_addr.s_addr);
    return 1;
}
static int cache_fake_name(void){
    if(dns_port==0)return 0;
    static const unsigned char query[]={0x11,0x22,1,0,0,1,0,0,0,0,0,0,9,'l','o','c','a','l','h','o','s','t',0,0,1,0,1};
    int fd=socket(AF_INET,SOCK_DGRAM,0);if(fd<0)return 0;
    struct timeval timeout={.tv_sec=5,.tv_usec=0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    struct sockaddr_in server={.sin_family=AF_INET,.sin_port=htons(dns_port),.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    unsigned char response[512];
    int valid=sendto(fd,query,sizeof(query),0,(struct sockaddr*)&server,sizeof(server))==(ssize_t)sizeof(query);
    ssize_t size=valid?recvfrom(fd,response,sizeof(response),0,NULL,NULL):-1;close(fd);
    if(size<(ssize_t)(sizeof(query)+16) || memcmp(response,query,2)!=0 || !(response[2]&0x80) || memcmp(response+size-4,"\xc6\x12\x4d\x09",4)!=0)return 0;
    struct addrinfo hints={.ai_family=AF_INET,.ai_socktype=SOCK_STREAM},*answer=NULL;
    char service[16];snprintf(service,sizeof(service),"%u",port);
    if(getaddrinfo("localhost",service,&hints,&answer)!=0 || !answer)return 0;
    memcpy(&cached_alias,answer->ai_addr,sizeof(cached_alias));freeaddrinfo(answer);has_cached_alias=1;
    return cached_alias.sin_addr.s_addr==htonl(0xc6124d09);
}
static int connect_cached_alias(int nonblocking){
    if(!has_cached_alias)return 0;
    int fd=socket(AF_INET,SOCK_STREAM|(nonblocking?SOCK_NONBLOCK:0),0);if(fd<0)return 0;
    struct timeval timeout={.tv_sec=5,.tv_usec=0};setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    int connected=connect(fd,(struct sockaddr*)&cached_alias,sizeof(cached_alias));
    int valid=connected==0;
    if(!valid && nonblocking && errno==EINPROGRESS){
        struct pollfd poller={.fd=fd,.events=POLLOUT};int error=0;socklen_t error_size=sizeof(error);
        valid=poll(&poller,1,5000)==1 && getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&error_size)==0 && error==0;
    }
    valid=valid && ((fcntl(fd,F_GETFL)&O_NONBLOCK)!=0)==nonblocking;
    struct sockaddr_in peer;socklen_t peer_size=sizeof(peer);cached_alias_native_peer=0;
    if(valid && getpeername(fd,(struct sockaddr*)&peer,&peer_size)==0)cached_alias_native_peer=peer.sin_family==AF_INET && peer.sin_addr.s_addr==htonl(INADDR_LOOPBACK) && peer.sin_port==htons(port);
    char out='F',in=0;
    struct pollfd reader={.fd=fd,.events=POLLIN};
    valid=valid && send(fd,&out,1,MSG_NOSIGNAL)==1 && poll(&reader,1,5000)==1 && recv(fd,&in,1,MSG_WAITALL)==1 && in==out;
    close(fd);return valid;
}
static int read_secret(void);
static int fork_cached_alias(int depth,int nonblocking){
    pid_t child=fork();if(child<0)return 33;
    if(child==0){
        if(depth>1)_exit(fork_cached_alias(depth-1,nonblocking));
        int native_read=read_secret();if(native_read!=0)_exit(native_read);
        _exit(connect_cached_alias(nonblocking) && cached_alias_native_peer?0:31);
    }
    int status=0;if(waitpid(child,&status,0)!=child)return 34;
    return WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);
}
static int fork_alias_collision(void){
    pid_t child=fork();if(child<0)return 33;
    if(child==0){
        struct addrinfo hints={.ai_family=AF_INET,.ai_socktype=SOCK_STREAM},*answer=NULL;
        char service[16];snprintf(service,sizeof(service),"%u",port);
        int status=getaddrinfo("different.test",service,&hints,&answer);
        if(answer)freeaddrinfo(answer);
        if(status!=EAI_FAIL)_exit(35);
        if(!connect_cached_alias(0) || !cached_alias_native_peer)_exit(36);
        _exit(read_secret()==0?0:37);
    }
    int status=0;if(waitpid(child,&status,0)!=child)return 34;
    return WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);
}
static void *worker(void *unused) {
    (void)unused;
    while (atomic_load(&running)) { atomic_fetch_add(&progress, 1); usleep(2000); }
    return NULL;
}
static void *busy_fork_worker(void *opaque){
    unsigned index=(unsigned)(uintptr_t)opaque;
    while(atomic_load(&busy_fork_running)){
        int generation=atomic_load(&busy_fork_generation);
        pid_t child=fork();
        if(child==0)_exit(read_secret());
        int status=0;pid_t waited=-1;
        if(child>0){do{waited=waitpid(child,&status,0);}while(waited<0 && errno==EINTR);}
        if(child<0 || waited!=child || !WIFEXITED(status))atomic_fetch_add(&busy_fork_errors,1);
        else if(WEXITSTATUS(status)!=0 && WEXITSTATUS(status)!=13)atomic_fetch_add(&busy_fork_errors,1);
        else if(generation){
            atomic_fetch_add(&busy_worker_marked[index],1);
            atomic_fetch_add(&busy_fork_marked,1);
            if(WEXITSTATUS(status)==13)atomic_fetch_add(&busy_fork_denied,1);
            else atomic_fetch_add(&busy_fork_allowed,1);
        }
        atomic_fetch_add(&busy_worker_completed[index],1);atomic_fetch_add(&busy_fork_completed,1);
    }
    return NULL;
}
static void busy_fork_stats(void){
    printf("{\"busy_completed\":%lu,\"busy_marked\":%lu,\"busy_denied\":%lu,\"busy_allowed\":%lu,\"busy_errors\":%lu,\"busy_workers\":%u,\"busy_worker_completed\":[",atomic_load(&busy_fork_completed),atomic_load(&busy_fork_marked),atomic_load(&busy_fork_denied),atomic_load(&busy_fork_allowed),atomic_load(&busy_fork_errors),busy_fork_count);
    for(unsigned i=0;i<busy_fork_count;i++)printf("%s%lu",i?",":"",atomic_load(&busy_worker_completed[i]));
    printf("],\"busy_worker_marked\":[");
    for(unsigned i=0;i<busy_fork_count;i++)printf("%s%lu",i?",":"",atomic_load(&busy_worker_marked[i]));
    puts("]}");
}
static void busy_fork_stop(void){
    atomic_store(&busy_fork_running,0);
    if(busy_fork_active){for(unsigned i=0;i<busy_fork_count;i++)pthread_join(busy_fork_threads[i],NULL);busy_fork_active=0;}
}
static int busy_fork_start(unsigned count){
    if(busy_fork_active)return 52;
    atomic_store(&busy_fork_completed,0);atomic_store(&busy_fork_marked,0);atomic_store(&busy_fork_denied,0);atomic_store(&busy_fork_allowed,0);atomic_store(&busy_fork_errors,0);atomic_store(&busy_fork_generation,0);atomic_store(&busy_fork_running,1);
    for(unsigned i=0;i<2;i++){atomic_store(&busy_worker_completed[i],0);atomic_store(&busy_worker_marked[i],0);}
    busy_fork_count=0;busy_fork_active=1;
    for(unsigned i=0;i<count;i++){
        if(pthread_create(&busy_fork_threads[i],NULL,busy_fork_worker,(void*)(uintptr_t)i)!=0){busy_fork_stop();return 53;}
        busy_fork_count++;
    }
    return 0;
}
static int write_byte(int fd,char byte){
    ssize_t result;
    do{result=write(fd,&byte,1);}while(result<0 && errno==EINTR);
    return result==1;
}
static void *blocked_read(void *unused) {
    (void)unused; char byte = 0;
    ssize_t result = read(block_fds[0], &byte, 1);
    block_ok = result == 1 && byte == 'B';
    return NULL;
}
static char *copy_env(const char *name) { const char *v=getenv(name); return v ? strdup(v) : NULL; }
static int same_env(const char *name, const char *old) {
    const char *now=getenv(name); return old ? now && strcmp(old,now)==0 : now==NULL;
}
static int connect_stream(void) {
    int fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0)return -1;
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(port)};
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(fd,(struct sockaddr*)&address,sizeof(address))!=0){close(fd);return -1;}
    return fd;
}
static int echo(int fd) {
    char out='E',in=0;
    if(fd<0 || send(fd,&out,1,MSG_NOSIGNAL)!=1)return 0;
    struct pollfd poller={.fd=fd,.events=POLLIN};
    return poll(&poller,1,5000)==1 && recv(fd,&in,1,MSG_WAITALL)==1 && in==out;
}
static int connect_preopened(int fd) {
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(port)};
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    int result=connect(fd,(struct sockaddr*)&address,sizeof(address));
    if(result!=0){
        if(errno!=EINPROGRESS)return 0;
        struct pollfd poller={.fd=fd,.events=POLLOUT};
        if(poll(&poller,1,5000)!=1)return 0;
        int error=0;socklen_t size=sizeof(error);
        if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)!=0 || error!=0)return 0;
    }
    return echo(fd) && (fcntl(fd,F_GETFL)&O_NONBLOCK)!=0;
}
static int read_path(const char *path) {
    int fd=open(path,O_RDONLY); if(fd<0)return errno==EACCES ? 13 : 20;
    char byte=0; ssize_t n=read(fd,&byte,1); close(fd); return n==1 && byte=='S' ? 0 : 21;
}
static int read_secret(void){return read_path(secret_path);}
/* Exercise the libc allocator's cold-thread arena growth, including its
   anonymous PROT_NONE-to-RW mprotect path. No application-specific allocator. */
static void *allocator_growth_worker(void *result){
    int valid=1;void *blocks[64]={0};
    for(unsigned round=0;round<3 && valid==1;round++){
        for(unsigned i=0;i<64;i++){
            errno=0;blocks[i]=malloc(65536);if(!blocks[i]){valid=errno?-errno:-1001;break;}
            memset(blocks[i],(int)(i+round),65536);
        }
        for(unsigned i=0;i<64;i++)if(blocks[i]){
            unsigned char expected=(unsigned char)(i+round);
            if(((unsigned char*)blocks[i])[0]!=expected || ((unsigned char*)blocks[i])[65535]!=expected)valid=-1002;
            free(blocks[i]);blocks[i]=NULL;
        }
    }
    *(int*)result=valid;return NULL;
}
static void allocator_growth(void){
    pthread_t threads[8];int results[8]={0},create_error=0,join_error=0;unsigned count=0;
    for(;count<8;count++){create_error=pthread_create(&threads[count],NULL,allocator_growth_worker,&results[count]);if(create_error)break;}
    int valid=count==8;
    for(unsigned i=0;i<count;i++){int error=pthread_join(threads[i],NULL);if(error)join_error=error;if(error || results[i]!=1)valid=0;}
    printf("{\"allocator_growth_preserved\":%s,\"allocator_created_threads\":%u,\"allocator_create_error\":%d,\"allocator_join_error\":%d,\"allocator_worker_results\":[",valid?"true":"false",count,create_error,join_error);
    for(unsigned i=0;i<8;i++)printf("%s%d",i?",":"",results[i]);
    printf("]}\n");
}
/* A live proc seq_file is not a stable byte string. Independent pread byte
   offsets on one shared descriptor can restart traversal after VMAs change.
   Compare it with one serialized sequential cursor, using only raw-map data. */
struct map_cursor_probe { int fd,serialized; atomic_ulong malformed,protect_errors; atomic_int stop; pthread_mutex_t lock; };
static struct map_cursor_probe application_churn;
static pthread_t application_churn_threads[2];
static unsigned application_churn_count;
static void *map_cursor_churn(void *context){
    struct map_cursor_probe *probe=context;
    while(!atomic_load(&probe->stop)){
        void *mapping=mmap(NULL,65536,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(mapping!=MAP_FAILED){if(mprotect(mapping,65536,PROT_READ|PROT_WRITE)==0)((volatile char*)mapping)[0]=1;else atomic_fetch_add(&probe->protect_errors,1);munmap(mapping,65536);}
    }
    return NULL;
}
static int map_cursor_scan(struct map_cursor_probe *probe){
    char bytes[1024],header[96];size_t used=0;off_t offset=0;int malformed=0;
    if(probe->serialized){pthread_mutex_lock(&probe->lock);if(lseek(probe->fd,0,SEEK_SET)<0)malformed=1;}
    while(!malformed){
        ssize_t count=probe->serialized?read(probe->fd,bytes,sizeof(bytes)):pread(probe->fd,bytes,sizeof(bytes),offset);
        if(count<0){if(errno==EINTR)continue;malformed=1;break;}
        if(count==0){if(used)malformed=1;break;}
        offset+=count;
        for(ssize_t i=0;i<count;i++){
            if(bytes[i]=='\n'){
                header[used]=0;unsigned long low=0,high=0;
                if(sscanf(header,"%lx-%lx",&low,&high)!=2 || low>=high){malformed=1;break;}
                used=0;
            }else if(used<sizeof(header)-1)header[used++]=bytes[i];
        }
    }
    if(probe->serialized)pthread_mutex_unlock(&probe->lock);
    return malformed;
}
static void *map_cursor_reader(void *context){
    struct map_cursor_probe *probe=context;
    for(unsigned i=0;i<100;i++)if(map_cursor_scan(probe))atomic_fetch_add(&probe->malformed,1);
    return NULL;
}
static int map_cursor_oracle(void){
    unsigned long counts[2]={0};
    for(int serialized=0;serialized<2;serialized++){
        struct map_cursor_probe probe={.fd=open("/proc/self/maps",O_RDONLY|O_CLOEXEC),.serialized=serialized,.lock=PTHREAD_MUTEX_INITIALIZER};
        if(probe.fd<0)return 64;
        pthread_t churn[2],readers[8];
        for(unsigned i=0;i<2;i++)if(pthread_create(&churn[i],NULL,map_cursor_churn,&probe)!=0)return 65;
        for(unsigned i=0;i<8;i++)if(pthread_create(&readers[i],NULL,map_cursor_reader,&probe)!=0)return 66;
        for(unsigned i=0;i<8;i++)if(pthread_join(readers[i],NULL)!=0)return 67;
        atomic_store(&probe.stop,1);
        for(unsigned i=0;i<2;i++)if(pthread_join(churn[i],NULL)!=0)return 68;
        counts[serialized]=atomic_load(&probe.malformed);close(probe.fd);pthread_mutex_destroy(&probe.lock);
    }
    printf("{\"shared_pread_malformed_scans\":%lu,\"serialized_cursor_malformed_scans\":%lu}\n",counts[0],counts[1]);
    /* A scheduler may not expose the old cursor race on every host. Only the
       corrected sequential path is a required zero-error invariant. */
    return counts[1]==0?0:69;
}
static int prepare_mapping(void){
    if(protected_mapping!=MAP_FAILED)return 0;
    int fd=open(secret_path,O_RDONLY);if(fd<0)return errno;
    protected_mapping_length=4096;
    protected_mapping=mmap(NULL,protected_mapping_length,PROT_NONE,MAP_PRIVATE,fd,0);
    int saved=errno;close(fd);return protected_mapping==MAP_FAILED?saved:0;
}
static int probe_mapping(void){
    if(protected_mapping==MAP_FAILED)return 55;
    errno=0;if(mprotect(protected_mapping,protected_mapping_length,PROT_READ)!=0)return errno;
    int result=*(volatile unsigned char*)protected_mapping=='S'?0:56;
    if(mprotect(protected_mapping,protected_mapping_length,PROT_NONE)!=0)return 57;
    return result;
}
static void probe_mapping_pressure(void){
    struct rlimit original,limited;int fillers[128],count=0,pressure=0,result=58;
    if(getrlimit(RLIMIT_NOFILE,&original)!=0){printf("{\"mapping_result\":58,\"fd_pressure\":false}\n");return;}
    limited=original;if(limited.rlim_cur>64)limited.rlim_cur=64;
    if(setrlimit(RLIMIT_NOFILE,&limited)==0){
        while(count<128){int fd=open("/dev/null",O_RDONLY|O_CLOEXEC);if(fd<0){pressure=errno==EMFILE;break;}fillers[count++]=fd;}
        result=probe_mapping();
        for(int i=0;i<count;i++)close(fillers[i]);
        if(setrlimit(RLIMIT_NOFILE,&original)!=0)result=59;
    }
    printf("{\"mapping_result\":%d,\"fd_pressure\":%s}\n",result,pressure?"true":"false");
}
struct connect_boundaries{int codes[9];};
static void probe_connect_boundaries(struct connect_boundaries *values){
    struct sockaddr_in good={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    unsigned char unaligned[sizeof(good)+1];memcpy(unaligned+1,&good,sizeof(good));
    void *inaccessible=mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    const struct sockaddr *addresses[]={ (void*)1,(void*)1,(void*)1,(void*)1,inaccessible,inaccessible,(void*)(unaligned+1),(void*)(unaligned+1),NULL };
    socklen_t lengths[]={0,0,1,sizeof(good),sizeof(good),sizeof(good),sizeof(good),sizeof(good)-1,sizeof(good)};
    for(unsigned i=0;i<9;i++){
        int fd=(i==0 || i==5)?-1:socket(AF_INET,SOCK_STREAM,0);
        errno=EDOM;int result=connect(fd,addresses[i],lengths[i]);values->codes[i]=result==0?0:errno;
        if(fd>=0)close(fd);
    }
    if(inaccessible!=MAP_FAILED)munmap(inaccessible,4096);
}
static void print_connect_boundaries(int in_child){
    struct connect_boundaries values={{0}};int status=0;
    if(in_child){
        int descriptors[2];if(pipe(descriptors)!=0)return;
        pid_t child=fork();
        if(child==0){
            close(descriptors[0]);probe_connect_boundaries(&values);
            ssize_t count;do{count=write(descriptors[1],&values,sizeof(values));}while(count<0 && errno==EINTR);
            _exit(count==(ssize_t)sizeof(values)?0:52);
        }
        close(descriptors[1]);
        ssize_t count;do{count=read(descriptors[0],&values,sizeof(values));}while(count<0 && errno==EINTR);
        close(descriptors[0]);
        int waited=0;
        if(child<0 || waitpid(child,&waited,0)!=child)status=53;
        else status=WIFEXITED(waited)?WEXITSTATUS(waited):128+WTERMSIG(waited);
        if(count!=(ssize_t)sizeof(values) && status==0)status=54;
    }else probe_connect_boundaries(&values);
    printf("{\"connect_boundary_child_result\":%d,\"connect_errno_vector\":[",status);
    for(unsigned i=0;i<9;i++)printf("%s%d",i?",":"",values.codes[i]);
    printf("]}\n");
}
static int read_other(void){
    char path[4096];int size=snprintf(path,sizeof(path),"%s.ordinary",secret_path);
    return size>0 && size<(int)sizeof(path)?read_path(path):22;
}
static void *thread_read(void *result){*(int*)result=read_secret();return NULL;}
static int signal_mask_stable(void){
    sigset_t now;sigemptyset(&now);if(sigprocmask(SIG_BLOCK,NULL,&now)!=0)return 0;
    for(int signal=1;signal<NSIG;signal++){if(sigismember(&now,signal)!=sigismember(&initial_signals,signal))return 0;}
    return 1;
}
static int count_entries(const char *path) {
    DIR *directory=opendir(path); if(!directory)return -1;
    int count=0;struct dirent *entry;
    while((entry=readdir(directory))!=NULL){if(entry->d_name[0]!='.')count++;}
    closedir(directory);return count;
}
static int native_mappings(void) {
    FILE *file=fopen("/proc/self/maps","r");if(!file)return -1;
    char line[4096];int count=0;
    while(fgets(line,sizeof(line),file)){
        char protection[5];unsigned long inode=0;
        if(sscanf(line,"%*s %4s %*s %*s %lu",protection,&inode)==2 && protection[2]=='x' && inode!=0)count++;
    }
    fclose(file);return count;
}
static void snapshot(void) {
    int stable=1; struct stat now;
    for(int fd=0;fd<3;fd++) {
        if(fstat(fd,&now)!=0 || now.st_dev!=initial_streams[fd].st_dev || now.st_ino!=initial_streams[fd].st_ino || fcntl(fd,F_GETFL)!=initial_flags[fd])stable=0;
    }
    if(stat(".",&now)!=0 || now.st_dev!=initial_cwd.st_dev || now.st_ino!=initial_cwd.st_ino)stable=0;
    int environment=same_env("HOME",saved_home)&&same_env("PATH",saved_path)&&same_env("SSL_CERT_FILE",saved_ca);
    struct termios terminal;
    int terminal_stable=!terminal_present || (tcgetattr(0,&terminal)==0 && tcgetpgrp(0)==initial_foreground && terminal.c_iflag==initial_terminal.c_iflag && terminal.c_oflag==initial_terminal.c_oflag && terminal.c_cflag==initial_terminal.c_cflag && terminal.c_lflag==initial_terminal.c_lflag && memcmp(terminal.c_cc,initial_terminal.c_cc,sizeof(terminal.c_cc))==0 && cfgetispeed(&terminal)==cfgetispeed(&initial_terminal) && cfgetospeed(&terminal)==cfgetospeed(&initial_terminal));
    printf("{\"pid\":%ld,\"progress\":%lu,\"stable_stdio_cwd\":%s,\"stable_environment\":%s,\"has_terminal\":%s,\"stable_terminal\":%s,\"fd_count\":%d,\"thread_count\":%d,\"native_mappings\":%d,\"null_argv_image\":%s}\n",(long)getpid(),atomic_load(&progress),stable?"true":"false",environment?"true":"false",terminal_present?"true":"false",terminal_stable?"true":"false",count_entries("/proc/self/fd"),count_entries("/proc/self/task"),native_mappings(),null_argv_image?"true":"false");
}
/* Invalid execution arguments must retain native error results and FD flags,
   and must never be dereferenced by metadata/policy hooks. These calls cannot
   replace the image; an unexpected replacement fails the harness protocol. */
static void exec_error_row(const char *name,int result,int error,int fd,int before,int *first){
    int after=fcntl(fd,F_GETFD);
    printf("%s{\"call\":\"%s\",\"result\":%d,\"errno\":%d,\"fd_flags_preserved\":%s}",*first?"":",",name,result,error,before==after?"true":"false");*first=0;
}
static void exec_fd_errors(const char *program){
    int fd=open("/proc/self/exe",O_PATH|O_CLOEXEC);if(fd<0){printf("{\"exec_setup_error\":%d}\n",errno);return;}
    int before=fcntl(fd,F_GETFD),first=1,result,error;
    char *next[]={(char*)program,NULL};
    void *none=mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(none==MAP_FAILED){close(fd);printf("{\"exec_setup_error\":%d}\n",errno);return;}
    printf("{\"exec_errors\":[");
#define EXEC_ERROR(name, expression) do { errno=0;result=(expression);error=errno;exec_error_row((name),result,error,fd,before,&first); } while(0)
    EXEC_ERROR("fexecve_invalid_fd",fexecve(-1,next,environ));
    EXEC_ERROR("execveat_invalid_flags",execveat(fd,"",next,environ,AT_EMPTY_PATH|0x40000000));
    EXEC_ERROR("execveat_bad_path",execveat(fd,(const char*)(uintptr_t)1,next,environ,AT_EMPTY_PATH));
    EXEC_ERROR("execveat_none_path",execveat(fd,none,next,environ,AT_EMPTY_PATH));
    EXEC_ERROR("fexecve_none_argv",fexecve(fd,(char *const*)none,environ));
    EXEC_ERROR("execveat_none_argv",execveat(fd,"",(char *const*)none,environ,AT_EMPTY_PATH));
    EXEC_ERROR("fexecve_none_envp",fexecve(fd,next,(char *const*)none));
    EXEC_ERROR("execveat_none_envp",execveat(fd,"",next,(char *const*)none,AT_EMPTY_PATH));
    char *bad_element[]={none,NULL};
    EXEC_ERROR("execveat_none_argv_element",execveat(fd,"",bad_element,environ,AT_EMPTY_PATH));
    const char *base=getenv("TMPDIR");if(!base)base=".";
    char directory[4096];int length=snprintf(directory,sizeof(directory),"%s/hh-exec-errors-XXXXXX",base);
    int cleanup=length>0 && (size_t)length<sizeof(directory) && mkdtemp(directory)!=NULL;
    if(cleanup){
        char script[4160],link[4160];snprintf(script,sizeof(script),"%s/script",directory);snprintf(link,sizeof(link),"%s/link",directory);
        int file=open(script,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0700);
        const char source[]="#!/bin/sh\nexit 37\n";
        if(file<0 || write(file,source,sizeof(source)-1)!=(ssize_t)sizeof(source)-1){cleanup=0;if(file>=0)close(file);}
        else {
            close(file);file=open(script,O_RDONLY|O_CLOEXEC);
            if(file<0)cleanup=0;else {EXEC_ERROR("fexecve_cloexec_script",fexecve(file,next,environ));cleanup=fcntl(file,F_GETFD)==FD_CLOEXEC && close(file)==0;}
        }
        int dir=open(directory,O_PATH|O_DIRECTORY|O_CLOEXEC);
        if(dir<0 || symlink(program,link)!=0){cleanup=0;if(dir>=0)close(dir);}
        else {EXEC_ERROR("execveat_nofollow",execveat(dir,"link",next,environ,AT_SYMLINK_NOFOLLOW));cleanup=fcntl(dir,F_GETFD)==FD_CLOEXEC && close(dir)==0 && cleanup;}
        if(unlink(script)!=0 || unlink(link)!=0 || rmdir(directory)!=0)cleanup=0;
    }
#undef EXEC_ERROR
    int unmapped=munmap(none,4096)==0,closed=close(fd)==0;
    printf("],\"temporary_resources_removed\":%s}\n",unmapped&&closed&&cleanup?"true":"false");
}
int main(int argc,char **argv) {
    /* Linux presents NULL exec argv as argc=1 with argv[0]="". Only this
       fixture restores its own command protocol from app-owned env sentinels;
       HyperHub must forward the raw NULL and never invent replacement argv. */
    char *fixture_argv[4];
    if(argc==1 && argv[0] && !*argv[0]){
        const char *image=getenv("HH_TEST_NULL_ARGV_IMAGE");
        const char *secret=getenv("HH_TEST_NULL_ARGV_SECRET");
        const char *service=getenv("HH_TEST_NULL_ARGV_PORT");
        const char *dns=getenv("HH_TEST_NULL_ARGV_DNS_PORT");
        if(!image || !*image || !secret || !service || !dns)return 83;
        fixture_argv[0]=strdup(image);fixture_argv[1]=strdup(secret);fixture_argv[2]=strdup(service);fixture_argv[3]=NULL;
        if(!fixture_argv[0] || !fixture_argv[1] || !fixture_argv[2])return 84;
        dns_port=(unsigned short)strtoul(dns,NULL,10);
        argv=fixture_argv;argc=3;null_argv_image=1;
    }
    if(argc<3)return 2;
    secret_path=argv[1];port=(unsigned short)strtoul(argv[2],NULL,10);
    if(argc>3 && strcmp(argv[3],"--map-cursor-oracle")==0)return map_cursor_oracle();
    if(argc>4 && strcmp(argv[3],"--startup-marker")==0){
        int marker=open(argv[4],O_WRONLY|O_CREAT|O_EXCL,0600);if(marker<0)return 49;
        int valid=write_byte(marker,'M');close(marker);return valid?37:50;
    }
    if(argc>4 && strcmp(argv[3],"--dns-port")==0)dns_port=(unsigned short)strtoul(argv[4],NULL,10);
    if(argc>3 && strcmp(argv[3],"--read-once")==0)return read_secret();
    if(argc>3 && strcmp(argv[3],"--environment-once")==0){
        const char *marker=getenv("HH_TEST_CHILD_MARKER");
        return marker && strcmp(marker,"retained")==0 && !getenv("HOME") && !getenv("SSL_CERT_FILE") && !getenv("HYPERHUB_SESSION_ID") ? 0 : 23;
    }
    /* Only this disposable fixture opts into same-user debugger access. The
       harness never changes host ptrace_scope or attaches any user program. */
    if(prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0)!=0)return 3;
    child_debugger_opt_in=getenv("HH_TEST_CHILD_DEBUGGER_OPT_IN")!=NULL;
    const char *crash_path=getenv("HH_TEST_CRASH_REPORT");
    if(crash_path){
        crash_report_fd=open(crash_path,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0600);if(crash_report_fd<0)return 47;
        struct sigaction crash={0};crash.sa_sigaction=diagnostic_crash;crash.sa_flags=SA_SIGINFO|SA_RESETHAND;sigemptyset(&crash.sa_mask);
        if(sigaction(SIGSEGV,&crash,NULL)!=0 || sigaction(SIGBUS,&crash,NULL)!=0 || sigaction(SIGILL,&crash,NULL)!=0 || sigaction(SIGABRT,&crash,NULL)!=0)return 48;
    }
    sigemptyset(&initial_signals);if(sigprocmask(SIG_BLOCK,NULL,&initial_signals)!=0)return 44;
    struct sigaction action={0};action.sa_handler=application_signal;action.sa_flags=SA_RESTART;sigemptyset(&action.sa_mask);if(sigaction(SIGUSR1,&action,NULL)!=0)return 45;
    if(pthread_atfork(NULL,NULL,application_fork_child)!=0)return 46;
    saved_home=copy_env("HOME");saved_path=copy_env("PATH");saved_ca=copy_env("SSL_CERT_FILE");
    for(int fd=0;fd<3;fd++){if(fstat(fd,&initial_streams[fd])!=0)return 4;initial_flags[fd]=fcntl(fd,F_GETFL);}
    if(stat(".",&initial_cwd)!=0)return 5;
    terminal_present=isatty(0);
    if(terminal_present){if(tcgetattr(0,&initial_terminal)!=0)return 16;initial_foreground=tcgetpgrp(0);if(initial_foreground!=getpgrp())return 17;}
    stream=connect_stream();if(!echo(stream))return 6;
    preopened=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0);if(preopened<0)return 36;
    if(pipe(existing_request)!=0 || pipe(existing_reply)!=0)return 28;
    pthread_t thread;
    existing_child=fork();if(existing_child<0)return 29;
    if(existing_child==0){
        if(prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0)!=0)_exit(35);
        close(existing_request[1]);close(existing_reply[0]);
        if(preopened>=0){close(preopened);preopened=-1;}
        if(idle_stream>=0)close(idle_stream);
        close(stream);
        char request;
        while(read(existing_request[0],&request,1)==1){
            if(request=='Q')break;
            if(request=='A'){
                int result=cache_issued_name()?0:55;
                if(write(existing_reply[1],&result,sizeof(result))!=(ssize_t)sizeof(result))_exit(56);
                if(result==0 && write(existing_reply[1],&cached_alias,sizeof(cached_alias))!=(ssize_t)sizeof(cached_alias))_exit(57);
                continue;
            }
            if(request=='O'){
                pid_t self=getpid();if(write(existing_reply[1],&self,sizeof(self))!=(ssize_t)sizeof(self))_exit(38);
                if(read(existing_request[0],&request,1)!=1 || request!='G')_exit(39);
                close(existing_request[0]);close(existing_reply[1]);existing_child=0;
                stream=connect_stream();if(!echo(stream))_exit(40);
                if(pthread_create(&thread,NULL,worker,NULL)!=0)_exit(41);
                goto interactive;
            }
            int result=read_secret();if(write(existing_reply[1],&result,sizeof(result))!=(ssize_t)sizeof(result))_exit(30);
        }
        _exit(0);
    }
    close(existing_request[0]);close(existing_reply[1]);
    if(pthread_create(&thread,NULL,worker,NULL)!=0)return 7;
interactive:
    setvbuf(stdout,NULL,_IOLBF,0);if(existing_child!=0)snapshot();
    char command[128];
    while(fgets(command,sizeof(command),stdin)) {
        if(strcmp(command,"read\n")==0)printf("{\"read_result\":%d}\n",read_secret());
        else if(strcmp(command,"allocator-growth\n")==0)allocator_growth();
        else if(strcmp(command,"exec-fd-errors\n")==0)exec_fd_errors(argv[0]);
        else if(strcmp(command,"start-map-churn\n")==0){
            if(application_churn_count)return 70;
            atomic_store(&application_churn.stop,0);atomic_store(&application_churn.protect_errors,0);
            int error=0;for(;application_churn_count<2;application_churn_count++){error=pthread_create(&application_churn_threads[application_churn_count],NULL,map_cursor_churn,&application_churn);if(error)break;}
            printf("{\"map_churn_threads\":%u,\"map_churn_create_error\":%d}\n",application_churn_count,error);
        }
        else if(strcmp(command,"stop-map-churn\n")==0){
            atomic_store(&application_churn.stop,1);
            for(unsigned i=0;i<application_churn_count;i++)if(pthread_join(application_churn_threads[i],NULL)!=0)return 71;
            application_churn_count=0;
            printf("{\"map_churn_mprotect_errors\":%lu}\n",atomic_load(&application_churn.protect_errors));
        }
        else if(strcmp(command,"prepare-mapping\n")==0)printf("{\"mapping_prepared\":%s}\n",prepare_mapping()==0?"true":"false");
        else if(strcmp(command,"probe-mapping\n")==0)printf("{\"mapping_result\":%d}\n",probe_mapping());
        else if(strcmp(command,"probe-mapping-pressure\n")==0)probe_mapping_pressure();
        else if(strcmp(command,"read-other\n")==0)printf("{\"other_read_result\":%d}\n",read_other());
        else if(strcmp(command,"socket\n")==0)printf("{\"old_stream\":%s}\n",echo(stream)?"true":"false");
        else if(strcmp(command,"new-socket\n")==0){int fd=connect_stream();int ok=echo(fd);if(fd>=0)close(fd);printf("{\"new_stream\":%s}\n",ok?"true":"false");}
        else if(strcmp(command,"snapshot\n")==0)snapshot();
        else if(strcmp(command,"exec-root\n")==0 || strcmp(command,"exec-root-path-nullargv\n")==0 || strcmp(command,"exec-root-execveat-nullargv\n")==0 || strcmp(command,"exec-root-fexecve\n")==0 || strcmp(command,"exec-root-execveat\n")==0 || strcmp(command,"exec-root-fexecve-opath\n")==0 || strcmp(command,"exec-root-execveat-relative\n")==0 || strcmp(command,"exec-root-fexecve-deleted\n")==0 || strcmp(command,"exec-root-execv\n")==0 || strcmp(command,"exec-root-execvp\n")==0 || strcmp(command,"exec-root-execl\n")==0 || strcmp(command,"exec-root-execlp\n")==0 || strcmp(command,"exec-root-execle\n")==0 || strcmp(command,"exec-root-execvpe\n")==0){
            /* The application closes its own old-image resources before exec.
               HyperHub must preserve the new image's active proxy stream until
               the application explicitly closes it after logical detach. */
            atomic_store(&running,0);if(pthread_join(thread,NULL)!=0)return 60;
            if(existing_child>0){
                if(!write_byte(existing_request[1],'Q'))return 61;
                close(existing_request[1]);close(existing_reply[0]);
                int status=0;if(waitpid(existing_child,&status,0)!=existing_child || !WIFEXITED(status) || WEXITSTATUS(status)!=0)return 62;
            }
            if(stream>=0)close(stream);
            if(preopened>=0)close(preopened);
            if(idle_stream>=0)close(idle_stream);
            char *next_argv[]={argv[0],(char *)secret_path,argv[2],NULL};
            int null_arguments=strcmp(command,"exec-root-path-nullargv\n")==0 || strcmp(command,"exec-root-execveat-nullargv\n")==0;
            if(null_arguments){
                char dns[16];snprintf(dns,sizeof(dns),"%u",(unsigned)dns_port);
                if(setenv("HH_TEST_NULL_ARGV_IMAGE",argv[0],1)!=0 || setenv("HH_TEST_NULL_ARGV_SECRET",secret_path,1)!=0 || setenv("HH_TEST_NULL_ARGV_PORT",argv[2],1)!=0 || setenv("HH_TEST_NULL_ARGV_DNS_PORT",dns,1)!=0)return 85;
            }
            char **volatile empty_arguments=NULL;
            const char *name=strrchr(argv[0],'/');name=name?name+1:argv[0];
            if(strcmp(command,"exec-root\n")==0)execve(argv[0],next_argv,environ);
            else if(strcmp(command,"exec-root-path-nullargv\n")==0)execve(argv[0],empty_arguments,environ);
            else if(strcmp(command,"exec-root-execveat-nullargv\n")==0){
                int executable=open("/proc/self/exe",O_PATH|O_CLOEXEC);if(executable<0)return 72;
                execveat(executable,"",empty_arguments,environ,AT_EMPTY_PATH);close(executable);
            }
            else if(strcmp(command,"exec-root-execv\n")==0)execv(argv[0],next_argv);
            else if(strcmp(command,"exec-root-execvp\n")==0)execvp(name,next_argv);
            else if(strcmp(command,"exec-root-execl\n")==0)execl(argv[0],argv[0],secret_path,argv[2],(char*)NULL);
            else if(strcmp(command,"exec-root-execlp\n")==0)execlp(name,argv[0],secret_path,argv[2],(char*)NULL);
            else if(strcmp(command,"exec-root-execle\n")==0)execle(argv[0],argv[0],secret_path,argv[2],(char*)NULL,environ);
            else if(strcmp(command,"exec-root-execvpe\n")==0)execvpe(name,next_argv,environ);
            else if(strcmp(command,"exec-root-execveat-relative\n")==0){
                char *directory=strdup(argv[0]);if(!directory)return 73;char *slash=strrchr(directory,'/');if(!slash)return 74;*slash=0;
                int executable=open(directory,O_PATH|O_DIRECTORY|O_CLOEXEC);if(executable<0)return 72;
                execveat(executable,slash+1,next_argv,environ,0);close(executable);free(directory);
            }
            else if(strcmp(command,"exec-root-fexecve-deleted\n")==0){
                const char *base=getenv("TMPDIR");if(!base)base=".";char file[4096];int length=snprintf(file,sizeof(file),"%s/hh-exec-image-XXXXXX",base);if(length<0 || (size_t)length>=sizeof(file))return 75;
                int output=mkostemp(file,O_CLOEXEC),input=open("/proc/self/exe",O_RDONLY|O_CLOEXEC);if(output<0 || input<0)return 76;
                char data[4096];ssize_t size;
                while((size=read(input,data,sizeof(data)))>0){ssize_t position=0;while(position<size){ssize_t wrote=write(output,data+position,(size_t)(size-position));if(wrote<0 && errno==EINTR)continue;if(wrote<=0)return 77;position+=wrote;}}
                if(size<0 || fchmod(output,0700)!=0 || close(input)!=0 || close(output)!=0)return 78;
                int executable=open(file,O_PATH|O_CLOEXEC);if(executable<0 || unlink(file)!=0)return 79;
                fexecve(executable,next_argv,environ);close(executable);
            }
            else {
                /* Open the actual running image, rather than assuming argv[0]
                   still names it. CLOEXEC is owned by the application and must
                   retain normal semantics through the exec-startup barrier. */
                int executable=open("/proc/self/exe",(strcmp(command,"exec-root-fexecve-opath\n")==0?O_PATH:O_RDONLY)|O_CLOEXEC);
                if(executable<0)return 72;
                if(strcmp(command,"exec-root-fexecve\n")==0 || strcmp(command,"exec-root-fexecve-opath\n")==0)fexecve(executable,next_argv,environ);
                else execveat(executable,"",next_argv,environ,AT_EMPTY_PATH);
                close(executable);
            }
            return 54;
        }
        else if(strcmp(command,"replace-stream-native\n")==0){
            int closed=stream>=0 && close(stream)==0;stream=connect_stream();
            printf("{\"old_stream_closed\":%s,\"replacement_stream\":%s}\n",closed?"true":"false",echo(stream)?"true":"false");
        }
        else if(strcmp(command,"busy-fork-start\n")==0 || strcmp(command,"busy-fork-start-two\n")==0){
            int result=busy_fork_start(strcmp(command,"busy-fork-start-two\n")==0?2:1);if(result)return result;
            busy_fork_stats();
        }
        else if(strcmp(command,"busy-fork-mark\n")==0){atomic_store(&busy_fork_generation,1);busy_fork_stats();}
        else if(strcmp(command,"busy-fork-stats\n")==0)busy_fork_stats();
        else if(strcmp(command,"busy-fork-pause\n")==0){atomic_store(&busy_fork_running,0);busy_fork_stats();}
        else if(strcmp(command,"busy-fork-stop\n")==0){busy_fork_stop();busy_fork_stats();}
        else if(strcmp(command,"signal-check\n")==0){sig_atomic_t before=signal_count;raise(SIGUSR1);printf("{\"signal_delivery_and_mask_preserved\":%s}\n",signal_count==before+1 && signal_mask_stable()?"true":"false");}
        else if(strcmp(command,"thread-read\n")==0){pthread_t reader;int result=47;if(pthread_create(&reader,NULL,thread_read,&result)!=0)return 48;pthread_join(reader,NULL);printf("{\"thread_read_result\":%d}\n",result);}
        else if(strcmp(command,"cache-fake-name\n")==0)printf("{\"cached_fake_alias\":%s}\n",cache_fake_name()?"true":"false");
        else if(strcmp(command,"cache-issued-name\n")==0)printf("{\"cached_fake_alias\":%s}\n",cache_issued_name()?"true":"false");
        else if(strcmp(command,"cache-second-issued-name\n")==0){
            int valid=cache_issued_address("127.0.0.1",&second_alias) && second_alias.sin_addr.s_addr!=cached_alias.sin_addr.s_addr;
            char first[INET_ADDRSTRLEN],second[INET_ADDRSTRLEN];
            if(!inet_ntop(AF_INET,&cached_alias.sin_addr,first,sizeof(first)) || !inet_ntop(AF_INET,&second_alias.sin_addr,second,sizeof(second)))return 51;
            printf("{\"distinct_second_issued_alias\":%s,\"first_alias\":\"%s\",\"second_alias\":\"%s\"}\n",valid?"true":"false",first,second);
        }
        else if(strcmp(command,"second-cached-connect\n")==0){
            struct sockaddr_in saved=cached_alias;cached_alias=second_alias;int valid=connect_cached_alias(0);cached_alias=saved;
            printf("{\"second_alias_stream\":%s}\n",valid?"true":"false");
        }
        else if(strcmp(command,"cached-connect\n")==0 || strcmp(command,"cached-connect-nonblocking\n")==0){int valid=connect_cached_alias(strcmp(command,"cached-connect-nonblocking\n")==0);printf("{\"cached_alias_stream\":%s,\"cached_alias_native_peer\":%s}\n",valid?"true":"false",cached_alias_native_peer?"true":"false");}
        else if(strcmp(command,"fork-cached-connect\n")==0 || strcmp(command,"fork-cached-connect-nonblocking\n")==0 || strcmp(command,"double-fork-cached-connect\n")==0 || strcmp(command,"double-fork-cached-connect-nonblocking\n")==0){
            int depth=strncmp(command,"double-",7)==0?2:1;
            printf("{\"cached_alias_child_result\":%d}\n",fork_cached_alias(depth,strstr(command,"nonblocking")!=NULL));
        }
        else if(strcmp(command,"fork-alias-collision\n")==0)printf("{\"alias_collision_child_result\":%d}\n",fork_alias_collision());
        else if(strcmp(command,"connect-boundaries\n")==0)print_connect_boundaries(0);
        else if(strcmp(command,"fork-connect-boundaries\n")==0)print_connect_boundaries(1);
        else if(strcmp(command,"preopened-socket\n")==0){
            int ok=connect_preopened(preopened);close(preopened);preopened=-1;
            printf("{\"preopened_nonblocking_preserved\":%s}\n",ok?"true":"false");
        }
        else if(strcmp(command,"idle-socket\n")==0){
            idle_stream=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0);
            printf("{\"idle_nonblocking_created\":%s}\n",idle_stream>=0 && (fcntl(idle_stream,F_GETFL)&O_NONBLOCK)!=0?"true":"false");
        }
        else if(strcmp(command,"idle-flags\n")==0)printf("{\"idle_native_nonblocking\":%s}\n",idle_stream>=0 && (fcntl(idle_stream,F_GETFL)&O_NONBLOCK)!=0?"true":"false");
        else if(strcmp(command,"idle-connect\n")==0){
            int ok=connect_preopened(idle_stream);close(idle_stream);idle_stream=-1;
            printf("{\"idle_nonblocking_preserved\":%s}\n",ok?"true":"false");
        }
        else if(strcmp(command,"orphan-root\n")==0){
            pid_t orphan=0;
            if(existing_child==0 || write(existing_request[1],"O",1)!=1 || read(existing_reply[0],&orphan,sizeof(orphan))!=(ssize_t)sizeof(orphan))return 42;
            printf("{\"orphan_pid\":%ld}\n",(long)orphan);fflush(stdout);
            if(write(existing_request[1],"G",1)!=1)return 43;
            _exit(37);
        }
        else if(strcmp(command,"existing-child-read\n")==0){
            int result=31;if(write(existing_request[1],"R",1)!=1 || read(existing_reply[0],&result,sizeof(result))!=(ssize_t)sizeof(result))return 32;
            printf("{\"existing_child_result\":%d}\n",result);
        }
        else if(strcmp(command,"producer-issued-address\n")==0){
            int result=58;
            if(existing_child<=0 || write(existing_request[1],"A",1)!=1 || read(existing_reply[0],&result,sizeof(result))!=(ssize_t)sizeof(result))return 59;
            if(result==0){
                if(read(existing_reply[0],&cached_alias,sizeof(cached_alias))!=(ssize_t)sizeof(cached_alias))return 60;
                has_cached_alias=1;
                typedef void (*collision_fn)(unsigned);collision_fn collision=(collision_fn)dlsym(RTLD_DEFAULT,"hh_fixture_set_issued_address");
                if(collision)collision(cached_alias.sin_addr.s_addr);
            }
            printf("{\"producer_result\":%d,\"producer_pid\":%ld,\"parent_did_not_resolve_name\":%s}\n",result,(long)existing_child,sdk_handle==NULL?"true":"false");
        }
        else if(strcmp(command,"producer-exit\n")==0){
            if(existing_child<=0 || write(existing_request[1],"Q",1)!=1)return 61;
            int status=0;pid_t child=existing_child;
            if(waitpid(child,&status,0)!=child)return 62;
            close(existing_request[1]);close(existing_reply[0]);existing_child=-1;
            printf("{\"producer_exit_code\":%d,\"producer_pid\":%ld}\n",WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status),(long)child);
        }
        else if(strcmp(command,"block\n")==0){
            if(block_active || pipe(block_fds)!=0)return 8;
            block_ok=0;block_active=1;if(pthread_create(&blocker,NULL,blocked_read,NULL)!=0)return 9;
            usleep(20000);puts("{\"blocked\":true}");
        }
        else if(strcmp(command,"unblock\n")==0){
            if(!block_active)return 10;
            if(!write_byte(block_fds[1],'B'))return 11;
            pthread_join(blocker,NULL);close(block_fds[0]);close(block_fds[1]);block_active=0;
            printf("{\"blocked_original_preserved\":%s}\n",block_ok?"true":"false");
        }
        else if(strcmp(command,"fork-exit\n")==0){
            int ready[2];if(pipe2(ready,O_CLOEXEC)!=0){printf("{\"neutral_child_result\":72,\"neutral_fork_errno\":%d}\n",errno);continue;}
            pid_t child=fork();
            if(child<0){int error=errno;close(ready[0]);close(ready[1]);printf("{\"neutral_child_result\":72,\"neutral_fork_errno\":%d}\n",error);continue;}
            if(child==0){
                syscall(SYS_close,ready[0]);char marker='E';ssize_t sent;
                do{sent=syscall(SYS_write,ready[1],&marker,1);}while(sent<0 && errno==EINTR);
                syscall(SYS_close,ready[1]);_exit(sent==1?0:74);
            }
            close(ready[1]);char marker=0;ssize_t count;
            do{count=read(ready[0],&marker,1);}while(count<0 && errno==EINTR);
            close(ready[0]);
            printf("{\"neutral_child_ready_to_exit\":%s,\"neutral_child_pid\":%ld}\n",count==1 && marker=='E'?"true":"false",(long)child);
            int status=0;pid_t waited;do{waited=waitpid(child,&status,0);}while(waited<0 && errno==EINTR);
            int result=waited==child?(WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status)):73;
            printf("{\"neutral_child_result\":%d,\"neutral_fork_errno\":0}\n",result);
        }
        else if(strcmp(command,"fexecve-read\n")==0 || strcmp(command,"execveat-read\n")==0){
            pid_t child=fork();if(child<0)return 80;
            if(child==0){int executable=open("/proc/self/exe",O_PATH|O_CLOEXEC);if(executable<0)_exit(81);char *next[]={argv[0],argv[1],argv[2],"--read-once",NULL};if(strcmp(command,"fexecve-read\n")==0)fexecve(executable,next,environ);else execveat(executable,"",next,environ,AT_EMPTY_PATH);_exit(82);}
            int status=0;if(waitpid(child,&status,0)!=child)return 83;
            printf("{\"child_result\":%d}\n",WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status));
        }
        else if(strcmp(command,"fork-read\n")==0 || strcmp(command,"exec-read\n")==0){
            int execute=command[0]=='e';pid_t child=fork();if(child<0)return 12;
            if(child==0){if(!signal_mask_stable() || !sigismember(&initial_signals,SIGUSR2))_exit(49);if(execute){execl(argv[0],argv[0],secret_path,argv[2],"--read-once",NULL);_exit(22);} _exit(read_secret());}
            int status=0;if(waitpid(child,&status,0)!=child)return 14;
            printf("{\"child_result\":%d}\n",WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status));
        }
        else if(strcmp(command,"vfork-read\n")==0){
            pid_t child=vfork();if(child<0)return 50;
            if(child==0){execl(argv[0],argv[0],secret_path,argv[2],"--read-once",NULL);_exit(22);}
            int status=0;if(waitpid(child,&status,0)!=child)return 51;
            printf("{\"vfork_child_result\":%d}\n",WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status));
        }
        else if(strcmp(command,"exec-env\n")==0 || strcmp(command,"spawn-env\n")==0){
            char *child_argv[]={argv[0],argv[1],argv[2],"--environment-once",NULL};
            char *child_env[]={"HH_TEST_CHILD_MARKER=retained",NULL};
            pid_t child=0;
            if(command[0]=='e'){
                child=fork();if(child<0)return 24;
                if(child==0){execve(argv[0],child_argv,child_env);_exit(25);}
            }else if(posix_spawn(&child,argv[0],NULL,NULL,child_argv,child_env)!=0)return 26;
            int status=0;if(waitpid(child,&status,0)!=child)return 27;
            printf("{\"child_environment_result\":%d}\n",WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status));
        }
        else if(strcmp(command,"exit\n")==0)break;
        else return 15;
    }
    if(block_active){if(!write_byte(block_fds[1],'B'))return 11;pthread_join(blocker,NULL);close(block_fds[0]);close(block_fds[1]);}
    atomic_store(&application_churn.stop,1);for(unsigned i=0;i<application_churn_count;i++)pthread_join(application_churn_threads[i],NULL);
    busy_fork_stop();
    atomic_store(&running,0);pthread_join(thread,NULL);close(stream);
    if(existing_child>0){
        if(write(existing_request[1],"Q",1)!=1)return 33;
        close(existing_request[1]);close(existing_reply[0]);
        int child_status=0;if(waitpid(existing_child,&child_status,0)!=existing_child || !WIFEXITED(child_status) || WEXITSTATUS(child_status)!=0)return 34;
    }
    if(preopened>=0)close(preopened);
    if(idle_stream>=0)close(idle_stream);
    if(protected_mapping!=MAP_FAILED)munmap(protected_mapping,protected_mapping_length);
    free(saved_home);free(saved_path);free(saved_ca);
    return 37;
}
