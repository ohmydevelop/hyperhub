#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>

static atomic_uint issued_collision;
void hh_fixture_set_issued_address(unsigned address){atomic_store(&issued_collision,address);}

/* This application-provided resolver models a local FAKE-IP resolver. It
   returns a valid libc-owned addrinfo allocation, so normal freeaddrinfo works.
   The managed getaddrinfo boundary must retain its hostname/address relation. */
int getaddrinfo(const char *node,const char *service,const struct addrinfo *hints,struct addrinfo **result){
    typedef int (*resolve_fn)(const char*,const char*,const struct addrinfo*,struct addrinfo**);
    resolve_fn original=(resolve_fn)dlsym(RTLD_NEXT,"getaddrinfo");
    if(!original)return EAI_SYSTEM;
    unsigned collision=atomic_load(&issued_collision);
    if(node && strcmp(node,"different.test")==0 && collision){
        int status=original("127.0.0.1",service,hints,result);
        if(status==0){for(struct addrinfo *item=*result;item;item=item->ai_next){if(item->ai_family==AF_INET)((struct sockaddr_in*)item->ai_addr)->sin_addr.s_addr=collision;}}
        return status;
    }
    if(!getenv("HH_TEST_OBSERVED_ALIAS") || !node || strcmp(node,"localhost")!=0)return original(node,service,hints,result);
    int status=original("127.0.0.1",service,hints,result);
    if(status==0){for(struct addrinfo *item=*result;item;item=item->ai_next){if(item->ai_family==AF_INET)((struct sockaddr_in*)item->ai_addr)->sin_addr.s_addr=htonl(0xc6124d09);}}
    return status;
}
/* An observed external resolver alias has a pre-existing native route. This
   connector models that route without changing host interfaces or routing. */
int connect(int fd,const struct sockaddr *address,socklen_t length){
    typedef int (*connect_fn)(int,const struct sockaddr*,socklen_t);
    connect_fn original=(connect_fn)dlsym(RTLD_NEXT,"connect");
    if(!original){errno=ENOSYS;return -1;}
    if(address && length>=sizeof(struct sockaddr_in) && address->sa_family==AF_INET){
        const struct sockaddr_in *input=(const struct sockaddr_in*)address;
        if(input->sin_addr.s_addr==htonl(0xc6124d09)){
            struct sockaddr_in native=*input;native.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
            return original(fd,(struct sockaddr*)&native,sizeof(native));
        }
        /* Synthetic SDK aliases have no application-native route. Fail them
           locally so the before-fix regression never sends external traffic. */
        unsigned ip=ntohl(input->sin_addr.s_addr);
        if((ip&0xfffe0000U)==0xc6120000U){errno=EHOSTUNREACH;return -1;}
    }
    return original(fd,address,length);
}
