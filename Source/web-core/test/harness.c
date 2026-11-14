#include <stdio.h>
#include <string.h>
#include <stdint.h>

int gs_abi_version(void);
int gs_header_hash(unsigned char *out, int cap);
int gs_test_address(char *out, int cap);
int gs_test_s1(char *out, int cap);
long long gs_checkpoint_height(void);
long long gs_restore_recent(void);


int main(void) {
    unsigned char hash[32];
    char address[128];
    memset(hash, 0, sizeof(hash));
    memset(address, 0, sizeof(address));
    int hv = gs_abi_version();
    int hn = gs_header_hash(hash, (int)sizeof(hash));
    int an = gs_test_address(address, (int)sizeof(address) - 1);
    printf("ABI=%d\nHEADER_HASH_LEN=%d\nHEADER_HASH=", hv, hn);
    for (int i = 0; i < hn; i++) printf("%02x", hash[i]);
    printf("\nADDRESS_LEN=%d\nADDRESS=%s\n", an, address);
    char s1[8192];
    memset(s1, 0, sizeof(s1));
    int sn = gs_test_s1(s1, (int)sizeof(s1));
    printf("S1_LEN=%d\nS1_PREFIX=%.20s\n", sn, s1);
    printf("CHECKPOINT_HEIGHT=%lld\n", gs_checkpoint_height());
    printf("RECENT_HEADERS=%lld\n", gs_restore_recent());



    return (hv == 1 && hn == 32 && an > 0) ? 0 : 2;
}


