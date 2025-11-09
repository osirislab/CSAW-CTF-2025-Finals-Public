#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MESSAGE_BYTES 60
#define KEY_LEN 6

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, char[7]);
    __uint(max_entries, 1);
} key_to_honey SEC(".maps");

static __inline unsigned char hexToByte(char high, char low) {
    unsigned int h;
    if (high >= '0' && high <= '9')
        h = (unsigned int)(high - '0');
    else if (high >= 'A' && high <= 'F')
        h = (unsigned int)(high - 'A' + 10);
    else
        h = (unsigned int)(high - 'a' + 10);

    unsigned int l;
    if (low >= '0' && low <= '9')
        l = (unsigned int)(low - '0');
    else if (low >= 'A' && low <= 'F')
        l = (unsigned int)(low - 'A' + 10);
    else
        l = (unsigned int)(low - 'a' + 10);

    unsigned int res = ((h << 4) & 0xFFu) | (l & 0x0Fu);
    return (unsigned char)res;
}

static __inline void xorDecrypt(const char *key_map_val) {
    unsigned char encryptedBytes[MESSAGE_BYTES];
    char decryptedMessage[MESSAGE_BYTES + 1];
    char key_local[KEY_LEN];

    __builtin_memcpy(key_local, key_map_val, KEY_LEN);

    const char *encryptedHex = "2B43133950002E4B0606562B2A034111020717564320521824692D2841477B542D284144256F133E5A343A692D0C462E326A0834692E124A08344909";

    for (int i = 0; i < MESSAGE_BYTES; i++) {
        encryptedBytes[i] = hexToByte(encryptedHex[2 * i], encryptedHex[2 * i + 1]);
    }

    int key_idx = 0;
    for (int i = 0; i < MESSAGE_BYTES; i++) {
        decryptedMessage[i] = (char)(encryptedBytes[i] ^ key_local[key_idx]);
        key_idx++;
        if (key_idx >= KEY_LEN)
            key_idx = 0;
    }
    decryptedMessage[MESSAGE_BYTES] = '\0';

    bpf_printk("%s", decryptedMessage);
}

SEC("lsm/inode_create")
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    char filename[20];
    char parent[20];
    int key = 0;

    const unsigned char *fname = BPF_CORE_READ(dentry, d_name.name);
    if (!fname)
        return 0;

    bpf_core_read_str(filename, sizeof(filename), fname);

    if (bpf_strncmp(filename, sizeof("cage.txt") - 1, "cage.txt") != 0)
        return 0;

    struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
    if (!parent_dentry)
        return 0;

    const unsigned char *pname = BPF_CORE_READ(parent_dentry, d_name.name);
    if (!pname)
        return 0;

    bpf_core_read_str(parent, sizeof(parent), pname);

    if (bpf_strncmp(parent, sizeof(".nectar") - 1, ".nectar") != 0)
        return 0;

    char *secret = bpf_map_lookup_elem(&key_to_honey, &key);
    if (secret)
        xorDecrypt(secret);

    return 0;
}
