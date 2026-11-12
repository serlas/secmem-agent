#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/memfd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sodium.h>
#include <time.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/resource.h>

#define MAX_SECRETS 100
#define KEY_LEN crypto_aead_aes256gcm_KEYBYTES
#define NONCE_LEN crypto_aead_aes256gcm_NPUBBYTES
#define ABYTES crypto_aead_aes256gcm_ABYTES

struct secret {
    char *key;
    int memfd;
    time_t expire_time;
    uid_t owner_uid;
};

struct agent {
    int sock;
    unsigned char enc_key[KEY_LEN];
    struct secret secrets[MAX_SECRETS];
    int num_secrets;
    pthread_t ttl_thread;
};

void *ttl_checker(void *arg) {
    struct agent *ag = arg;
    while (1) {
        time_t now = time(NULL);
        for (int i = 0; i < ag->num_secrets; i++) {
            if (ag->secrets[i].expire_time < now) {
                close(ag->secrets[i].memfd);
                explicit_bzero(ag->secrets[i].key, strlen(ag->secrets[i].key));
                free(ag->secrets[i].key);
                // Audit: printf("TTL expired for %s\n", ag->secrets[i].key);
                ag->num_secrets--;
            }
        }
        sleep(1);
    }
}

int main() {
    struct agent ag = {0};
    randombytes_buf(ag.enc_key, KEY_LEN);
    mlockall(MCL_CURRENT | MCL_FUTURE);

    struct rlimit rl;
    getrlimit(RLIMIT_MEMLOCK, &rl);
    if (rl.rlim_cur < 1 << 20) { fprintf(stderr, "Low memlock limit\n"); exit(1); }

    unlink("/run/secmem.sock");
    ag.sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {AF_UNIX, "/run/secmem.sock"};
    bind(ag.sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(ag.sock, 5);

    pthread_create(&ag.ttl_thread, NULL, ttl_checker, &ag);

    while (1) {
        int client = accept(ag.sock, NULL, NULL);
        struct ucred cred;
        socklen_t len = sizeof(cred);
        getsockopt(client, SOL_SOCKET, SO_PEERCRED, &cred, &len);
        if (cred.uid != 0) { close(client); continue; }

        char buf[1024] = {0};
        read(client, buf, sizeof(buf));
        char *cmd = strtok(buf, " ");
        if (strcmp(cmd, "put") == 0) {
            char *key_val = strtok(NULL, " ");
            char *key = strtok(key_val, "=");
            char *value = strtok(NULL, "=");
            char *ttl_str = strtok(NULL, "--ttl");
            time_t ttl = atoi(ttl_str) * 60;

            int memfd = memfd_create("secret", MFD_CLOEXEC);
            fcntl(memfd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
            size_t val_len = strlen(value);
            unsigned char nonce[NONCE_LEN];
            randombytes_buf(nonce, NONCE_LEN);
            unsigned char ciphertext[val_len + ABYTES];
            crypto_aead_aes256gcm_encrypt(ciphertext, NULL, (unsigned char*)value, val_len, NULL, 0, NULL, nonce, ag.enc_key);
            write(memfd, ciphertext, val_len + ABYTES);
            lseek(memfd, 0, SEEK_SET);

            ag.secrets[ag.num_secrets].key = strdup(key);
            ag.secrets[ag.num_secrets].memfd = memfd;
            ag.secrets[ag.num_secrets].expire_time = time(NULL) + ttl;
            ag.secrets[ag.num_secrets].owner_uid = cred.uid;
            ag.num_secrets++;
            // Audit: printf("UID %d put %s TTL %ld\n", cred.uid, key, ttl);

            struct msghdr msg = {0};
            struct iovec iov = {"OK", 2};
            char cmsg[CMSG_SPACE(sizeof(int))];
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg;
            msg.msg_controllen = sizeof(cmsg);
            struct cmsghdr *cmsg_hdr = CMSG_FIRSTHDR(&msg);
            cmsg_hdr->cmsg_level = SOL_SOCKET;
            cmsg_hdr->cmsg_type = SCM_RIGHTS;
            cmsg_hdr->cmsg_len = CMSG_LEN(sizeof(int));
            *((int*)CMSG_DATA(cmsg_hdr)) = memfd;
            sendmsg(client, &msg, 0);
            explicit_bzero(value, val_len);
        } else if (strcmp(cmd, "get") == 0) {
            char *key = strtok(NULL, " ");
            for (int i = 0; i < ag.num_secrets; i++) {
                if (strcmp(ag.secrets[i].key, key) == 0 && ag.secrets[i].owner_uid == cred.uid) {
                    // Decrypt to new memfd
                    int dec_fd = memfd_create("dec", MFD_CLOEXEC);
                    fcntl(dec_fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
                    size_t len = lseek(ag.secrets[i].memfd, 0, SEEK_END);
                    unsigned char ciphertext[len];
                    read(ag.secrets[i].memfd, ciphertext, len);
                    unsigned char plaintext[len - ABYTES];
                    crypto_aead_aes256gcm_decrypt(plaintext, NULL, NULL, ciphertext, len, NULL, 0, NULL, ag.enc_key);
                    write(dec_fd, plaintext, len - ABYTES);
                    lseek(dec_fd, 0, SEEK_SET);
                    // Send dec_fd via SCM_RIGHTS (similar to above)
                    // Audit: printf("UID %d get %s\n", cred.uid, key);
                    explicit_bzero(plaintext, len - ABYTES);
                    break;
                }
            }
        }
        close(client);
    }
    explicit_bzero(ag.enc_key, KEY_LEN);
    return 0;
}