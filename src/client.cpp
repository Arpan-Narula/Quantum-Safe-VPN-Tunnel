#include <iostream>
#include <cstring>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/select.h>
#include <signal.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define BUFFER_SIZE 2048
#define KYBER_ALG OQS_KEM_alg_kyber_512
#define IV_LEN 12
#define TAG_LEN 16

using namespace std;

int tun_fd, sock;
uint8_t final_symmetric_key[32]; 

void handle_crypto_error() {
    ERR_print_errors_fp(stderr);
    cerr << "[!] Cryptographic operation failed." << endl;
}

int encrypt_packet(const uint8_t *plaintext, int plaintext_len, const uint8_t *key, uint8_t *ciphertext_out) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];

    if (!RAND_bytes(iv, sizeof(iv))) handle_crypto_error();

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_crypto_error();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handle_crypto_error();
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handle_crypto_error();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext_out + IV_LEN, &len, plaintext, plaintext_len)) handle_crypto_error();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext_out + IV_LEN + len, &len)) handle_crypto_error();
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) handle_crypto_error();

    memcpy(ciphertext_out, iv, IV_LEN);
    memcpy(ciphertext_out + IV_LEN + ciphertext_len, tag, TAG_LEN);

    EVP_CIPHER_CTX_free(ctx);
    return IV_LEN + ciphertext_len + TAG_LEN;
}

int decrypt_packet(const uint8_t *encrypted_data, int encrypted_len, const uint8_t *key, uint8_t *plaintext_out) {
    if (encrypted_len < IV_LEN + TAG_LEN) return -1;
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];
    int ciphertext_len = encrypted_len - IV_LEN - TAG_LEN;
    
    memcpy(iv, encrypted_data, IV_LEN);
    memcpy(tag, encrypted_data + encrypted_len - TAG_LEN, TAG_LEN);
    const uint8_t *ciphertext = encrypted_data + IV_LEN;

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_crypto_error();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handle_crypto_error();
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handle_crypto_error();

    if (!EVP_DecryptUpdate(ctx, plaintext_out, &len, ciphertext, ciphertext_len)) handle_crypto_error();
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) handle_crypto_error();

    int ret = EVP_DecryptFinal_ex(ctx, plaintext_out + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
}

void handle_sigint(int sig) {
    cout << "\n[!] Caught signal " << sig << ", shutting down gracefully..." << endl;
    if (sock > 0) close(sock);
    if (tun_fd > 0) close(tun_fd);
    OQS_destroy();
    exit(0);
}

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("[ERROR] Opening /dev/net/tun failed");
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 
    if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("[ERROR] ioctl(TUNSETIFF) failed");
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

bool derive_final_key(const uint8_t* x25519_ss, size_t x25519_len, 
                      const uint8_t* kyber_ss, size_t kyber_len, 
                      uint8_t* out_key, size_t out_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    size_t total_len = x25519_len + kyber_len;
    uint8_t *combined_secret = new uint8_t[total_len];
    memcpy(combined_secret, x25519_ss, x25519_len);
    memcpy(combined_secret + x25519_len, kyber_ss, kyber_len);

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, combined_secret, total_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (char*)"VPN_HANDSHAKE", 13);
    params[3] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out_key, out_len, params) <= 0) {
        delete[] combined_secret;
        EVP_KDF_CTX_free(kctx);
        return false;
    }

    delete[] combined_secret;
    EVP_KDF_CTX_free(kctx);
    return true;
}

bool perform_handshake(struct sockaddr_in& serv_addr) {
    cout << "[*] Starting Hybrid Handshake..." << endl;
    OQS_init();

    EVP_PKEY *x25519_pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    uint8_t x25519_pub[32];
    size_t x25519_pub_len = sizeof(x25519_pub);
    EVP_PKEY_get_raw_public_key(x25519_pkey, x25519_pub, &x25519_pub_len);

    OQS_KEM *kem = OQS_KEM_new(KYBER_ALG);
    uint8_t kyber_pub[kem->length_public_key];
    uint8_t kyber_sec[kem->length_secret_key];
    OQS_KEM_keypair(kem, kyber_pub, kyber_sec);

    size_t hello_len = x25519_pub_len + kem->length_public_key;
    uint8_t *client_hello = new uint8_t[hello_len];
    memcpy(client_hello, x25519_pub, x25519_pub_len);
    memcpy(client_hello + x25519_pub_len, kyber_pub, kem->length_public_key);

    cout << "[*] Sending ClientHello (X25519 PK + Kyber PK)..." << endl;
    sendto(sock, client_hello, hello_len, 0, (const struct sockaddr*)&serv_addr, sizeof(serv_addr));
    delete[] client_hello;

    cout << "[*] Waiting for ServerHello..." << endl;
    uint8_t server_hello[2048];
    socklen_t len = sizeof(serv_addr);
    int valread = recvfrom(sock, server_hello, sizeof(server_hello), 0, (struct sockaddr*)&serv_addr, &len);

    if (valread <= 0) {
        cerr << "[ERROR] Failed to receive ServerHello." << endl;
        return false;
    }

    uint8_t server_x25519_pub[32];
    memcpy(server_x25519_pub, server_hello, 32);
    
    uint8_t kyber_ct[kem->length_ciphertext];
    memcpy(kyber_ct, server_hello + 32, kem->length_ciphertext);

    EVP_PKEY *server_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_x25519_pub, 32);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(x25519_pkey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, server_pkey);
    
    size_t x25519_ss_len;
    EVP_PKEY_derive(ctx, NULL, &x25519_ss_len);
    uint8_t x25519_ss[x25519_ss_len];
    EVP_PKEY_derive(ctx, x25519_ss, &x25519_ss_len);

    uint8_t kyber_ss[kem->length_shared_secret];
    OQS_KEM_decaps(kem, kyber_ss, kyber_ct, kyber_sec);

    derive_final_key(x25519_ss, x25519_ss_len, kyber_ss, kem->length_shared_secret, final_symmetric_key, 32);
    
    cout << "[+] Handshake Complete. Symmetric key derived successfully!" << endl;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(server_pkey);
    EVP_PKEY_free(x25519_pkey);
    OQS_KEM_free(kem);
    
    return true;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <Server_IP> <Server_Port>\n";
        return -1;
    }
    signal(SIGINT, handle_sigint); 

    string server_ip = argv[1];
    int server_port = stoi(argv[2]);

    char tun_name[IFNAMSIZ] = "tun0";
    tun_fd = tun_alloc(tun_name);
    system("ip addr add 10.0.0.2/24 dev tun0");
    system("ip link set dev tun0 up");

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return -1;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr);

    if (!perform_handshake(serv_addr)) {
        cerr << "[!] Handshake failed. Exiting." << endl;
        return -1;
    }

    cout << "[+] UDP Client ready! Sending traffic to Server at " << server_ip << ":" << server_port << endl;
    cout << "------------------------------------------------------" << endl;

    char buffer[BUFFER_SIZE];
    fd_set readfds;

    char tun_buf[BUFFER_SIZE];
    uint8_t wire_buf[BUFFER_SIZE + IV_LEN + TAG_LEN];
    uint8_t decrypt_buf[BUFFER_SIZE];

    cout << "\n[***] SECURE TUNNEL ESTABLISHED [***]" << endl;
    cout << "Routing all OS traffic through AES-256-GCM encrypted UDP stream." << endl;
    
    while (true) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);   
        FD_SET(tun_fd, &readfds); 

        int max_fd = max(sock, tun_fd);
        int activity = select(max_fd + 1, &readfds, NULL, NULL, NULL);

        if (activity < 0) break;

        if (FD_ISSET(tun_fd, &readfds)) {
            int valread = read(tun_fd, tun_buf, sizeof(tun_buf));
            if (valread > 0) {
                int wire_len = encrypt_packet((uint8_t*)tun_buf, valread, final_symmetric_key, wire_buf);

                sendto(sock, wire_buf, wire_len, 0, (const struct sockaddr *) &serv_addr, sizeof(serv_addr));
                
                cout << "[OUTBOUND] Captured " << valread << " bytes from OS. " 
                     << "Encrypted to " << wire_len << " bytes. Sent to Server " 
                     << server_ip << ":" << server_port << endl;
            }
        }

        if (FD_ISSET(sock, &readfds)) {
            socklen_t len = sizeof(serv_addr);
            int valread = recvfrom(sock, wire_buf, sizeof(wire_buf), 0, (struct sockaddr *) &serv_addr, &len);
            
            if (valread > 0) {
                int plain_len = decrypt_packet(wire_buf, valread, final_symmetric_key, decrypt_buf);
                
                if (plain_len > 0) {
                    write(tun_fd, decrypt_buf, plain_len);
                    
                    cout << "[ INBOUND] Received " << valread << " bytes from Server. "
                         << "Decrypted successfully (" << plain_len << " bytes). Injected to OS (tun0)." << endl;
                } else {
                    cerr << "[! ALERT !] Received tampered/corrupt packet from Server. Dropped immediately!" << endl;
                }
            }
        }
    }

    handle_sigint(0);
    return 0;
}

