#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void write_to_file(const char *filepath, const unsigned char *alice_public_key,
                   const unsigned char *bob_public_key,
                   const unsigned char *shared_secret_alice,
                   const unsigned char *shared_secret_bob) {
    FILE *file = fopen(filepath, "w");
    if (!file) {
        printf("Error with the file initialization\n");
        exit(1);
    }
    fprintf(file, "Alice's Public Key:\n");
    for (size_t i = 0; i < crypto_scalarmult_BYTES; i++) {
        fprintf(file, "%02x", alice_public_key[i]);
    }
    fprintf(file, "\n");

    fprintf(file, "Bob's Public Key:\n");
    for (size_t i = 0; i < crypto_scalarmult_BYTES; i++) {
        fprintf(file, "%02x", bob_public_key[i]);
    }
    fprintf(file, "\n");

    fprintf(file, "Shared Secret (Alice):\n");
    for (size_t i = 0; i < crypto_scalarmult_BYTES; i++) {
        fprintf(file, "%02x", shared_secret_alice[i]);
    }
    fprintf(file, "\n");

    fprintf(file, "Shared Secret (Bob):\n");
    for (size_t i = 0; i < crypto_scalarmult_BYTES; i++) {
        fprintf(file, "%02x", shared_secret_bob[i]);
    }
    fprintf(file, "\n");

    fclose(file);
}




int main(int argc, char *argv[]) {
    int opt;
    char *output_path = NULL;
    unsigned char alice_private_key[crypto_scalarmult_SCALARBYTES];
    unsigned char bob_private_key[crypto_scalarmult_SCALARBYTES];
    int alice_private_given = 0;
    int bob_private_given = 0;






    // command line options 
    while ((opt = getopt(argc, argv, "o:a:b:h")) != -1) {
        switch (opt) {
            case 'o':
                output_path = optarg;
                break;
            case 'a':
                alice_private_given = 1;
                memset(alice_private_key, 0, crypto_scalarmult_SCALARBYTES);
                sscanf(optarg, "%llx", (unsigned long long *)alice_private_key);
                break;
            case 'b':
                bob_private_given = 1;
                memset(bob_private_key, 0, crypto_scalarmult_SCALARBYTES);
                sscanf(optarg, "%llx", (unsigned long long *)bob_private_key);
                break;
            case 'h':
                printf("Use: ./assign_1 -o path_to_output_file -a alice_private_key (optional) -b bob_private_key (optional)\n");
                exit(0);
            default:
                fprintf(stderr, "Not an option \n");
                exit(EXIT_FAILURE);
        }
    }






    if (output_path == NULL) {
        fprintf(stderr, "Error invalid output path\n");
        exit(EXIT_FAILURE);
    }
    // initialize sodium
    if (sodium_init() < 0) {
        printf("Error sodium is not initilized\n");
        return -1;
    }
    // if the private keys are not given they are produced randomly 
    if (!alice_private_given) {
        randombytes_buf(alice_private_key, crypto_scalarmult_SCALARBYTES);
    }
    if (!bob_private_given) {
        randombytes_buf(bob_private_key, crypto_scalarmult_SCALARBYTES);
    }




    // Public keys
    unsigned char alice_public_key[crypto_scalarmult_BYTES];
    unsigned char bob_public_key[crypto_scalarmult_BYTES];
    // Calculate public keys
    crypto_scalarmult_base(alice_public_key, alice_private_key);
    crypto_scalarmult_base(bob_public_key, bob_private_key);
    // Calculate shared secret
    unsigned char shared_secret_alice[crypto_scalarmult_BYTES];
    unsigned char shared_secret_bob[crypto_scalarmult_BYTES];
    crypto_scalarmult(shared_secret_alice, alice_private_key, bob_public_key);
    crypto_scalarmult(shared_secret_bob, bob_private_key, alice_public_key);





    // check if the secrets are same
    if (memcmp(shared_secret_alice, shared_secret_bob, crypto_scalarmult_BYTES) != 0) {
        printf("Error secrets doesnt match\n");
        return -1;
    }




    printf("Alice's Public Key: ");
    print_hex(alice_public_key, crypto_scalarmult_BYTES);
    printf("Bob's Public Key: ");
    print_hex(bob_public_key, crypto_scalarmult_BYTES);
    printf("Shared Secret (Alice): ");
    print_hex(shared_secret_alice, crypto_scalarmult_BYTES);
    printf("Shared Secret (Bob): ");
    print_hex(shared_secret_bob, crypto_scalarmult_BYTES);
    printf("Shared secrets match!!\n");




    // Write to file as asked
    write_to_file(output_path, alice_public_key, bob_public_key, shared_secret_alice, shared_secret_bob);

    return 0;
}
