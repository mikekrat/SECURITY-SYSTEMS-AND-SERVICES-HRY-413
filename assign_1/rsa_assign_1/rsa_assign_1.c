#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <sys/time.h>
#include <unistd.h> 
#include <sys/resource.h>
#include <stdio.h> 
#include <time.h>  
// Function to check if a number is prime
int is_prime(mpz_t num) {
    int result = mpz_probab_prime_p(num, 25);
    return result > 0;
}

// Function to generate RSA keys
void generateRSAKeyPair(int key_length) {
    mpz_t p, q, n, lambda, e, d;
    mpz_inits(p, q, n, lambda, e, d, NULL);
    
    // Generate random primes p and q
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    // Generate prime p
    do {
        mpz_urandomb(p, state, key_length / 2);
    } while (!is_prime(p));

    // Generate prime q (different from p)
    do {
        mpz_urandomb(q, state, key_length / 2);
    } while (!is_prime(q) || mpz_cmp(p, q) == 0);

    // Calculate n = p * q
    mpz_mul(n, p, q);

    // Calculate lambda(n) = (p - 1) * (q - 1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(lambda, p, q);

    // Choose e such that 1 < e < lambda and gcd(e, lambda) == 1
    do {
        mpz_urandomb(e, state, 16);
        mpz_gcd(p, e, lambda); // reuse p to store gcd result
    } while (mpz_cmp_ui(p, 1) != 0);

    // Calculate d, the modular inverse of e mod lambda
    mpz_invert(d, e, lambda);


    char public_key_file[64];
    char private_key_file[64];
    snprintf(public_key_file, sizeof(public_key_file), "public_%d.key", key_length);
    snprintf(private_key_file, sizeof(private_key_file), "private_%d.key", key_length);

    // Write the public key (n, e) to the public key file
    FILE *pub_file = fopen(public_key_file, "w");
    if (pub_file != NULL) {
        gmp_fprintf(pub_file, "%Zd\n%Zd\n", n, e);
        fclose(pub_file);
    } else {
        perror("Error opening public key file");
    }

    // Write the private key (n, d) to the private key file
    FILE *priv_file = fopen(private_key_file, "w");
    if (priv_file != NULL) {
        gmp_fprintf(priv_file, "%Zd\n%Zd\n", n, d);
        fclose(priv_file);
    } else {
        perror("Error opening private key file");
    }
    //gmp_printf("d %Zd e %Zd n %Zd ",d,e,n);
    // Clear variables
    mpz_clears(p, q, n, lambda, e, d, NULL);
    gmp_randclear(state);
}



// Function to perform RSA encryption
void encryptData(const char *input_file, const char *output_file, const char *key_file) {
    mpz_t n, e, plaintext, ciphertext;
    mpz_inits(n, e, plaintext, ciphertext, NULL);

    // Read the public key from the file
    FILE *key_fp = fopen(key_file, "r");
    if (key_fp == NULL) {
        perror("Error opening key file");
        return;
    }
    if(gmp_fscanf(key_fp, "%Zd\n%Zd", n, e)!=2){
        printf("ERROR!\n");
        return;
    }
    //gmp_printf("n = %Zd\ne = %Zd\n", n,e);
    fclose(key_fp);

    // Read the plaintext from the input file
    FILE *input_fp = fopen(input_file, "r");
    if (input_fp == NULL) {
        perror("Error opening input file");
        return;
    }


    char message[256];
    fscanf(input_fp, "%s", message);
    fclose(input_fp);
    mpz_import(plaintext, strlen(message), 1, 1, 0, 0, message);

    
    // Perform encryption: ciphertext = plaintext^e mod n
    mpz_powm(ciphertext, plaintext, e, n);
    //gmp_printf("%Zd\n",ciphertext);

    // Write the ciphertext to the output file
    FILE *output_fp = fopen(output_file, "w");
    gmp_fprintf(output_fp, "%Zd\n", ciphertext);
    fclose(output_fp);

    // Clear variables
    mpz_clears(n, e, plaintext, ciphertext, NULL);
}


// Function to perform RSA decryption
void decryptData(const char *input_file, const char *output_file, const char *key_file) {
    mpz_t n, d, ciphertext, plaintext;
    mpz_inits(n, d, ciphertext, plaintext, NULL);

    // Read the private key from the file
    FILE *key_fp = fopen(key_file, "r");
    if (key_fp == NULL) {
        perror("Error opening key file");
        return;
    }
    if(gmp_fscanf(key_fp, "%Zd\n%Zd", n, d)!=2){
        printf("ERROR!\n");
        return;
    }
    //gmp_printf("n %Zd\nd %Zd\n",n,d);
    fclose(key_fp);

    // Read the ciphertext from the input file
    FILE *input_fp = fopen(input_file, "r");
    if (input_fp == NULL) {
        perror("Error opening input file");
        return;
    }
    mpz_inp_str(ciphertext, input_fp, 10);
    //gmp_printf("%Zd\n",ciphertext);
    fclose(input_fp);

    // Perform decryption: plaintext = ciphertext^d mod n
    mpz_powm(plaintext, ciphertext, d, n);
    //gmp_printf("%Zd\n",plaintext);
    
    char *decrypted_message = mpz_export(NULL, NULL, 1, 1, 0, 0, plaintext);
    FILE *output_fp = fopen(output_file, "w");
    fprintf(output_fp, "%s", decrypted_message);
    fclose(output_fp);

    // Clear variables
    mpz_clears(n, d, ciphertext, plaintext, NULL);
}
void print_help() {
    printf("Usage:\n");
    printf("-i <path>   Path to the input file\n");
    printf("-o <path>   Path to the output file\n");
    printf("-k <path>   Path to the key file\n");
    printf("-g <length> Generate RSA key pair of the specified length\n");
    printf("-e          Encrypt input and store results to output\n");
    printf("-d          Decrypt input and store results to output\n");
    printf("-a          Compare performance with different key lengths\n");
    printf("-h          Show this help message\n");
}
double get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}
long get_memory_usage() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        // If getrusage fails, return -1
        return -1;
    }
    // Return the maximum resident set size used (in kilobytes)
    return usage.ru_maxrss;
}
void compare_performance(const char* performance_file) {
    int key_lengths[3] = {1024, 2048, 4096};
    FILE *perf_file = fopen(performance_file, "w");
    if (!perf_file) {
        printf("Error: Unable to open file %s for writing\n", performance_file);
        return;
    }

    for (int i = 0; i < 3; i++) {
        char pub_file[20], priv_file[20];
        sprintf(pub_file, "public_%d.key", key_lengths[i]);
        sprintf(priv_file, "private_%d.key", key_lengths[i]);

        printf("\nGenerating RSA keys with %d-bit length...\n", key_lengths[i]);

        // Measure key generation time
        double start_time = get_time();
        generateRSAKeyPair(key_lengths[i]);
        double end_time = get_time();

        fprintf(perf_file, "Key Length: %d bits\n", key_lengths[i]);
        fprintf(perf_file, "Key Generation Time: %f\n", end_time - start_time);
        
        // Encryption performance
        start_time = get_time();
        encryptData("plaintext.txt", "ciphertext.txt", pub_file);
        end_time = get_time();
        fprintf(perf_file, "Encryption Time: %f\n", end_time - start_time);
        fprintf(perf_file, "Peak Memory Usage (Encryption): %ld KB\n", get_memory_usage());

        // Decryption performance
        start_time = get_time();
        decryptData("ciphertext.txt", "output.txt", priv_file);
        end_time = get_time();
        fprintf(perf_file, "Decryption Time: %f\n", end_time - start_time);
        fprintf(perf_file, "Peak Memory Usage (Decryption): %ld KB\n\n\n", get_memory_usage());
        
    }

    fclose(perf_file);
}


// Main function to handle command-line arguments and call appropriate functions
int main(int argc, char *argv[]) {
    int opt;
    char *input_file = NULL;
    char *output_file = NULL;
    char *key_file = NULL;
    char *private_key_file = NULL;
    char *public_key_file = NULL;
    char *performance_file = NULL;
    int key_length = 0;
    int key_lengths[] = {1024, 2048, 4096};  // for performance comparison

    // Command-line argument parsing
    while ((opt = getopt(argc, argv, "i:o:k:g:edah")) != -1) {
        switch (opt) {
            case 'i':
                input_file = optarg;  // Get input file path
                break;
            case 'o':
                output_file = optarg;  // Get output file path
                break;
            case 'k':
                key_file = optarg;  // Get key file path
                break;
            case 'g':
                key_length = atoi(optarg);  // Get key length for key generation
                generateRSAKeyPair(key_length);
                break;
            case 'e':
                if (input_file && output_file && key_file) {
                    encryptData(input_file, output_file, key_file);
                } else {
                    fprintf(stderr, "Error: Missing arguments for encryption.\n");
                }
                break;
            case 'd':
                if (input_file && output_file && key_file) {
                    decryptData(input_file, output_file, key_file);
                } else {
                    fprintf(stderr, "Error: Missing arguments for decryption.\n");
                }
                break;
            case 'a':
                // Compare performance for different key lengths
                if (optarg != NULL) {
                    performance_file = optarg; // The argument following -a
                } else {
                    performance_file = "performance.txt"; // Default if none provided
                }
                compare_performance(performance_file);
                break;
            case 'h':
                print_help();
            default:
                return 1;
        }
    }
    return 0;
}
