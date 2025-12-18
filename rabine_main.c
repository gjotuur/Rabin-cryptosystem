/*Stable version 2025 12 17, all of the funcs are debugged and stabilized
prototyping and declaration fully checked, memory leaks and input buffer also checked
Decrypt func fully stable, works for every possible len of key without bugs / problems
Tests:
256 bit     | passed
512 bit     | passed
1024 bit    | passed
2048 bit    | passed*/

#include <stdio.h>
#include <math.h>
#include <stdint.h>         //uint64_t used
#include <time.h>           //random seed
#include <string.h>         //fgets for mpz_init_set_str
#include <stdbool.h>        //boolean type funcs
#include <stdlib.h>         
#include <gmp.h>            //compiled only with -o ".exe" -lgmp instructions, main lib here

typedef struct{
    mpz_t n;
    mpz_t b;
}RabinPublic; //stored in memory with all components

typedef struct{
    mpz_t p;
    mpz_t q;
    mpz_t b;
}RabinPrivate; //same, stored in memory

typedef struct{
    mpz_t m;
    mpz_t r;
    mpz_t x;
}RabinMessage; //have limited use for formatting/unformatting tests and so on

// Keys generation
void GenerateKeys(RabinPublic **public_key, RabinPrivate **private_key, int bits, gmp_randstate_t state);                    //Debugged
void InputKeys(RabinPublic* pub, RabinPrivate* priv, int* key_length);                                                       //memory allocation - outside of func
void FreeKeys(RabinPrivate* private_key, RabinPublic* public_key);                                                           //#removekebab

// Message formatting
void RabinMessage_init(RabinMessage* m);                                                                                     //init func, barely used due to architecture
void RabinMessage_clear(RabinMessage* m);                                                                                    //clear func with mpz_clears to avoid leaks
bool format_m(RabinMessage* msg, const mpz_t m, const mpz_t n, gmp_randstate_t state);                                       //debugged twice
bool unformat_m(mpz_t m, const mpz_t x, const mpz_t n);                                                                      //debugged + reworked

// Encryption/Decryption
void RabinEncrypt(mpz_t y, int* c1, int* c2, const mpz_t x, const RabinPublic* public_key);                                  //Fully stable, debugged, core func
bool RabinDecrypt(mpz_t x, const mpz_t y, int c1, int c2, const RabinPrivate* private_key, const RabinPublic* public_key);   //Fully stable, debugged, core func

// Signing/Verification
bool RabinSign(mpz_t signature, int* s1, int* s2, const mpz_t message, const RabinPrivate* private_key, const RabinPublic* public_key, gmp_randstate_t state); //stable, debugged
bool RabinVerify(const mpz_t message, const mpz_t signature, int s1, int s2, const RabinPublic* public_key);                                                   //stable, debugged

//Not all funcs may be declared here due to the fact that they are still used after declaration at the bottom, so they still work well without prototyping
//undeclared - gcd, most significant byte + few service funcs used in those prototyped here

int main(){
    RabinPrivate* private = malloc(sizeof(RabinPrivate));
    RabinPublic* public = malloc(sizeof(RabinPublic));
    //RNG, seed = time
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    //So program could work with any length of the key
    int keylen;
    bool sw1;                                           //simple switch - we can understand possible funcs regarding server interactions
    printf("\nAsymCrypto Lab#3: Rabin cryptosystem.\nSo it begins.\nEnter mode: 1 to input keys, 0 to generate keys\nYour answer: ");
    scanf(" %d", &sw1);
    getchar();                                          //clear buffer
    printf("\n");
    if(sw1){
        InputKeys(public, private, &keylen);
    } else {
        printf("Enter key length");
        scanf(" %d", &keylen);
        getchar();
        printf("\n");
        GenerateKeys(&public, &private, keylen, state);
    }
    //Debug / Diagnostics
    gmp_printf("\nCurrent keys\n");
    gmp_printf("Public key:\nn = %Zx\nb = %Zx\n", public->n, public->b);
    gmp_printf("Private key:\np = %Zx\nq = %Zx\nb = %Zx\n", private->p, private->q, private->b);

    //Encryption test
    printf("\nEncryption\n");
    RabinMessage* message1 = malloc(sizeof(RabinMessage));
    RabinMessage_init(message1);

    //Text input + memory allocation (char*)
    mpz_t plaintext;
    mpz_init_set_str(plaintext, "76 6c 61 64 79 6b 61 72 65 61 6c 6e 6f 73 74 69", 16); // "vladykarealnosti"
    gmp_printf("Plaintext: %Zx (vladykarealnosti)\n", plaintext);

    if(!format_m(message1, plaintext, public->n, state)) {
        fprintf(stderr, "Padding error\n");
        return 1;
    }
    gmp_printf("Formatted x: %Zx\n", message1->x);

    //Initialize ciphertext and fill it
    mpz_t ciphertext;
    mpz_init(ciphertext);
    int c1, c2;
    RabinEncrypt(ciphertext, &c1, &c2, message1->x, public);
    gmp_printf("Encrypted y: %Zx\nc1=%d, c2=%d\n", ciphertext, c1, c2);

    //___Decryption tests - interaction with server
    printf("Decryption\n");
    mpz_t ciphertext2;
    mpz_init(ciphertext2);
    RabinPrivate* private_2 = NULL;
    RabinPublic* public_2 = NULL;
    bool sw2;
    printf("We`re generating keys with the same len? 1 - yes, 0 - no: ");
    scanf(" %d", &sw2);
    getchar();
    //Let`s check for 70 69 64 70 72 6f 73 74 69 72 70 72 6f 73 74 6f 72 79 (pidprostirprostory)
    if(!sw2){
        int keylen2;
        printf("\nEnter new keylen then: ");
        scanf(" %d", &keylen2);
        getchar();
        keylen = keylen2;
    }
    //Generate keys for server
    GenerateKeys(&public_2, &private_2, keylen, state);                     //Generating keys for the server, so it will encrypt and program will decrypt
    mpz_t tmp1488;
    mpz_init(tmp1488);
    mpz_mul(tmp1488, private_2->p, private_2->q);
    gmp_printf("\nSo we got:\nn = %ZX\nb = %ZX\np*q = %ZX", public_2->n, public_2->b, tmp1488);
    printf("\nPlaintext is 70696470726f7374697270726f73746f7279 (pidprostirprostory)\n");
    mpz_clear(tmp1488);

    //Input server response
    char* dec_test = malloc(((keylen/4)+2)*sizeof(char)); // +2 для \n та \0
    printf("Input encrypted version here: ");
    if(fgets(dec_test, (keylen/4) + 2, stdin) != NULL) {
        dec_test[strcspn(dec_test, "\n")] = '\0';
    }

    mpz_set_str(ciphertext2, dec_test, 16);
    free(dec_test);

    int dec_c1, dec_c2;
    printf("Enter c1: ");
    scanf(" %d", &dec_c1);
    getchar();

    printf("\nEnter c2: ");
    scanf(" %d", &dec_c2);
    getchar();

    //Try to decrypt with our keys (only program knows private key)
    mpz_t decrypted;
    mpz_init(decrypted);
    RabinDecrypt(decrypted, ciphertext2, dec_c1, dec_c2, private_2, public_2);
    gmp_printf("\nPlaintext now is: %ZX", ciphertext2);
    gmp_printf("\nFormatted decrypted text: %ZX\n", decrypted);

    mpz_t un_decrypted;
    mpz_init(un_decrypted);
    unformat_m(un_decrypted, decrypted, public_2->n);
    gmp_printf("\nUnformatted decrypted text: %ZX", un_decrypted);
    printf("\nC1 is %d, C2 is %d", dec_c1, dec_c2);

    //_____Signature tests: both Sign and Verify
    //RabinSign test: signed in program, given to server to verify
    mpz_t signature_1;
    mpz_init(signature_1);
    int s1,s2;
    RabinSign(signature_1, &s1, &s2, un_decrypted, private_2, public_2, state);
    gmp_printf("\nSignature for this message is: %ZX", signature_1);

    if(!sw1){
        printf("\nVerification unavailable, keys are generated");
        RabinMessage_clear(message1);
        free(message1);
        FreeKeys(private, public);
        FreeKeys(private_2, public_2);
        gmp_randclear(state);
        mpz_clears(plaintext, ciphertext, decrypted, un_decrypted, signature_1, NULL);
        return 0;
    }

    //Verify test: we use keys from server to create signature and then verify it inside of the program
    char* text_signature = malloc(((keylen/4)+2)*sizeof(char)); // additional 2 for \n \0 which may occur
    printf("\nInput signature here: ");
    if(fgets(text_signature, (keylen/4) + 2, stdin) != NULL) {
        text_signature[strcspn(text_signature, "\n")] = '\0';
    }
    mpz_t test_signature;
    mpz_init_set_str(test_signature, text_signature, 16);

    gmp_printf("\nVerifying for public key\nn = %ZX\nm = %ZX", public->n, un_decrypted);
    if(RabinVerify(un_decrypted, test_signature, 0, 0, public)){
        printf("\nVerification: TRUE");
    } else {
        printf("\nVerification: FALSE");
    }

    printf("\nThx for using our airlines! (Is it Jet2 now???)\n");

    // Cleanup
    RabinMessage_clear(message1);
    free(message1);
    FreeKeys(private, public);
    FreeKeys(private_2, public_2);
    gmp_randclear(state);
    mpz_clears(plaintext, ciphertext, decrypted, un_decrypted, signature_1, NULL);

    return 0;
}

//Main func for key generation, stable
void blum_prime(mpz_t p, int bits, gmp_randstate_t state){
    mpz_urandomb(p, state, bits);
    mpz_nextprime(p, p);
    while(mpz_tdiv_ui(p, 4) != 3){
        mpz_nextprime(p,p);
    }
}
//obvious
void RabinMessage_init(RabinMessage* msg) {
    mpz_inits(msg->m, msg->r, msg->x, NULL);
}

//#removekebab
void RabinMessage_clear(RabinMessage* msg) {
    mpz_clears(msg->m, msg->r, msg->x, NULL);
}

//Simple as that, 1 func = 1 purpose
void generate_b(mpz_t b, const mpz_t p, const mpz_t q, const mpz_t n, gmp_randstate_t state){
    mpz_t mod_p, mod_q;
    mpz_init(mod_p);
    mpz_init(mod_q);
    do {
        mpz_urandomm(b, state, n);
        if (mpz_cmp_ui(b, 2) < 0) {
            continue;
        }
        mpz_mod(mod_p, b, p);
        mpz_mod(mod_q, b, q);
        
    } while (mpz_cmp_ui(mod_p, 0) == 0 || mpz_cmp_ui(mod_q, 0) == 0);
    
    mpz_clear(mod_p);
    mpz_clear(mod_q);
}

//Keys generation - fully stable, but may fail at the start due to randstate
void GenerateKeys(RabinPublic **public_key, RabinPrivate **private_key, int bits, gmp_randstate_t state){
    *public_key = malloc(sizeof(RabinPublic));
    *private_key = malloc(sizeof(RabinPrivate));
    
    mpz_inits((*private_key)->p, (*private_key)->q, (*private_key)->b, NULL);
    mpz_inits((*public_key)->n, (*public_key)->b, NULL);
    
    blum_prime((*private_key)->p, bits/2, state);
    blum_prime((*private_key)->q, bits/2, state);
    
    mpz_mul((*public_key)->n, (*private_key)->p, (*private_key)->q);
    generate_b((*private_key)->b, (*private_key)->p, (*private_key)->q, (*public_key)->n, state);
    mpz_set((*public_key)->b, (*private_key)->b);
}

//If we want to input it from keyboard - here, use this, king
void InputKeys(RabinPublic* pub, RabinPrivate* priv, int* key_length){

    int keylen;
    printf("\nEnter key length: ");
    scanf(" %d", &keylen);
    getchar();
    *key_length = keylen;                                       //passed before reassignment
    keylen /= 4;                                                //reassignment: hex len = bit len / 4
    printf("\n");
    char* ext_pub_n = malloc((keylen + 1) * sizeof(char));      //no max len for n
    char* ext_pub_b = malloc((keylen + 1) * sizeof(char));      //no max len for b
    printf("Input public key here: ");
    fgets(ext_pub_n, keylen + 1, stdin);
    getchar();                                                  //clear buffer
    printf("Input b from public key here: ");
    fgets(ext_pub_b, keylen + 1, stdin);
    getchar();                                                  //clear buffer
    //clean the input
    ext_pub_n[strcspn(ext_pub_n, "\n")] = '\0';
    ext_pub_b[strcspn(ext_pub_b, "\n")] = '\0';
    //initialize
    mpz_init_set_str(pub->n, ext_pub_n, 16);                    //only hex is valid
    mpz_init_set_str(pub->b, ext_pub_b, 16);                    //only hex is valid
    mpz_init_set(priv->b, pub->b);
    mpz_inits(priv->p, priv->q, NULL);
    //Cleanup
    free(ext_pub_b);
    free(ext_pub_n);
}

//#remove kebab func
void FreeKeys(RabinPrivate* private_key, RabinPublic* public_key){
    if(private_key){
        mpz_clears(private_key->p, private_key->q, private_key->b, NULL);
        free(private_key);
    }
    if(public_key){
        mpz_clears(public_key->n, public_key->b, NULL);
        free(public_key);
    }
}

//Sometimes we need to get most significant byte, so let`s just do it :)
uint64_t getbyte(const mpz_t x){
    uint64_t res;
    size_t bl = mpz_sizeinbase(x, 2);
    if(bl <= 8){
        res = mpz_get_ui(x);
        return res;
    }
    mpz_t tmp;
    mpz_init_set(tmp, x);
    mpz_tdiv_q_2exp(tmp, tmp, bl - 8);
    res = mpz_get_ui(tmp);

    return res;
}

//Format message 0x00 || 0xFF || m || r || debugged = true
bool format_m(RabinMessage* msg, const mpz_t m, const mpz_t n, gmp_randstate_t state) {
    size_t l = (mpz_sizeinbase(n, 2) + 7) / 8;
    size_t m_bytes = (mpz_sizeinbase(m, 2) + 7) / 8;
    
    if (mpz_cmp_ui(m, 0) == 0) {
        m_bytes = 1;
    }
    
    if (m_bytes > (l - 10)) {
        fprintf(stderr, "Message too long: %zu bytes, max allowed: %zu bytes\n", m_bytes, l - 10);
        return false;
    }
    
    mpz_set(msg->m, m);
    mpz_urandomb(msg->r, state, 64);
    
    mpz_set(msg->x, msg->r);
    
    mpz_t temp;
    mpz_init(temp);
    mpz_mul_2exp(temp, msg->m, 64);
    mpz_add(msg->x, msg->x, temp);
    
    mpz_set_ui(temp, 0xFF);
    mpz_mul_2exp(temp, temp, (l - 2) * 8);
    mpz_add(msg->x, msg->x, temp);
    
    if (mpz_cmp(msg->x, n) >= 0) {
        fprintf(stderr, "Formatted message >= n\n");
        mpz_clear(temp);
        return false;
    }
    mpz_clear(temp);
    return true;
}

//Unpadding: remove r -> remove FF, what`s left is m, debugged = true
bool unformat_m(mpz_t m, const mpz_t x, const mpz_t n){
    mpz_t highest_byte;
    mpz_init(highest_byte);

    mpz_set(m, x);
    mpz_tdiv_q_2exp(m, x, 64);
    size_t l = mpz_sizeinbase(m, 2);        //len without r (save some time, easier division here)
    mpz_tdiv_q_2exp(highest_byte, m, l-8);
    for(size_t bit = l-1; bit >= l - 8; bit--){
        mpz_clrbit(m, bit);
    }
    if(mpz_cmp_ui(highest_byte, 0xFF) != 1){
        return false;
    }
    return true;
}

//Encryption func, debugged = true
void RabinEncrypt(mpz_t y, int* c1, int* c2, const mpz_t x, const RabinPublic* public_key){
    mpz_t tmp1, tmp2;
    mpz_inits(tmp1, tmp2, NULL);
    
    // y = x * (x + b) mod n
    mpz_mul(y, x, x);
    mpz_mul(tmp1, x, public_key->b);
    mpz_add(y, y, tmp1);
    mpz_mod(y, y, public_key->n);
    
    // c1 = ((x + b/2) mod n) mod 2!!! b/2 = b * 2 ^ -1 mod n!!!
    mpz_t inv2, func1;
    mpz_init_set_ui(func1, (uint64_t)2);
    mpz_init(inv2);
    mpz_invert(inv2, func1, public_key->n); //2^-1 !!!
    mpz_mul(tmp2, public_key->b, inv2);     //b * 2^-1
    mpz_mod(tmp2, tmp2, public_key->n);     //mod n
    mpz_add(tmp1, x, tmp2);                 //x + b / 2 or actually x + b * 2^-1
    mpz_mod(tmp2, tmp1, public_key->n);     //mod n
    mpz_mod_ui(tmp2, tmp2, 2);              //mod 2
    *c1 = mpz_tstbit(tmp2, 0);              //finally, dereferencing c1
    
    // c2 = Jacobi(x + b/2, n) == 1 ? 1 : 0
    *c2 = (mpz_jacobi(tmp1, public_key->n) == 1) ? 1 : 0;       //may not be reduced due to Jacobi symbol properties

    mpz_clears(tmp1, tmp2, inv2, func1, NULL);
}

//EEA in terms of gmp functions
void extended_gcd(mpz_t gcd, mpz_t x, mpz_t y, const mpz_t a, const mpz_t b) {
    if (mpz_cmp_ui(b, 0) == 0) {
        mpz_set(gcd, a);
        mpz_set_ui(x, 1);
        mpz_set_ui(y, 0);
        return;
    }
    
    mpz_t x1, y1, q, tmp;
    mpz_inits(x1, y1, q, tmp, NULL);
    
    mpz_tdiv_q(q, a, b);
    mpz_tdiv_r(tmp, a, b);
    
    extended_gcd(gcd, x1, y1, b, tmp);
    
    mpz_set(x, y1);
    mpz_mul(tmp, q, y1);
    mpz_sub(y, x1, tmp);
    
    mpz_clears(x1, y1, q, tmp, NULL);
}

//Decryption func, may propose some bugs, debugged = false
bool RabinDecrypt(mpz_t x, const mpz_t y, int c1, int c2, const RabinPrivate* private_key, const RabinPublic* public_key) {
    mpz_t p, q, n, b;
    mpz_inits(p, q, n, b, NULL);
    mpz_set(p, private_key->p);
    mpz_set(q, private_key->q);
    mpz_set(n, public_key->n);
    mpz_set(b, private_key->b);
    mpz_t b_half, b_squared, t;
    mpz_inits(b_half, b_squared, t, NULL);

    // b_half = b / 2 = b * 2^-1
    mpz_t inv2, inv4, func1, func2;
    mpz_init_set_ui(func1, 2);
    mpz_init_set_ui(func2, 4);
    mpz_inits(inv2, inv4, NULL);

    mpz_invert(inv2, func1, n);
    mpz_invert(inv4, func2, n);

    mpz_mul(b_half, b, inv2);       //b * 2^ (-1)
    mpz_mod(b_half, b_half, n);     //mod n
    // t = y + (b^2)/4 mod n
    mpz_mul(b_squared, b, b);
    mpz_mul(b_squared, b_squared, inv4); //directly: b^2 * 4^-1
    mpz_mod(b_squared, b_squared, n);    //mod n
    mpz_add(t, y, b_squared);
    mpz_mod(t, t, n);


    //sqrt mod n
    mpz_t sp, sq, exp;
    mpz_inits(sp, sq, exp, NULL);

    // sp = t^((p+1)/4) mod p
    mpz_add_ui(exp, p, 1);
    mpz_tdiv_q_ui(exp, exp, 4);         //we have blum primes => we can do this operation without 4^-1 and without residue
    mpz_powm(sp, t, exp, p);

    // sq = t^((q+1)/4) mod q
    mpz_add_ui(exp, q, 1);
    mpz_tdiv_q_ui(exp, exp, 4);         //we have blum primes => we can do this operation without 4^-1 and without residue
    mpz_powm(sq, t, exp, q);

    //EEA: u*p + v*q = 1
    mpz_t u, v, gcd;
    mpz_inits(u, v, gcd, NULL);
    mpz_gcdext(gcd, u, v, p, q);

    //roots, bloody roots z: ±(v*q*sp ± u*p*sq) mod n
    mpz_t z[4], tmp1, tmp2;
    mpz_inits(tmp1, tmp2, NULL);
    for (int i = 0; i < 4; i++)
        mpz_init(z[i]);

    mpz_mul(tmp1, v, q);
    mpz_mul(tmp1, tmp1, sp);  // v*q*sp

    mpz_mul(tmp2, u, p);
    mpz_mul(tmp2, tmp2, sq);  // u*p*sq

    mpz_add(z[0], tmp1, tmp2);   // +v*q*sp + u*p*sq
    mpz_sub(z[1], tmp1, tmp2);   // +v*q*sp - u*p*sq
    mpz_neg(z[2], z[0]);         // -(+v*q*sp + u*p*sq)
    mpz_neg(z[3], z[1]);         // -(+v*q*sp - u*p*sq)

    for (int i = 0; i < 4; i++) {
        mpz_mod(z[i], z[i], n);
    }

    // ✅ x = z - b/2 mod n
    bool found = false;
    mpz_t candidate, check_val;
    mpz_inits(candidate, check_val, NULL);
    uint64_t msb;
    for (int i = 0; i < 4; i++) {
        //x = z - b/2 mod n
        mpz_sub(candidate, z[i], b_half);
        mpz_mod(candidate, candidate, n);
        //Additional bits???
        //(x + b/2) mod n = z[i]
        mpz_add(check_val, candidate, b_half);
        mpz_mod(check_val, check_val, n);      
        int cc1 = mpz_tstbit(check_val, 0);
        int cc2 = (mpz_jacobi(check_val, n) == 1) ? 1 : 0;
        gmp_printf("\nChecking root: %ZX, c1 = %d, c2 = %d", candidate, cc1, cc2);  
        msb = getbyte(candidate);
        if (cc1 == c1 && cc2 == c2 && msb == 255) {         //third condition: correct padding
            mpz_set(x, candidate);
            found = true;
            break;
        }
    }
    if(!found){
        mpz_set_ui(x, 0ULL);
        printf("Correct root not found, sorry\n");
    }
    // Cleanup
    for (int i = 0; i < 4; i++) mpz_clear(z[i]);
    mpz_clears(b_half, b_squared, t, sp, sq, exp, u, v, gcd, tmp1, tmp2, candidate, check_val, p, q, n, b, func1, func2, inv2, inv4, NULL);

    return found;
}

//Sign message - to add only signature, debugged = true
bool RabinSign(mpz_t signature, int* s1, int* s2, const mpz_t message, const RabinPrivate* private_key, const RabinPublic* public_key, gmp_randstate_t state) {
    RabinMessage msg;
    RabinMessage_init(&msg);
    
    mpz_t x_formatted;
    mpz_init(x_formatted);
    
    //Max formatting attempts, let`s go
    int max_attempts = 128;
    bool is_qr = false;
    
    for(int attempt = 0; attempt < max_attempts; attempt++) {
        //Format message
        if(!format_m(&msg, message, public_key->n, state)) {
            RabinMessage_clear(&msg);
            mpz_clear(x_formatted);
            return false;
        }
        
        mpz_set(x_formatted, msg.x);
        
        //LGNDR, JCB
        int legendre_p = mpz_legendre(x_formatted, private_key->p);
        int legendre_q = mpz_legendre(x_formatted, private_key->q);
        
        if(legendre_p == 1 && legendre_q == 1) {
            is_qr = true;
            break;
        }
        //Is not => goto
    }
    
    if(!is_qr) {
        fprintf(stderr, "Could not find quadratic residue after %d attempts\n", max_attempts);
        RabinMessage_clear(&msg);
        mpz_clear(x_formatted);
        return false;
    }
    
    //quadratic residues
    mpz_t sp, sq, exp, u, v, gcd;
    mpz_inits(sp, sq, exp, u, v, gcd, NULL);
    
    // sp = x^((p+1)/4) mod p
    mpz_add_ui(exp, private_key->p, 1);
    mpz_tdiv_q_ui(exp, exp, 4);
    mpz_powm(sp, x_formatted, exp, private_key->p);
    
    // sq = x^((q+1)/4) mod q
    mpz_add_ui(exp, private_key->q, 1);
    mpz_tdiv_q_ui(exp, exp, 4);
    mpz_powm(sq, x_formatted, exp, private_key->q);
    
    //EEA (Bezout) u*p + v*q = 1
    mpz_gcdext(gcd, u, v, private_key->p, private_key->q);
    
    //4 square roots (Kytais`ka theorema pro lyshky tryastsya) s = ±(v*q*sp ± u*p*sq) mod n
    mpz_t roots[4], tmp1, tmp2;
    mpz_inits(tmp1, tmp2, NULL);
    for(int i = 0; i < 4; i++)
        mpz_init(roots[i]);
    
    mpz_mul(tmp1, v, private_key->q);
    mpz_mul(tmp1, tmp1, sp);  // v*q*sp
    
    mpz_mul(tmp2, u, private_key->p);
    mpz_mul(tmp2, tmp2, sq);  // u*p*sq
    
    mpz_add(roots[0], tmp1, tmp2);   // +v*q*sp + u*p*sq
    mpz_sub(roots[1], tmp1, tmp2);   // +v*q*sp - u*p*sq
    mpz_neg(roots[2], roots[0]);     // -v*q*sp - u*p*sq
    mpz_neg(roots[3], roots[1]);     // -v*q*sp + u*p*sq
    
    for(int i = 0; i < 4; i++) {
        mpz_mod(roots[i], roots[i], public_key->n);
    }
    
    //Generate num for choice
    unsigned long random_choice = gmp_urandomm_ui(state, 4);
    mpz_set(signature, roots[random_choice]);
    
    //We need additional nums?:
    mpz_t b_half, check;
    mpz_inits(b_half, check, NULL);
    
    mpz_tdiv_q_ui(b_half, private_key->b, 2);
    mpz_add(check, signature, b_half);
    mpz_mod(check, check, public_key->n);
    
    *s1 = mpz_tstbit(check, 0);
    *s2 = (mpz_jacobi(check, public_key->n) == 1) ? 1 : 0;
    
    // Cleanup
    for(int i = 0; i < 4; i++)
        mpz_clear(roots[i]);
    mpz_clears(sp, sq, exp, u, v, gcd, tmp1, tmp2, b_half, check, x_formatted, NULL);
    RabinMessage_clear(&msg);
    return true;
}

//Verify message, debugged = true
bool RabinVerify(const mpz_t message, const mpz_t signature, int s1, int s2, const RabinPublic* public_key) {
    (void)s1;
    (void)s2;

    mpz_t x;
    mpz_init(x);

    // x' = s^2 mod n
    mpz_mul(x, signature, signature);
    mpz_mod(x, x, public_key->n);

    // unformat(x') -> m'
    mpz_t recovered;
    mpz_init(recovered);

    unformat_m(recovered, x, public_key->n);
    //gmp_printf("\nunpadding issue brother. sorry, current is: %ZX", recovered);

    // m' == m ?
    bool ok = (mpz_cmp(recovered, message) == 0);
    gmp_printf("\nJust so we could compare\n%ZX\n%ZX", message, recovered);

    mpz_clears(x, recovered, NULL);
    return ok;
} //hehe boi, exactly 666)))

//just so it won`t be 666 lines program xD