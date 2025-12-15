#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <gmp.h>

typedef struct{
    mpz_t n;
    mpz_t b;
}RabinPublic; //sole purpose - not to save it as an array

typedef struct{
    mpz_t p;
    mpz_t q;
    mpz_t b;
}RabinPrivate; //sole purpose - not to save it as an array

typedef struct{
    mpz_t m;        //Plain text
    mpz_t r;        //RNG-based boi
    mpz_t x;        //Ciphertext we get
}RabinMessage;      //We`re saving all states of 1 message in 1 struct, just so we can access it whenever we need

//Keys generation
void GenerateKeys(RabinPublic **public_key, RabinPrivate **private_key, int bits, gmp_randstate_t state);       //Generate keys and immediately save them in structure
void FreeKeys(RabinPrivate* private_key, RabinPublic* public_key);                                              //Clear keys

//Message formatting (padding) + usage of struct
void RabinMessage_init(RabinMessage* m);
void RabinMessage_clear(RabinMessage* m);
bool format_m(RabinMessage* msg, const mpz_t m, const mpz_t n, gmp_randstate_t state);                          //Format message, bool to check if it is formatted or no
bool unformat_m(mpz_t m, const mpz_t x, const mpz_t n);                                                         //Unformat message, same as format with struct


void RabinEncrypt(mpz_t y, int* c1, int* c2, const mpz_t x, const RabinPublic* public_key);                     //Encryption, message MUST be formatted BEFORE encrypting it
void RabinDecrypt(mpz_t ciphertext, int c1, int c2);
void RabinSign();
void RabinVerify();

int main(){
    RabinPrivate* private = NULL;
    RabinPublic* public = NULL;

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    GenerateKeys(&public, &private, 256, state);

    gmp_printf("Public key:\nn = %ZX\nb = %ZX", public->n, public->b);
    gmp_printf("\nPrivate key:\np = %ZX\nq = %ZX\nb = %ZX\n", private->p, private->q, private->b);

    RabinMessage* message1 = malloc(sizeof(RabinMessage));
    RabinMessage_init(message1);

    mpz_t plaintext;
    mpz_init_set_str(plaintext, "48656C6C6F20526162696E21", 16);

    format_m(message1, plaintext, public->n, state);
    gmp_printf("\nFormatted message 48656C6C6F20526162696E21 with our key is %ZX", message1->x);

    mpz_t test_y;
    mpz_init(test_y);
    int c1, c2;
    RabinEncrypt(test_y, &c1, &c2, message1->x, public);
    gmp_printf("\nEncrypted message is %ZX\nc1 is %d\nc2 is %d", test_y, c1, c2);

    RabinMessage_clear(message1);
    FreeKeys(private, public);
    gmp_randclear(state);
    mpz_clears(plaintext, test_y, NULL);

    return 0;
}

//Generate prime and check is it Bloom, if not - generate next prime
void blum_prime(mpz_t p, int bits, gmp_randstate_t state){
    mpz_urandomb(p, state, bits);
    mpz_nextprime(p, p);
    while(mpz_tdiv_ui(p, 4) != 3){
        mpz_nextprime(p,p);
    }
}

//Initialize message to fill it with plain- or ciphertext
void RabinMessage_init(RabinMessage* msg) {
    mpz_inits(msg->m, msg->r, msg->x, NULL);
}

void RabinMessage_clear(RabinMessage* msg) {
    mpz_clears(msg->m, msg->r, msg->x, NULL);
}

//Generation of b, which is needed for the extended scheme
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

void GenerateKeys(RabinPublic **public_key, RabinPrivate **private_key, int bits, gmp_randstate_t state){
    *public_key = malloc(sizeof(RabinPublic));
    *private_key = malloc(sizeof(RabinPrivate));
    //Init
    mpz_inits((*private_key)->p, (*private_key)->q, (*private_key)->b, NULL);
    mpz_inits((*public_key)->n, (*public_key)->b, NULL);
    //Generation
    blum_prime((*private_key)->p, bits/2, state);
    blum_prime((*private_key)->q, bits/2, state);
    //b and public key
    mpz_mul((*public_key)->n, (*private_key)->p, (*private_key)->q);
    generate_b((*private_key)->b, (*private_key)->p, (*private_key)->q, (*public_key)->n, state);
    mpz_set((*public_key)->b, (*private_key)->b);
}

//Just another #remove_kebab function
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

//Format message. Formula in CP was wrong, but scheme was not => done using scheme, not formula.
bool format_m(RabinMessage* msg, const mpz_t m, const mpz_t n, gmp_randstate_t state) {
    size_t l = (mpz_sizeinbase(n, 2) + 7) / 8;
    size_t m_bytes = (mpz_sizeinbase(m, 2) + 7) / 8;
    
    if (mpz_cmp_ui(m, 0) == 0) {
        m_bytes = 1;
    }
    
    if (m_bytes > (l - 10)) {
        fprintf(stderr, "Message too long: %zu bytes, max allowed: %zu bytes\n", 
                m_bytes, l - 10);
        return false;
    }
    
    mpz_set(msg->m, m);
    mpz_urandomb(msg->r, state, 64);

    //x = 0x00 || 0xFF || padding || m || r
    mpz_set(msg->x, msg->r);
    
    mpz_t temp;
    mpz_init(temp);
    
    mpz_mul_2exp(temp, msg->m, 64);
    mpz_add(msg->x, msg->x, temp);
    
    mpz_set_ui(temp, 0xFF);
    mpz_mul_2exp(temp, temp, (l - 2) * 8);
    mpz_add(msg->x, msg->x, temp);
    
    mpz_set_ui(temp, 0x00);
    mpz_mul_2exp(temp, temp, (l - 1) * 8);
    mpz_add(msg->x, msg->x, temp);
    
    if (mpz_cmp(msg->x, n) >= 0) {
        fprintf(stderr, "Formatted message >= n\n");
        mpz_clear(temp);
        return false;
    }
    
    mpz_clear(temp);
    return true;
}

//Not sure it will work, hehe
bool unformat_m(mpz_t m, const mpz_t x, const mpz_t n) {
    size_t l = (mpz_sizeinbase(n, 2) + 7) / 8;

    mpz_t tmp;
    mpz_init(tmp);

    // High byte == 0xFF ? (ok) : (gtfo ricer)
    mpz_tdiv_q_2exp(tmp, x, 8 * (l - 1));
    if (mpz_cmp_ui(tmp, 0xFF) != 0) {
        fprintf(stderr, "Invalid padding (missing 0xFF)\n");
        mpz_clear(tmp);
        return false;
    }

    mpz_tdiv_r_2exp(tmp, x, 8 * (l - 1));

    mpz_tdiv_q_2exp(m, tmp, 64);

    mpz_clear(tmp);
    return true;
}


//Fuck formatting, fuck padding, fuck everything
void RabinEncrypt(mpz_t y, int* c1, int* c2, const mpz_t x, const RabinPublic* public_key){
    mpz_t tmp1, tmp2;
    //y = x * (x + b) mod n, b = public_key->b, n = public_key->n
    mpz_inits(tmp1, tmp2, NULL);
    mpz_mul(y, x, x);
    mpz_mul(tmp1, x, public_key->b);
    mpz_add(y, y, tmp1);
    mpz_mod(y, y, public_key->n);
    //c1 = ((x+b/2)mod n)mod2
    mpz_tdiv_q_ui(tmp2, public_key->b, 2);
    mpz_add(tmp1, x, tmp2); //SAVE TMP1 FOR FURTHER CALCULATIONS
    mpz_mod(tmp2, tmp1, public_key->n);
    mpz_mod_ui(tmp2, tmp2, 2);
    *c1 = mpz_tstbit(tmp2, 0);
    *c2 = (mpz_jacobi(tmp1, public_key->n) == 1) ? 1 : 0;

    mpz_clears(tmp1, tmp2, NULL);
}