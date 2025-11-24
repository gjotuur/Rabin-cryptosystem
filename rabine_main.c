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

void GenerateKeys(RabinPublic **public_key, RabinPrivate **private_key, int bits, gmp_randstate_t state);       //Generate keys and immediately save them in structure
void FreeKeys(RabinPrivate* private_key, RabinPublic* public_key);                                              //Clear keys
void format_m(mpz_t x, const mpz_t m, const mpz_t n, gmp_randstate_t state);                                    //Format message
void unformat_m(mpz_t m, const mpz_t x, const mpz_t n);                                                         //Unformat message

int main(){
    RabinPrivate* private = NULL;
    RabinPublic* public = NULL;

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    GenerateKeys(&public, &private, 256, state);

    gmp_printf("Public key:\nn = %ZX\nb = %ZX", public->n, public->b);
    gmp_printf("\nPrivate key:\np = %ZX\nq = %ZX\nb = %ZX\n", private->p, private->q, private->b);

    mpz_t some_message;
    mpz_init_set_str(some_message, "48656C6C6F20526162696E21", 16);
    mpz_t initial_x;
    format_m(initial_x, some_message, public->n, state);

    gmp_printf("Formatted 48656C6C6F20526162696E21 is:\n%ZX", initial_x);
    mpz_t unformatted_m;
    unformat_m(unformatted_m, initial_x, public->n);

    gmp_printf("\nUnformatted: %ZX", unformatted_m);

    FreeKeys(private, public);
    gmp_randclear(state);
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
void format_m(mpz_t x, const mpz_t m, const mpz_t n, gmp_randstate_t state){
    size_t n_bit_length = (mpz_sizeinbase(n, 2) + 7) / 8;

    size_t message_length = (mpz_sizeinbase(m, 2) + 7) / 8;
    if (message_length > n_bit_length - 10) {
        fprintf(stderr, "Too long.");
        return;
    }
    //Gen_r
    mpz_t r, temp, power;
    mpz_inits(r, temp, power, NULL);
    mpz_urandomb(r, state, 64);
    
    mpz_set(x, r);
    
    //+2^64 * m
    mpz_ui_pow_ui(power, 2, 64);
    mpz_mul(temp, m, power);
    mpz_add(x, x, temp);
    //+255*2^(l-2)
    mpz_ui_pow_ui(power, 2, 8 * (n_bit_length - 2));
    mpz_mul_ui(temp, power, 255);
    mpz_add(x, x, temp);
    //#remove_kebab
    mpz_clears(r, temp, power, NULL);
}

//Not sure it will work, hehe
void unformat_m(mpz_t m, const mpz_t x, const mpz_t n) {
    size_t l = (mpz_sizeinbase(n, 2) + 7) / 8;
    
    mpz_t temp, mask, power;
    mpz_inits(temp, mask, power, NULL);
    
    mpz_ui_pow_ui(power, 2, 8 * (l - 2));
    mpz_tdiv_q(temp, x, power);
    mpz_tdiv_r_ui(temp, temp, 256);
    
    if (mpz_cmp_ui(temp, 255) != 0) {
        fprintf(stderr, "Message was unformatted");
        mpz_clears(temp, mask, power, NULL);
        return;
    }
    
    mpz_ui_pow_ui(power, 2, 64);
    mpz_tdiv_q(temp, x, power);
    
    mpz_ui_pow_ui(mask, 2, 8 * (l - 10));
    mpz_tdiv_r(m, temp, mask);
    
    mpz_clears(temp, mask, power, NULL);
}