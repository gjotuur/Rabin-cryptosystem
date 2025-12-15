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
}RabinPublic;

typedef struct{
    mpz_t p;
    mpz_t q;
    mpz_t b;
}RabinPrivate;

typedef struct{
    mpz_t m;
    mpz_t r;
    mpz_t x;
}RabinMessage;

// Keys generation
void GenerateKeys(RabinPublic **public_key, RabinPrivate **private_key, int bits, gmp_randstate_t state);
void InputKeys(RabinPublic* pub, RabinPrivate* priv, int* key_length);                                                       //memory allocation - outside of func
void FreeKeys(RabinPrivate* private_key, RabinPublic* public_key);

// Message formatting
void RabinMessage_init(RabinMessage* m);
void RabinMessage_clear(RabinMessage* m);
bool format_m(RabinMessage* msg, const mpz_t m, const mpz_t n, gmp_randstate_t state);
bool unformat_m(mpz_t m, const mpz_t x, const mpz_t n);

// Encryption/Decryption
void RabinEncrypt(mpz_t y, int* c1, int* c2, const mpz_t x, const RabinPublic* public_key);
bool RabinDecrypt(mpz_t x, const mpz_t y, int c1, int c2, const RabinPrivate* private_key, const RabinPublic* public_key);

// Signing/Verification
bool RabinSign(mpz_t signature, int* s1, int* s2, const mpz_t message, const RabinPrivate* private_key, const RabinPublic* public_key, gmp_randstate_t state);
bool RabinVerify(const mpz_t message, const mpz_t signature, int s1, int s2, const RabinPublic* public_key);

int main(){
    RabinPrivate* private = malloc(sizeof(RabinPrivate));
    RabinPublic* public = malloc(sizeof(RabinPublic));

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    int keylen;
    bool sw1;
    printf("\nAsymCrypto Lab#3: Rabin cryptosystem.\nSo it begins.\nEnter mode: 1 to input keys, 0 to generate keys\nYour answer: ");
    scanf(" %d", &sw1);
    getchar();
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
    
    gmp_printf("\nCurrent keys\n");
    gmp_printf("Public key:\nn = %Zx\nb = %Zx\n", public->n, public->b);
    gmp_printf("Private key:\np = %Zx\nq = %Zx\nb = %Zx\n", private->p, private->q, private->b);

    // Тест шифрування/дешифрування
    printf("\nEncrypt / Decrypt\n");
    RabinMessage* message1 = malloc(sizeof(RabinMessage));
    RabinMessage_init(message1);

    mpz_t plaintext;
    mpz_init_set_str(plaintext, "76 6c 61 64 79 6b 61 72 65 61 6c 6e 6f 73 74 69", 16); // "vladykarealnosti"
    gmp_printf("Plaintext: %Zx (vladykarealnosti)\n", plaintext);

    if(!format_m(message1, plaintext, public->n, state)) {
        fprintf(stderr, "Padding error\n");
        return 1;
    }
    gmp_printf("Formatted x: %Zx\n", message1->x);

    mpz_t ciphertext;
    mpz_init(ciphertext);
    int c1, c2;
    RabinEncrypt(ciphertext, &c1, &c2, message1->x, public);
    gmp_printf("Encrypted y: %Zx\nc1=%d, c2=%d\n", ciphertext, c1, c2);



    // Cleanup
    RabinMessage_clear(message1);
    free(message1);
    FreeKeys(NULL, public);
    gmp_randclear(state);
    mpz_clears(plaintext, ciphertext, /*decrypted_x signature , test_msg,*/ NULL);

    return 0;
}

void blum_prime(mpz_t p, int bits, gmp_randstate_t state){
    mpz_urandomb(p, state, bits);
    mpz_nextprime(p, p);
    while(mpz_tdiv_ui(p, 4) != 3){
        mpz_nextprime(p,p);
    }
}

void RabinMessage_init(RabinMessage* msg) {
    mpz_inits(msg->m, msg->r, msg->x, NULL);
}

void RabinMessage_clear(RabinMessage* msg) {
    mpz_clears(msg->m, msg->r, msg->x, NULL);
}

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
    
    mpz_inits((*private_key)->p, (*private_key)->q, (*private_key)->b, NULL);
    mpz_inits((*public_key)->n, (*public_key)->b, NULL);
    
    blum_prime((*private_key)->p, bits/2, state);
    blum_prime((*private_key)->q, bits/2, state);
    
    mpz_mul((*public_key)->n, (*private_key)->p, (*private_key)->q);
    generate_b((*private_key)->b, (*private_key)->p, (*private_key)->q, (*public_key)->n, state);
    mpz_set((*public_key)->b, (*private_key)->b);
}

//If we want to input it from keyboard - here, use this king
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

bool unformat_m(mpz_t m, const mpz_t x, const mpz_t n) {
    size_t l = (mpz_sizeinbase(n, 2) + 7) / 8;

    mpz_t tmp;
    mpz_init(tmp);

    // Перевірка старшого байту на 0xFF
    mpz_tdiv_q_2exp(tmp, x, 8 * (l - 1));
    if (mpz_cmp_ui(tmp, 0xFF) != 0) {
        fprintf(stderr, "Invalid padding: expected 0xFF, got ");
        gmp_fprintf(stderr, "%Zx\n", tmp);
        mpz_clear(tmp);
        return false;
    }

    // tmp = m || r (все крім старшого байту)
    mpz_tdiv_r_2exp(tmp, x, 8 * (l - 1));

    // m = (m || r) >> 64
    mpz_tdiv_q_2exp(m, tmp, 64);

    mpz_clear(tmp);
    return true;
}

void RabinEncrypt(mpz_t y, int* c1, int* c2, const mpz_t x, const RabinPublic* public_key){
    mpz_t tmp1, tmp2;
    mpz_inits(tmp1, tmp2, NULL);
    
    // y = x * (x + b) mod n
    mpz_mul(y, x, x);
    mpz_mul(tmp1, x, public_key->b);
    mpz_add(y, y, tmp1);
    mpz_mod(y, y, public_key->n);
    
    // c1 = ((x + b/2) mod n) mod 2
    mpz_tdiv_q_ui(tmp2, public_key->b, 2);
    mpz_add(tmp1, x, tmp2);
    mpz_mod(tmp2, tmp1, public_key->n);
    mpz_mod_ui(tmp2, tmp2, 2);
    *c1 = mpz_tstbit(tmp2, 0);
    
    // c2 = Jacobi(x + b/2, n) == 1 ? 1 : 0
    *c2 = (mpz_jacobi(tmp1, public_key->n) == 1) ? 1 : 0;

    mpz_clears(tmp1, tmp2, NULL);
}

// Розширений алгоритм Евкліда для обчислення оберненого за модулем
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

bool RabinDecrypt(mpz_t x, const mpz_t y, int c1, int c2, const RabinPrivate* private_key, const RabinPublic* public_key) {
    mpz_t mp, mq, yp, yq, temp, b_half;
    mpz_inits(mp, mq, yp, yq, temp, b_half, NULL);
    
    // b/2
    mpz_tdiv_q_ui(b_half, private_key->b, 2);
    
    // yp = y mod p, yq = y mod q
    mpz_mod(yp, y, private_key->p);
    mpz_mod(yq, y, private_key->q);
    
    // mp = yp^((p+1)/4) mod p
    mpz_add_ui(temp, private_key->p, 1);
    mpz_tdiv_q_ui(temp, temp, 4);
    mpz_powm(mp, yp, temp, private_key->p);
    
    // mq = yq^((q+1)/4) mod q
    mpz_add_ui(temp, private_key->q, 1);
    mpz_tdiv_q_ui(temp, temp, 4);
    mpz_powm(mq, yq, temp, private_key->q);
    
    // Китайська теорема про залишки для 4 варіантів
    mpz_t yp_inv, yq_inv, r1, r2, r3, r4;
    mpz_inits(yp_inv, yq_inv, r1, r2, r3, r4, NULL);
    
    // yp_inv = p^(-1) mod q
    mpz_invert(yp_inv, private_key->p, private_key->q);
    // yq_inv = q^(-1) mod p
    mpz_invert(yq_inv, private_key->q, private_key->p);
    
    // r1 = (yp_inv * p * mq + yq_inv * q * mp) mod n
    mpz_mul(r1, yp_inv, private_key->p);
    mpz_mul(r1, r1, mq);
    mpz_mul(temp, yq_inv, private_key->q);
    mpz_mul(temp, temp, mp);
    mpz_add(r1, r1, temp);
    mpz_mod(r1, r1, public_key->n);
    
    // r2 = (yp_inv * p * mq - yq_inv * q * mp) mod n
    mpz_mul(r2, yp_inv, private_key->p);
    mpz_mul(r2, r2, mq);
    mpz_mul(temp, yq_inv, private_key->q);
    mpz_mul(temp, temp, mp);
    mpz_sub(r2, r2, temp);
    mpz_mod(r2, r2, public_key->n);
    
    // r3 = n - r1
    mpz_sub(r3, public_key->n, r1);
    
    // r4 = n - r2
    mpz_sub(r4, public_key->n, r2);
    
    // Вибираємо правильний корінь за допомогою c1 та c2
    mpz_t roots[4];
    mpz_init_set(roots[0], r1);
    mpz_init_set(roots[1], r2);
    mpz_init_set(roots[2], r3);
    mpz_init_set(roots[3], r4);
    
    bool found = false;
    for(int i = 0; i < 4; i++) {
        // Перевірка c1: ((root + b/2) mod n) mod 2
        mpz_add(temp, roots[i], b_half);
        mpz_mod(temp, temp, public_key->n);
        int check_c1 = mpz_tstbit(temp, 0);
        
        // Перевірка c2: Jacobi(root + b/2, n)
        int check_c2 = (mpz_jacobi(temp, public_key->n) == 1) ? 1 : 0;
        
        if(check_c1 == c1 && check_c2 == c2) {
            mpz_set(x, roots[i]);
            found = true;
            break;
        }
    }
    
    for(int i = 0; i < 4; i++) {
        mpz_clear(roots[i]);
    }
    mpz_clears(mp, mq, yp, yq, temp, b_half, yp_inv, yq_inv, r1, r2, r3, r4, NULL);
    
    return found;
}

bool RabinSign(mpz_t signature, int* s1, int* s2, const mpz_t message, const RabinPrivate* private_key, const RabinPublic* public_key, gmp_randstate_t state) {
    RabinMessage msg;
    RabinMessage_init(&msg);
    
    // Форматуємо повідомлення
    if(!format_m(&msg, message, public_key->n, state)) {
        RabinMessage_clear(&msg);
        return false;
    }
    
    // Підпис - це розв'язок рівняння s(s+b) ≡ x (mod n)
    // Використовуємо той самий алгоритм що й для дешифрування
    mpz_t mp, mq, xp, xq, temp, b_half;
    mpz_inits(mp, mq, xp, xq, temp, b_half, NULL);
    
    mpz_tdiv_q_ui(b_half, private_key->b, 2);
    
    mpz_mod(xp, msg.x, private_key->p);
    mpz_mod(xq, msg.x, private_key->q);
    
    // mp = xp^((p+1)/4) mod p
    mpz_add_ui(temp, private_key->p, 1);
    mpz_tdiv_q_ui(temp, temp, 4);
    mpz_powm(mp, xp, temp, private_key->p);
    
    // mq = xq^((q+1)/4) mod q
    mpz_add_ui(temp, private_key->q, 1);
    mpz_tdiv_q_ui(temp, temp, 4);
    mpz_powm(mq, xq, temp, private_key->q);
    
    // CRT
    mpz_t yp_inv, yq_inv;
    mpz_inits(yp_inv, yq_inv, NULL);
    
    mpz_invert(yp_inv, private_key->p, private_key->q);
    mpz_invert(yq_inv, private_key->q, private_key->p);
    
    mpz_mul(signature, yp_inv, private_key->p);
    mpz_mul(signature, signature, mq);
    mpz_mul(temp, yq_inv, private_key->q);
    mpz_mul(temp, temp, mp);
    mpz_add(signature, signature, temp);
    mpz_mod(signature, signature, public_key->n);
    
    // Обчислюємо s1 та s2
    mpz_add(temp, signature, b_half);
    mpz_mod(temp, temp, public_key->n);
    *s1 = mpz_tstbit(temp, 0);
    *s2 = (mpz_jacobi(temp, public_key->n) == 1) ? 1 : 0;
    
    mpz_clears(mp, mq, xp, xq, temp, b_half, yp_inv, yq_inv, NULL);
    RabinMessage_clear(&msg);
    
    return true;
}

bool RabinVerify(const mpz_t message, const mpz_t signature, int s1, int s2, const RabinPublic* public_key) {
    mpz_t computed_y, temp, b_half, formatted_msg;
    mpz_inits(computed_y, temp, b_half, formatted_msg, NULL);
    
    // Обчислюємо y = signature * (signature + b) mod n
    mpz_mul(computed_y, signature, signature);
    mpz_mul(temp, signature, public_key->b);
    mpz_add(computed_y, computed_y, temp);
    mpz_mod(computed_y, computed_y, public_key->n);
    
    // Перевіряємо s1 та s2
    mpz_tdiv_q_ui(b_half, public_key->b, 2);
    mpz_add(temp, signature, b_half);
    mpz_mod(temp, temp, public_key->n);
    
    int check_s1 = mpz_tstbit(temp, 0);
    int check_s2 = (mpz_jacobi(temp, public_key->n) == 1) ? 1 : 0;
    
    if(check_s1 != s1 || check_s2 != s2) {
        mpz_clears(computed_y, temp, b_half, formatted_msg, NULL);
        return false;
    }
    
    // Розформатовуємо computed_y та порівнюємо з повідомленням
    mpz_t recovered_msg;
    mpz_init(recovered_msg);
    
    if(!unformat_m(recovered_msg, computed_y, public_key->n)) {
        mpz_clears(computed_y, temp, b_half, formatted_msg, recovered_msg, NULL);
        return false;
    }
    
    bool result = (mpz_cmp(recovered_msg, message) == 0);
    
    mpz_clears(computed_y, temp, b_half, formatted_msg, recovered_msg, NULL);
    return result;
}