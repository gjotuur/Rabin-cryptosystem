#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>

// Структури для ключів
typedef struct {
    mpz_t n;  // Відкритий ключ (n = p * q)
    mpz_t b;  // Додатковий параметр для розширеної схеми
} PublicKey;

typedef struct {
    mpz_t p;  // Перше просте число Блюма
    mpz_t q;  // Друге просте число Блюма
    mpz_t n;  // n = p * q
    mpz_t b;  // Додатковий параметр
} PrivateKey;

// Структура для шифротексту
typedef struct {
    mpz_t y;
    int c1;  // Біт парності
    int c2;  // Символ Якобі
} Ciphertext;

// Ініціалізація ключів
void init_public_key(PublicKey *pk) {
    mpz_init(pk->n);
    mpz_init(pk->b);
}

void init_private_key(PrivateKey *sk) {
    mpz_init(sk->p);
    mpz_init(sk->q);
    mpz_init(sk->n);
    mpz_init(sk->b);
}

void clear_public_key(PublicKey *pk) {
    mpz_clear(pk->n);
    mpz_clear(pk->b);
}

void clear_private_key(PrivateKey *sk) {
    mpz_clear(sk->p);
    mpz_clear(sk->q);
    mpz_clear(sk->n);
    mpz_clear(sk->b);
}

void init_ciphertext(Ciphertext *ct) {
    mpz_init(ct->y);
    ct->c1 = 0;
    ct->c2 = 0;
}

void clear_ciphertext(Ciphertext *ct) {
    mpz_clear(ct->y);
}

// Функція для генерування простого числа Блюма (p ≡ 3 (mod 4))
void generate_blum_prime(mpz_t result, gmp_randstate_t state, int bits) {
    mpz_t temp, four, three;
    mpz_init(temp);
    mpz_init(four);
    mpz_init(three);
    
    mpz_set_ui(four, 4);
    mpz_set_ui(three, 3);
    
    do {
        // Генеруємо випадкове число
        mpz_urandomb(result, state, bits);
        mpz_setbit(result, bits - 1);  // Встановлюємо старший біт
        mpz_setbit(result, 0);  // Робимо непарним
        
        // Перевіряємо, чи є число простим
        if (mpz_probab_prime_p(result, 25) > 0) {
            // Перевіряємо, чи p ≡ 3 (mod 4)
            mpz_mod(temp, result, four);
            if (mpz_cmp(temp, three) == 0) {
                break;
            }
        }
    } while (1);
    
    mpz_clear(temp);
    mpz_clear(four);
    mpz_clear(three);
}

// Обчислення символу Якобі
int jacobi_symbol(mpz_t a, mpz_t n) {
    return mpz_jacobi(a, n);
}

// Генерування пари ключів
void GenerateKeyPair(PublicKey *pk, PrivateKey *sk, int bits) {
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL));
    
    printf("Генерування простих чисел Блюма...\n");
    
    // Генеруємо два прості числа Блюма
    generate_blum_prime(sk->p, state, bits / 2);
    printf("p згенеровано\n");
    
    generate_blum_prime(sk->q, state, bits / 2);
    printf("q згенеровано\n");
    
    // Обчислюємо n = p * q
    mpz_mul(sk->n, sk->p, sk->q);
    mpz_set(pk->n, sk->n);
    
    // Генеруємо випадкове b
    mpz_urandomm(sk->b, state, sk->n);
    mpz_set(pk->b, sk->b);
    
    gmp_randclear(state);
    
    printf("Ключі успішно згенеровані!\n");
}

// Форматування повідомлення
void format_message(mpz_t x, const unsigned char *msg, size_t msg_len, mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL) + rand());
    
    // Генеруємо випадкове 64-бітове число r
    mpz_t r;
    mpz_init(r);
    mpz_urandomb(r, state, 64);
    
    // Формуємо x = 0xFF || 0x00 || m || r
    mpz_set_ui(x, 0xFF);
    mpz_mul_2exp(x, x, 8);  // Зсув на 8 біт
    
    mpz_mul_2exp(x, x, 8);  // 0x00
    
    // Додаємо повідомлення
    for (size_t i = 0; i < msg_len; i++) {
        mpz_mul_2exp(x, x, 8);
        mpz_add_ui(x, x, msg[i]);
    }
    
    // Додаємо r
    mpz_mul_2exp(x, x, 64);
    mpz_add(x, x, r);
    
    mpz_clear(r);
    gmp_randclear(state);
}

// Перевірка форматування
int check_format(mpz_t x) {
    mpz_t temp;
    mpz_init(temp);
    
    size_t bits = mpz_sizeinbase(x, 2);
    
    // Перевіряємо перші байти (0xFF || 0x00)
    mpz_tdiv_q_2exp(temp, x, bits - 16);
    int result = (mpz_cmp_ui(temp, 0xFF00) == 0);
    
    mpz_clear(temp);
    return result;
}

// Видалення форматування
void unformat_message(unsigned char *msg, size_t *msg_len, mpz_t x) {
    mpz_t temp;
    mpz_init(temp);
    
    // Видаляємо 64 біти r
    mpz_tdiv_q_2exp(temp, x, 64);
    
    // Отримуємо байти повідомлення
    size_t count = (mpz_sizeinbase(temp, 2) - 16 + 7) / 8;  // -16 для 0xFF00
    
    mpz_tdiv_q_2exp(temp, temp, 16);  // Видаляємо 0xFF00
    
    *msg_len = count;
    mpz_export(msg, NULL, 1, 1, 1, 0, temp);
    
    mpz_clear(temp);
}

// Швидке обчислення квадратних коренів за модулем Блюма
void compute_square_roots(mpz_t roots[4], mpz_t y, mpz_t p, mpz_t q, mpz_t n) {
    mpz_t s1, s2, u, v, gcd_val, temp1, temp2, exp_p, exp_q;
    mpz_init(s1);
    mpz_init(s2);
    mpz_init(u);
    mpz_init(v);
    mpz_init(gcd_val);
    mpz_init(temp1);
    mpz_init(temp2);
    mpz_init(exp_p);
    mpz_init(exp_q);
    
    // Обчислюємо s1 = y^((p+1)/4) mod p
    mpz_add_ui(exp_p, p, 1);
    mpz_tdiv_q_2exp(exp_p, exp_p, 2);
    mpz_powm(s1, y, exp_p, p);
    
    // Обчислюємо s2 = y^((q+1)/4) mod q
    mpz_add_ui(exp_q, q, 1);
    mpz_tdiv_q_2exp(exp_q, exp_q, 2);
    mpz_powm(s2, y, exp_q, q);
    
    // Розширений алгоритм Евкліда: u*p + v*q = 1
    mpz_gcdext(gcd_val, u, v, p, q);
    
    // Обчислюємо чотири корені: x = ±(v*q*s1 + u*p*s2) mod n
    mpz_mul(temp1, v, q);
    mpz_mul(temp1, temp1, s1);
    
    mpz_mul(temp2, u, p);
    mpz_mul(temp2, temp2, s2);
    
    // Корінь 1: + +
    mpz_add(roots[0], temp1, temp2);
    mpz_mod(roots[0], roots[0], n);
    
    // Корінь 2: + -
    mpz_sub(roots[1], temp1, temp2);
    mpz_mod(roots[1], roots[1], n);
    
    // Корінь 3: - +
    mpz_neg(temp1, temp1);
    mpz_add(temp1, temp1, temp2);
    mpz_mod(roots[2], temp1, n);
    
    // Корінь 4: - -
    mpz_neg(temp2, temp2);
    mpz_sub(roots[3], temp1, temp2);
    mpz_mod(roots[3], roots[3], n);
    
    mpz_clear(s1);
    mpz_clear(s2);
    mpz_clear(u);
    mpz_clear(v);
    mpz_clear(gcd_val);
    mpz_clear(temp1);
    mpz_clear(temp2);
    mpz_clear(exp_p);
    mpz_clear(exp_q);
}

// Шифрування (розширена схема Рабіна)
void Encrypt(Ciphertext *ct, mpz_t x, PublicKey *pk) {
    mpz_t temp, b_inv, x_b;
    mpz_init(temp);
    mpz_init(b_inv);
    mpz_init(x_b);
    
    // Обчислюємо y = (x + b)^2 mod n
    mpz_add(x_b, x, pk->b);
    mpz_powm_ui(ct->y, x_b, 2, pk->n);
    
    // c1 = (x + b) mod 2
    ct->c1 = mpz_tstbit(x_b, 0);
    
    // c2 = символ Якобі ((x + b) / n)
    ct->c2 = (jacobi_symbol(x_b, pk->n) == 1) ? 1 : 0;
    
    mpz_clear(temp);
    mpz_clear(b_inv);
    mpz_clear(x_b);
}

// Розшифрування (розширена схема Рабіна)
void Decrypt(mpz_t x, Ciphertext *ct, PrivateKey *sk) {
    mpz_t roots[4], b_inv, x_candidate, temp;
    
    for (int i = 0; i < 4; i++) {
        mpz_init(roots[i]);
    }
    mpz_init(b_inv);
    mpz_init(x_candidate);
    mpz_init(temp);
    
    // Обчислюємо 4 квадратні корені з y
    compute_square_roots(roots, ct->y, sk->p, sk->q, sk->n);
    
    // Знаходимо 4^(-1) mod n для обчислення x = (z - b) / 4 mod n
    mpz_set_ui(temp, 4);
    mpz_invert(b_inv, temp, sk->n);
    
    // Перевіряємо кожен корінь
    for (int i = 0; i < 4; i++) {
        // x_candidate = root - b
        mpz_sub(x_candidate, roots[i], sk->b);
        mpz_mod(x_candidate, x_candidate, sk->n);
        
        // Перевіряємо біт парності
        int bit_parity = mpz_tstbit(roots[i], 0);
        
        // Перевіряємо символ Якобі
        int jac = (jacobi_symbol(roots[i], sk->n) == 1) ? 1 : 0;
        
        if (bit_parity == ct->c1 && jac == ct->c2) {
            mpz_set(x, x_candidate);
            break;
        }
    }
    
    for (int i = 0; i < 4; i++) {
        mpz_clear(roots[i]);
    }
    mpz_clear(b_inv);
    mpz_clear(x_candidate);
    mpz_clear(temp);
}

// Постановка цифрового підпису
void Sign(mpz_t signature, const unsigned char *msg, size_t msg_len, PrivateKey *sk) {
    mpz_t x, roots[4];
    mpz_init(x);
    for (int i = 0; i < 4; i++) {
        mpz_init(roots[i]);
    }
    
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL));
    
    // Форматуємо повідомлення
    do {
        format_message(x, msg, msg_len, sk->n);
        
        // Перевіряємо, чи x є квадратичним лишком
        int jac_p = jacobi_symbol(x, sk->p);
        int jac_q = jacobi_symbol(x, sk->q);
        
        if (jac_p == 1 && jac_q == 1) {
            break;
        }
    } while (1);
    
    // Обчислюємо квадратні корені
    compute_square_roots(roots, x, sk->p, sk->q, sk->n);
    
    // Обираємо випадковий корінь як підпис
    unsigned long idx = mpz_urandomm_ui(state, 4);
    mpz_set(signature, roots[idx]);
    
    for (int i = 0; i < 4; i++) {
        mpz_clear(roots[i]);
    }
    mpz_clear(x);
    gmp_randclear(state);
}

// Перевірка цифрового підпису
int Verify(mpz_t signature, const unsigned char *msg, size_t msg_len, PublicKey *pk) {
    mpz_t x, s_squared;
    mpz_init(x);
    mpz_init(s_squared);
    
    // Обчислюємо s^2 mod n
    mpz_powm_ui(s_squared, signature, 2, pk->n);
    
    // Форматуємо повідомлення
    format_message(x, msg, msg_len, pk->n);
    
    // Перевіряємо, чи x' є форматованим повідомленням
    int valid = check_format(s_squared);
    
    mpz_clear(x);
    mpz_clear(s_squared);
    
    return valid;
}

// Атака на протокол доведення без розголошення
void attack_znp_protocol(mpz_t p_or_q, mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL));
    
    mpz_t t, y, z, gcd_val, diff;
    mpz_init(t);
    mpz_init(y);
    mpz_init(z);
    mpz_init(gcd_val);
    mpz_init(diff);
    
    int attempts = 0;
    
    printf("\n=== Атака на протокол доведення без розголошення ===\n");
    printf("Модуль n: ");
    mpz_out_str(stdout, 10, n);
    printf("\n\n");
    
    while (1) {
        attempts++;
        
        // 1. Генеруємо випадкове t
        mpz_urandomm(t, state, n);
        
        // 2. Обчислюємо y = t^2 mod n
        mpz_powm_ui(y, t, 2, n);
        
        printf("Спроба %d:\n", attempts);
        printf("  t = ");
        mpz_out_str(stdout, 10, t);
        printf("\n");
        printf("  y = ");
        mpz_out_str(stdout, 10, y);
        printf("\n");
        
        // !!! ТУТ ПОТРІБНО НАДІСЛАТИ y НА СЕРВЕР І ОТРИМАТИ z !!!
        // Для демонстрації ми симулюємо відповідь сервера
        // В реальній реалізації тут має бути HTTP запит
        
        printf("  [Надсилаємо y на сервер...]\n");
        printf("  [Очікуємо z від сервера...]\n");
        
        // Для тестування: введіть z вручну або реалізуйте HTTP клієнт
        // mpz_set_str(z, "...", 10);
        
        // 3. Перевіряємо, чи t ≠ z
        mpz_sub(diff, t, z);
        mpz_mod(diff, diff, n);
        
        if (mpz_cmp_ui(diff, 0) != 0) {
            // Обчислюємо gcd(t - z, n)
            mpz_sub(diff, t, z);
            mpz_gcd(gcd_val, diff, n);
            
            // Якщо знайшли множник
            if (mpz_cmp_ui(gcd_val, 1) > 0 && mpz_cmp(gcd_val, n) < 0) {
                mpz_set(p_or_q, gcd_val);
                printf("\n✓ УСПІХ! Знайдено множник на спробі %d\n", attempts);
                printf("Множник: ");
                mpz_out_str(stdout, 10, p_or_q);
                printf("\n");
                break;
            }
        }
        
        if (attempts >= 100) {
            printf("\nПеревищено максимальну кількість спроб.\n");
            break;
        }
    }
    
    mpz_clear(t);
    mpz_clear(y);
    mpz_clear(z);
    mpz_clear(gcd_val);
    mpz_clear(diff);
    gmp_randclear(state);
}

// Головна функція
int main() {
    printf("=== Криптосистема Рабіна ===\n\n");
    
    PublicKey pk;
    PrivateKey sk;
    
    init_public_key(&pk);
    init_private_key(&sk);
    
    // 1. Генерування ключів
    printf("1. Генерування ключів (1024 біт)...\n");
    GenerateKeyPair(&pk, &sk, 1024);
    
    printf("\nВідкритий ключ n: ");
    mpz_out_str(stdout, 10, pk.n);
    printf("\n");
    
    printf("Параметр b: ");
    mpz_out_str(stdout, 10, pk.b);
    printf("\n\n");
    
    // 2. Тест шифрування/розшифрування
    printf("2. Тест шифрування/розшифрування\n");
    const char *message = "Hello, Rabin!";
    printf("Повідомлення: %s\n", message);
    
    mpz_t x, x_decrypted;
    mpz_init(x);
    mpz_init(x_decrypted);
    
    format_message(x, (unsigned char*)message, strlen(message), pk.n);
    printf("Форматоване повідомлення x: ");
    mpz_out_str(stdout, 16, x);
    printf("\n");
    
    Ciphertext ct;
    init_ciphertext(&ct);
    
    Encrypt(&ct, x, &pk);
    printf("Шифротекст y: ");
    mpz_out_str(stdout, 10, ct.y);
    printf("\nБіт парності c1: %d\n", ct.c1);
    printf("Символ Якобі c2: %d\n", ct.c2);
    
    Decrypt(&x_decrypted, &ct, &sk);
    
    unsigned char decrypted_msg[1000];
    size_t dec_len;
    unformat_message(decrypted_msg, &dec_len, x_decrypted);
    decrypted_msg[dec_len] = '\0';
    
    printf("Розшифроване повідомлення: %s\n\n", decrypted_msg);
    
    // 3. Тест цифрового підпису
    printf("3. Тест цифрового підпису\n");
    mpz_t signature;
    mpz_init(signature);
    
    Sign(signature, (unsigned char*)message, strlen(message), &sk);
    printf("Підпис: ");
    mpz_out_str(stdout, 10, signature);
    printf("\n");
    
    int valid = Verify(signature, (unsigned char*)message, strlen(message), &pk);
    printf("Підпис %s\n\n", valid ? "КОРЕКТНИЙ" : "НЕКОРЕКТНИЙ");
    
    // 4. Інформація про атаку
    printf("4. Атака на протокол доведення без розголошення\n");
    printf("Для проведення атаки використовуйте:\n");
    printf("http://asymcryptwebservice.appspot.com/?section=znp\n\n");
    
    // Очищення пам'яті
    mpz_clear(x);
    mpz_clear(x_decrypted);
    mpz_clear(signature);
    clear_ciphertext(&ct);
    clear_public_key(&pk);
    clear_private_key(&sk);
    
    return 0;
}
