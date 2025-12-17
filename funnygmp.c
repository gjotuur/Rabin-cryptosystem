#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <gmp.h>

int main(){
    mpz_t f;
    mpz_init_set_str(f, "FFF000000070696470726F7374697270726F73746F7279A842BFF452018329", 16);
    mpz_t m, x, n, r;
    mpz_inits(m,x,n,r,NULL);
    mpz_set(m,f);
    mpz_tdiv_q_2exp(m, m, 64);
    gmp_printf("Current is %ZX\n", m);
    size_t l = mpz_sizeinbase(m,2);
    mpz_tdiv_q_2exp(n, m, l-8);
    gmp_printf("Highest byte is: %ZX", n);
    for(size_t i = l - 1; i >= l - 8; i--){
        mpz_clrbit(m, i);
    }

    gmp_printf("Current is %ZX\n", m);
    mpz_t ascr;

    mpz_clears(m,x,n,r,f,NULL);
    return 0;
}