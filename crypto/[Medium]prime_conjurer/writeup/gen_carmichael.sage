"""
Majority of code from https://eprint.iacr.org/2019/032.pdf
Safety in Numbers: On the Need for Robust Diffie-Hellman Parameter Validation
"""

import itertools
from operator import mul

def all_combinations(any_list): 
    """
    Wrapper for itertools to generate all possible combinations of all (non trivial) sizes.
    """
    return itertools.chain.from_iterable(itertools.combinations(any_list , i + 1) for i in range(len(any_list)))

def LCMpim1(n):
    """
    Takes as input n: a list of integers p_i and returns the lcm(p_i-1) for all i 
    """
    pim1list = []
    for pi in n:
        pim1 = pi - 1
        pim1list.append(pim1) 
    return lcm(pim1list)

def listbuild(L):
    """
    Takes as input a (highly composite) number L and returns a list of all primes p such 
    that p-1 | L where p does not divide L. We include the additional requirement that p = 3 mod 4.
    """
    a = list(factor(L))
    p = []
    for y in a:
        for i in range(0, y[1]): 
            p.append(y[0])
    
    pvals = all_combinations(p) 
    ps = []
    for pp in pvals:
        t = reduce(mul, pp, 1)
        tt = t + 1
        if tt.is_prime(proof=False) and L % tt != 0:
            if tt not in ps: 
                ps.append(tt)
    pps = []
    ps.sort()
    # we now filter results to only inlude p with p = 3 mod 4 
    for p in ps:
        if p % 4 == 3: 
            pps.append(p)
    return pps

def erdos_build(factors , L, k):
    """
    This function takes a list of possible factors, a (highly composite) integer L and k,
    and produces a Carmichael number with k factors sampled from "factors" such that the 
    LCM of each factor p_i - 1 is equal to L. Output is parsed as n,[p_1,p_2,...,p_k] 
    where n = p_1 * p_2 * ... * p_k.
    """
    if k <=2:
        print("Choice of factors must be >=3")
        return 0
    for i in itertools.combinations(factors , k):
        v = reduce(mul, i, 1) 
        if v % L == 1:
            fin = list(i) 
            fin.sort()
            if LCMpim1(fin) == L:
                return [v,fin]
    print("None found, try increasing size of factor list")


def granville_and_pomerance(factors):
    k = 1
    L = LCMpim1(factors)
    while True:
        M = 1 + k*L
        qs = [1 + M*(p-1) for p in factors]
        if all(q.is_prime(proof=False) for q in qs):
            N = prod(qs)
            return N, qs
        k += 1


Ls = [810810, 2088450, 4054050, 7657650, 13783770, 22972950, 53603550]

# Small L picked to keep N.nbits() small
L = 2*3^4*5*7*11^2
factors = listbuild(L)
print(factors, L, len(factors))

char, car_factors = erdos_build(factors , L, 6)
print(char, car_factors)

N, qs = granville_and_pomerance(car_factors)

print(N)
print(qs)
print('N bits', N.nbits())
print([q.nbits() for q in qs])
