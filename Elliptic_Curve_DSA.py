#SECP256K1
#constants defined by Standards for Efficient Cryptography recommended elliptic curve parameters
p_curve = 2**256 - 2**32 - 2**9 - 2**7 - 2**6 - 2**4 - 1 #the proven prime
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # number of points in the field
a_curve = 0; b_curve = 7 # curve parameters (y**2 = x**2 + a_curve*x + b_curve)
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
g_point = (Gx, Gy) #generator point
#not constant, but hard coded for proof of concept
priv_key = 0xA0DC65FFCA799873CBEA0AC274015B9526505DAAAED385155425F7337704883E

def modular_inverse(a, n = p_curve): # extended euclidian algorithm(elliptic curve division)
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ec_addition(a, b): #'addition' exclusive to elliptic curves
    lam_add = ((b[1] - a[1]) * modular_inverse(b[0] - a[0], p_curve)) % p_curve
    x = (lam_add * lam_add - a[0] - b[0]) % p_curve
    y = (lam_add * (a[0] - x) - a[1]) % p_curve
    return (x,y)

def ec_double(a): #point doubling exclusive to elliptic curves
    lam = ((3 * a[0] * a[0] + a_curve) * modular_inverse((2 * a[1]), p_curve)) % p_curve
    x = (lam * lam - 2 * a[0])
    y = (lam * (a[0] - x) - a[1]) % p_curve
    return (x,y)

def ec_multiplication(gen_point, scalar_hex): #double and add exclusive to elliptic curves
    if scalar_hex == 0 or scalar_hex >= n:
        raise Exception('[!]Invalid Private Key')
    scalar_bin = str(bin(scalar_hex))[2:]
    q = gen_point
    for i in range(1, len(scalar_bin)):
        q = ec_double(q)
        print('DUB: {}\n'.format(q[0]))
        if scalar_bin[i] == '1':
            q = ec_addition(q, gen_point)
            print('ADD: {}\n'.format(q[0]))
    return q

def main():
    print('\n[*] Generating Public Key...\n')
    pub_key = ec_multiplication(g_point, priv_key)
    print('[+] Private Key: \n{}\n'.format(priv_key))
    print('[+] Uncompressed Public Key (NOT ADDRESS): \n{}\n'.format(pub_key))

if __name__ == '__main__':
    main()