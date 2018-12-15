#SECP256K1
#constants defined by Standards for Efficient Cryptography recommended elliptic curve parameters
p_curve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1 #the proven prime
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # number of points in the field
a_curve = 0; b_curve = 7 # curve parameters (y**2 = x**2 + a_curve*x + b_curve)
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
g_point = (Gx, Gy) #generator point
#signature iformation
priv_key = 75263518707598184987916378021939673586055614731957507592904438851787542395619
rand_num = 28695618543805844332113829720373285210420739438570883203839696518176414791234
message_hash = 86032112319101611046176971828093669637772856272773459297323797145286374828050

def modular_inverse(a, n = p_curve): # extended euclidian algorithm(elliptic curve division)
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ec_addition(xp, yp, xq, yq): #'addition' exclusive to elliptic curves
    m = ((yq - yp) * modular_inverse(xq - xp, p_curve)) % p_curve
    xr = (m * m - xp - xq) % p_curve
    yr = (m * (xp - xr) - yp) % p_curve
    return (xr, yr)

def ec_double(xp, yp): #point doubling exclusive to elliptic curves
    lam_numerator = 3 * xp * xp + a_curve
    lam_denominator = 2 * yp
    lam = (lam_numerator * modular_inverse(lam_denominator, p_curve)) % p_curve
    xr = (lam * lam - 2 * xp) % p_curve
    yr = (lam * (xp - xr)  - yp) % p_curve
    return (xr, yr)

def ec_multiplication(xs, ys, scalar): #double and add exclusive to elliptic curves
    if scalar == 0 or scalar >= n:
        raise Exception('[!]Invalid Private Key')
    scalar_bin = str(bin(scalar))[2:]
    Qx, Qy = xs, ys
    for i in range(1, len(scalar_bin)):
        Qx, Qy = ec_double(Qx, Qy)
        if scalar_bin[i] == '1':
            Qx, Qy = ec_addition(Qx, Qy, xs, ys)
    return(Qx, Qy)

def main():
    print(p_curve)
    print('\n----------Public Key Generation----------\n')
    x_pub_key, y_pub_key = ec_multiplication(Gx, Gy, priv_key)
    print('Private Key (base 10): \n{}\n'.format(priv_key))
    print('Uncompressed Public Key (NOT ADDRESS): \n04{}{}\n'.format(x_pub_key, y_pub_key))

    print('\n----------Signature Generation----------\n')
    
    x_rand_sig, y_rand_sig = ec_multiplication(Gx, Gy, rand_num)
    r = x_rand_sig % n
    s = ((message_hash + r * priv_key)*(modular_inverse(rand_num, n))) % n 

    print('Note: the sending party signs a message using the private key, the recieving party verifies with the corresponding public key')
    print('\'r\' is the x coordinate of elliptic curve multiplication of a single use random number')
    print('\'s\' is a combination of the message hash, r, the single use random number, and the private key of sending party\n\n')
    print('message hash = {}\n'.format(message_hash))
    print('single use random number = {}\n'.format(rand_num))
    print('r = {}\n'.format(r))
    print('s = {}\n'.format(s))
    print('The signature to be verified by recieving party is (r, s)')

    print('\n----------Signature Verification----------\n')

    w = modular_inverse(s, n)
    xu1, yu1 = ec_multiplication(Gx, Gy, (message_hash * w) % n)
    xu2, yu2 = ec_multiplication(x_pub_key, y_pub_key, (r * w) % n)
    x, y = ec_addition(xu1, yu1, xu2, yu2)
    print('Note: recieving party does NOT have access to the sending party\'s private key')
    print('\'w\' is the modular inverse of \'s\'')
    print('\'x\' is the x coordinate of a combination of the message hash, \'w\', \'r\', and the sending party\'s public key\n\n')
    print('w = {}\n'.format(w))
    print('x = {}\n'.format(x))
    print('If x == r : the signature is verified.')
    if r == x:
        print('[+] Signature Verified!\n')
    else:
       print('[-] Signature Not Verified...\n')

if __name__ == '__main__':
    main()
