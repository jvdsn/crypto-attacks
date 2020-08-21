# Crypto attacks
Python implementations of cryptographic attacks and utilities.

## Requirements
* PyCryptodome 
* SageMath

## Implementations
### CBC
* [x] [Bit flipping attack](cbc/bit_flipping.py)
* [x] [IV recovery attack](cbc/iv_recovery.py)
* [x] [Padding oracle attack](cbc/padding_oracle.py)

### CBC + CBC-MAC
* [x] [Key reuse attack (encrypt-and-MAC)](cbc_and_cbc_mac/eam_key_reuse.py)
* [x] [Key reuse attack (encrypt-then-MAC)](cbc_and_cbc_mac/eam_key_reuse.py)
* [x] [Key reuse attack (MAC-then-encrypt)](cbc_and_cbc_mac/eam_key_reuse.py)

### CBC-MAC
* [x] [Length extension attack](cbc_mac/length_extension.py)

### CTR
* [x] [CRIME attack](ctr/crime.py)
* [x] [Separator oracle attack](ctr/separator_oracle.py)

### ECB
* [x] [Plaintext recovery attack](ecb/plaintext_recovery.py)

### Elliptic Curve Cryptography
* [x] [ECDSA nonce reuse attack](ecc/ecdsa_nonce_reuse.py)
* [ ] Frey-Ruck attack
* [x] [MOV attack](ecc/mov_attack.py)
* [x] [Singular curve attack (cusp)](ecc/singular_curve_cusp.py)
* [x] [Singular curve attack (node)](ecc/singular_curve_node.py)
* [x] [Smart's attack](ecc/smart_attack.py) [More information: Smart N. P., "The discrete logarithm problem on elliptic curves of trace one"]

### ElGamal Encryption
* [x] [Nonce reuse attack](elgamal_encryption/nonce_reuse.py)
* [x] [Unsafe generator attack](elgamal_encryption/unsafe_generator.py)

### ElgGamal Signature
* [ ] Bleichenbacher's attack
* [ ] Khadir's attack
* [x] [Nonce reuse attack](elgamal_signature/nonce_reuse.py)

### Factorization
* [x] [Base conversion factorization](factorization/base_conversion.py)
* [x] [Coppersmith factorization](factorization/coppersmith.py)
* [x] [Fermat factorization](factorization/fermat.py)
* [x] [Known phi factorization](factorization/known_phi.py)
* [x] [ROCA](factorization/roca.py) [More information: Nemec M. et al., "The Return of Coppersmith’s Attack: Practical Factorization of Widely Used RSA Moduli"]
* [x] [Twin primes factorization](factorization/twin_primes.py)

### GCM
* [x] [Forbidden attack](gcm/forbidden_attack.py) [More information: Joux A., "Authentication Failures in NIST version of GCM"]

### IGE
* [x] [Padding oracle attack](ige/padding_oracle.py)

### OFB
* [x] [CRIME attack](ofb/crime.py)
* [x] [Separator oracle attack](ctr/separator_oracle.py)

### Pseudoprimes
* [x] [Generating Miller-Rabin pseudoprimes](pseudoprimes/miller_rabin.py)

### RSA
* [ ] Bleichenbacher's attack
* [x] [Bleichenbacher's signature forgery attack](rsa/bleichenbacher_signature_forgery.py)
* [x] [Boneh-Durfee attack](rsa/boneh_durfee.py) [More information: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"]
* [x] [Common modulus attack](rsa/common_modulus.py)
* [x] [Common prime factor attack](rsa/common_prime_factor.py)
* [x] [CRT fault attack](rsa/crt_fault_attack.py)
* [x] [Extended Wiener's attack](rsa/extended_wiener_attack.py) [More information: Dujella A., "Continued fractions and RSA with small secret exponent"]
* [x] [Hastad's broadcast attack](rsa/hastad_attack.py)
* [x] [Low public exponent attack](rsa/low_exponent.py)
* [x] [LSB oracle attack](rsa/lsb_oracle.py)
* [ ] Manger's attack
* [x] [Partial key exposure attack for low public exponents](rsa/partial_key_exposure.py) [More information: Boneh D., Durfee G., Frankel Y., "An Attack on RSA Given a Small Fraction of the Private Key Bits"]
* [x] [Related message attack](rsa/related_message.py)
* [x] [Stereotyped message attack](rsa/stereotyped_message.py)
* [x] [Wiener's attack](rsa/wiener_attack.py)

### Shamir's Secret Sharing
* [x] [Deterministic coefficients](shamir_secret_sharing/deterministic_coefficients.py)
* [x] [Share forgery](shamir_secret_sharing/share_forgery.py)

### Small roots
* [x] [Boneh-Durfee method](small_roots/boneh_durfee.py) [More information: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"]
* [x] [Coron method](small_roots/coron.py) [More information: Coron J., "Finding Small Roots of Bivariate Integer Polynomial Equations: a Direct Approach"]
* [x] [Herrmann-May method (Boneh-Durfee with unravelled linearization)](small_roots/herrmann_may.py) [Herrmann M., May A., "Maximizing Small Root Bounds by Linearization and Applications to Small Secret Exponent RSA"]
* [x] [Howgrave-Graham method](small_roots/howgrave_graham.py) [More information: May A., "New RSA Vulnerabilities Using Lattice Reduction Methods"]
* [ ] Jochemsz-May method [More information: Jochemsz E., May A., "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants"]
