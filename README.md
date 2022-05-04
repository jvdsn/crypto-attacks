## Introduction
Python implementations of cryptographic attacks and utilities.

## Requirements
* [SageMath](https://www.sagemath.org/) with Python 3.9
* [PyCryptodome](https://pycryptodome.readthedocs.io/)
* [Hilbert Class Polynomial database](https://doc.sagemath.org/html/en/reference/databases/sage/databases/db_class_polynomials.html) (Only required for complex multiplication)

You can check your SageMath Python version using the following command:
```
$ sage -python --version
Python 3.9.0
```
If your SageMath Python version is older than 3.9.0, some features in some scripts might not work.

## Usage
Unit tests are located in the `test` directory and can be executed using the `unittest` module or using `pytest`. This should not take very long, perhaps a few minutes depending on your machine.

To run a specific attack, you must add the code to the proper file before executing it.

### Example

For example, you want to attack RSA using the Boneh-Durfee attack, with the following parameters (taken from [test_rsa.py](test/test_rsa.py)):
```python
N = 88320836926176610260238895174120738360949322009576866758081671082752401596826820274141832913391890604999466444724537056453777218596634375604879123818123658076245218807184443147162102569631427096787406420042132112746340310992380094474893565028303466135529032341382899333117011402408049370805729286122880037249
e = 36224751658507610673165956970793195381480143363550601971796688201449789736497322700382657163240771111376677180786660893671085854060092736865293791299460933460067267613023891500397200389824179925263846148644777638774319680682025117466596019474987378275216579013846855328009375540444176771945272078755317168511
```

You add the following code at the bottom of the [boneh_durfee.py](attacks/rsa/boneh_durfee.py) file:
```python
import logging

# Some logging so we can see what's happening.
logging.basicConfig(level=logging.DEBUG)

N = 88320836926176610260238895174120738360949322009576866758081671082752401596826820274141832913391890604999466444724537056453777218596634375604879123818123658076245218807184443147162102569631427096787406420042132112746340310992380094474893565028303466135529032341382899333117011402408049370805729286122880037249
e = 36224751658507610673165956970793195381480143363550601971796688201449789736497322700382657163240771111376677180786660893671085854060092736865293791299460933460067267613023891500397200389824179925263846148644777638774319680682025117466596019474987378275216579013846855328009375540444176771945272078755317168511
p_bits = 512
delta = 0.26

p, q = attack(N, e, p_bits, delta=delta)
assert p * q == N
print(f"Found p = {p} and q = {q}")
```

Then you can simply execute the file using Sage. It does not matter where you execute it from, the Python path is automagically set:
```commandline
[crypto-attacks]$ sage -python attacks/rsa/boneh_durfee.py
INFO:root:Trying m = 1, t = 0...
DEBUG:root:Generating shifts...
DEBUG:root:Filling the lattice (3 x 3)...
DEBUG:root:Executing the LLL algorithm...
DEBUG:root:Reconstructing polynomials...
DEBUG:root:Polynomial at row 0 is constant, ignoring...
DEBUG:root:Reconstructed 2 polynomials
DEBUG:root:Using Groebner basis method to find roots...
DEBUG:root:Groebner basis length: 1
DEBUG:root:Groebner basis length: 1
INFO:root:Trying m = 2, t = 0...
DEBUG:root:Generating shifts...
DEBUG:root:Filling the lattice (6 x 6)...
DEBUG:root:Executing the LLL algorithm...
DEBUG:root:Reconstructing polynomials...
DEBUG:root:Polynomial at row 0 is constant, ignoring...
DEBUG:root:Reconstructed 5 polynomials
DEBUG:root:Using Groebner basis method to find roots...
DEBUG:root:Groebner basis length: 1
DEBUG:root:Groebner basis length: 1
DEBUG:root:Groebner basis length: 1
DEBUG:root:Groebner basis length: 1
DEBUG:root:Groebner basis length: 1
INFO:root:Trying m = 3, t = 1...
DEBUG:root:Generating shifts...
DEBUG:root:Filling the lattice (11 x 11)...
DEBUG:root:Executing the LLL algorithm...
DEBUG:root:Reconstructing polynomials...
DEBUG:root:Polynomial at row 8 is constant, ignoring...
DEBUG:root:Reconstructed 10 polynomials
DEBUG:root:Using Groebner basis method to find roots...
DEBUG:root:Groebner basis length: 1
DEBUG:root:Groebner basis length: 1
DEBUG:root:Groebner basis length: 1
DEBUG:root:Groebner basis length: 2
Found p = 7866790440964395011005623971351568677139336343167390105188826934257986271072664643571727955882500173182140478082778193338086048035817634545367411924942763 and q = 11227048386374621771175649743442169526805922745751610531569607663416378302561807690656370394330458335919244239976798600743588701676542461805061598571009923
```

You can also call the attacks from other Python files, but then you'll have to fix the Python path yourself.

## Implemented attacks
### Approximate Common Divisor
* [x] [Multivariate polynomial attack](attacks/acd/mp.py) [More information: Galbraith D. S. et al., "Algorithms for the Approximate Common Divisor Problem" (Section 5)]
* [x] [Orthogonal based attack](attacks/acd/ol.py) [More information: Galbraith D. S. et al., "Algorithms for the Approximate Common Divisor Problem" (Section 4)]
* [x] [Simultaneous Diophantine approximation attack](attacks/acd/sda.py) [More information: Galbraith D. S. et al., "Algorithms for the Approximate Common Divisor Problem" (Section 3)]

### CBC
* [x] [Bit flipping attack](attacks/cbc/bit_flipping.py)
* [x] [IV recovery attack](attacks/cbc/iv_recovery.py)
* [x] [Padding oracle attack](attacks/cbc/padding_oracle.py)

### CBC + CBC-MAC
* [x] [Key reuse attack (encrypt-and-MAC)](attacks/cbc_and_cbc_mac/eam_key_reuse.py)
* [x] [Key reuse attack (encrypt-then-MAC)](attacks/cbc_and_cbc_mac/etm_key_reuse.py)
* [x] [Key reuse attack (MAC-then-encrypt)](attacks/cbc_and_cbc_mac/mte_key_reuse.py)

### CBC-MAC
* [x] [Length extension attack](attacks/cbc_mac/length_extension.py)

### CTR
* [x] [CRIME attack](attacks/ctr/crime.py)
* [x] [Separator oracle attack](attacks/ctr/separator_oracle.py)

### ECB
* [x] [Plaintext recovery attack](attacks/ecb/plaintext_recovery.py)
* [x] [Plaintext recovery attack (harder variant)](attacks/ecb/plaintext_recovery_harder.py)
* [x] [Plaintext recovery attack (hardest variant)](attacks/ecb/plaintext_recovery_harder.py)

### Elliptic Curve Cryptography
* [x] [ECDSA nonce reuse attack](attacks/ecc/ecdsa_nonce_reuse.py)
* [x] [Frey-Ruck attack](attacks/ecc/frey_ruck_attack.py) [More information: Harasawa R. et al., "Comparing the MOV and FR Reductions in Elliptic Curve Cryptography" (Section 3)]
* [x] [MOV attack](attacks/ecc/mov_attack.py) [More information: Harasawa R. et al., "Comparing the MOV and FR Reductions in Elliptic Curve Cryptography" (Section 2)]
* [x] [Parameter recovery](attacks/ecc/parameter_recovery.py)
* [x] [Singular curve attack](attacks/ecc/singular_curve.py)
* [x] [Smart's attack](attacks/ecc/smart_attack.py) [More information: Smart N. P., "The discrete logarithm problem on elliptic curves of trace one"]

### ElGamal Encryption
* [x] [Nonce reuse attack](attacks/elgamal_encryption/nonce_reuse.py)
* [x] [Unsafe generator attack](attacks/elgamal_encryption/unsafe_generator.py)

### ElgGamal Signature
* [ ] Bleichenbacher's attack
* [ ] Khadir's attack
* [x] [Nonce reuse attack](attacks/elgamal_signature/nonce_reuse.py)

### Factorization
* [x] [Base conversion factorization](attacks/factorization/base_conversion.py)
* [x] [Branch and prune attack](attacks/factorization/branch_and_prune.py) [More information: Heninger N., Shacham H., "Reconstructing RSA Private Keys from Random Key Bits"]
* [x] [Complex multiplication (elliptic curve) factorization](attacks/factorization/complex_multiplication.py) [More information: Sedlacek V. et al., "I want to break square-free: The 4p - 1 factorization method and its RSA backdoor viability"]
* [x] [Coppersmith factorization](attacks/factorization/coppersmith.py)
* [x] [Fermat factorization](attacks/factorization/fermat.py)
* [x] [Ghafar-Ariffin-Asbullah attack](attacks/factorization/gaa.py) [More information: Ghafar AHA. et al., "A New LSB Attack on Special-Structured RSA Primes"]
* [x] [Implicit factorization](attacks/factorization/implicit.py) [More information: Nitaj A., Ariffin MRK., "Implicit factorization of unbalanced RSA moduli"]
* [x] [Known phi factorization](attacks/factorization/known_phi.py) [More information: Hinek M. J., Low M. K., Teske E., "On Some Attacks on Multi-prime RSA" (Section 3)]
* [x] [ROCA](attacks/factorization/roca.py) [More information: Nemec M. et al., "The Return of Coppersmith’s Attack: Practical Factorization of Widely Used RSA Moduli"]
* [x] [Shor's algorithm (classical)](attacks/factorization/shor.py) [More information: M. Johnston A., "Shor’s Algorithm and Factoring: Don’t Throw Away the Odd Orders"]
* [x] [Twin primes factorization](attacks/factorization/twin_primes.py)
* [x] [Factorization of unbalanced moduli](attacks/factorization/unbalanced.py) [More information: Brier E. et al., "Factoring Unbalanced Moduli with Known Bits" (Section 4)]

### GCM
* [x] [Forbidden attack](attacks/gcm/forbidden_attack.py) [More information: Joux A., "Authentication Failures in NIST version of GCM"]

### Hidden Number Problem
* [ ] Extended hidden number problem [More information: Hlavac M., Rosa T., "Extended Hidden Number Problem and Its Cryptanalytic Applications" (Section 4)]
* [ ] Fourier analysis attack
* [x] [Lattice-based attack](attacks/hnp/lattice_attack.py)

### IGE
* [x] [Padding oracle attack](attacks/ige/padding_oracle.py)

### Knapsack Cryptosystems
* [x] [Low density attack](attacks/knapsack/low_density.py) [More information: Coster M. J. et al., "Improved low-density subset sum algorithms"]

### Linear Congruential Generators

* [x] [LCG parameter recovery](attacks/lcg/parameter_recovery.py)
* [x] [Truncated LCG parameter recovery](attacks/lcg/truncated_parameter_recovery.py) [More information: Contini S., Shparlinski I. E., "On Stern's Attack Against Secret Truncated Linear Congruential Generators"]
* [x] [Truncated LCG state recovery](attacks/lcg/truncated_state_recovery.py) [More information: Frieze, A. et al., "Reconstructing Truncated Integer Variables Satisfying Linear Congruences"]

### Learning With Errors

* [x] [Arora-Ge attack](attacks/lwe/arora_ge.py) [More information: "The Learning with Errors Problem: Algorithms" (Section 1)]
* [ ] Blum-Kalai-Wasserman attack
* [ ] Lattice reduction attack

### Mersenne Twister

* [x] [State recovery](attacks/mersenne_twister/state_recovery.py)

### One-time Pad

* [x] [Key reuse](attacks/otp/key_reuse.py)

### Pseudoprimes

* [x] [Generating Miller-Rabin pseudoprimes](attacks/pseudoprimes/miller_rabin.py) [More information: R. Albrecht M. et al., "Prime and Prejudice: Primality Testing Under Adversarial Conditions"]

### RC4

* [x] [Fluhrer-Mantin-Shamir attack](attacks/rc4/fms.py)

### RSA

* [x] [Bleichenbacher's attack](attacks/rsa/bleichenbacher.py) [More information: Bleichenbacher D., "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"]
* [x] [Bleichenbacher's signature forgery attack](attacks/rsa/bleichenbacher_signature_forgery.py)
* [x] [Boneh-Durfee attack](attacks/rsa/boneh_durfee.py) [More information: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"]
* [x] [Common modulus attack](attacks/rsa/common_modulus.py)
* [x] [CRT fault attack](attacks/rsa/crt_fault_attack.py)
* [x] [Extended Wiener's attack](attacks/rsa/extended_wiener_attack.py) [More information: Dujella A., "Continued fractions and RSA with small secret exponent"]
* [x] [Hastad's broadcast attack](attacks/rsa/hastad_attack.py)
* [x] [Known CRT exponents attack](attacks/rsa/known_crt_exponents.py) [More information: Campagna M., Sethi A., "Key Recovery Method for CRT Implementation of RSA"]
* [x] [Known private exponent attack](attacks/rsa/known_d.py)
* [x] [Low public exponent attack](attacks/rsa/low_exponent.py)
* [x] [LSB oracle (parity oracle) attack](attacks/rsa/lsb_oracle.py)
* [x] [Manger's attack](attacks/rsa/manger.py) [More information: Manger J., "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0"]
* [x] [Nitaj's CRT-RSA attack](attacks/rsa/nitaj_crt_rsa.py) [More information: Nitaj A., "A new attack on RSA and CRT-RSA"]
* [x] [Non coprime public exponent attack](attacks/rsa/non_coprime_exponent.py) [More information: Shumow D., "Incorrectly Generated RSA Keys: How To Recover Lost Plaintexts"]
* [x] [Partial key exposure](attacks/rsa/partial_key_exposure.py) [More information: Boneh D., Durfee G., Frankel Y., "An Attack on RSA Given a Small Fraction of the Private Key Bits", Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents", Blomer J., May A., "New Partial Key Exposure Attacks on RSA"]
* [x] [Related message attack](attacks/rsa/related_message.py)
* [x] [Stereotyped message attack](attacks/rsa/stereotyped_message.py)
* [x] [Wiener's attack](attacks/rsa/wiener_attack.py)
* [x] [Wiener's attack for Common Prime RSA](attacks/rsa/wiener_attack_common_prime.py) [More information: Jochemsz E., May A., "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants" (Section 5)]
* [x] [Wiener's attack (Heuristic lattice variant)](attacks/rsa/wiener_attack_lattice.py) [More information: Nguyen P. Q., "Public-Key Cryptanalysis"]

### Shamir's Secret Sharing
* [x] [Deterministic coefficients](attacks/shamir_secret_sharing/deterministic_coefficients.py)
* [x] [Share forgery](attacks/shamir_secret_sharing/share_forgery.py)

## Other interesting implementations
* [x] [Adleman-Manders-Miller root extraction method](shared/__init__.py) [More information: Cao Z. et al., "Adleman-Manders-Miller Root Extraction Method Revisited" (Section 5)]
* [x] [Fast CRT using divide-and-conquer](shared/crt.py)
* [x] [Linear Hensel lifting](shared/hensel.py)
* [ ] Quadratic Hensel lifting
* [x] [Babai's Nearest Plane Algorithm](shared/lattice.py)
* [x] [Matrix discrete logarithm](shared/matrices.py)
* [x] [Matrix discrete logarithm (equation)](shared/matrices.py)
* [x] [PartialInteger](shared/partial_integer.py)
* [x] [Fast polynomial GCD using half GCD](shared/polynomial.py)

### Elliptic Curve Generation
* [ ] MNT curves
* [ ] Prescribed order
* [ ] Prescribed trace
* [ ] Supersingular curves

### Small Roots
* [x] [Polynomial roots using Groebner bases](shared/small_roots/__init__.py)
* [x] [Polynomial roots using resultants](shared/small_roots/__init__.py)
* [x] [Polynomial roots using Sage variety (triangular decomposition)](shared/small_roots/__init__.py)
* [x] [Blomer-May method](shared/small_roots/blomer_may.py) [More information: Blomer J., May A., "New Partial Key Exposure Attacks on RSA" (Section 6)]
* [x] [Boneh-Durfee method](shared/small_roots/boneh_durfee.py) [More information: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"]
* [x] [Coron method](shared/small_roots/coron.py) [More information: Coron J., "Finding Small Roots of Bivariate Polynomial Equations Revisited"]
* [x] [Coron method (direct)](shared/small_roots/coron_direct.py) [More information: Coron J., "Finding Small Roots of Bivariate Integer Polynomial Equations: a Direct Approach"]
* [x] [Ernst et al. methods](shared/small_roots/ernst.py) [More information: Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents"]
* [x] [Herrmann-May method (unravelled linearization)](shared/small_roots/herrmann_may.py) [More information: Herrmann M., May A., "Maximizing Small Root Bounds by Linearization and Applications to Small Secret Exponent RSA"]
* [x] [Herrmann-May method (modular multivariate)](shared/small_roots/herrmann_may_multivariate.py) [More information: Herrmann M., May A., "Solving Linear Equations Modulo Divisors: On Factoring Given Any Bits" (Section 3 and 4)]
* [x] [Howgrave-Graham method](shared/small_roots/howgrave_graham.py) [More information: May A., "New RSA Vulnerabilities Using Lattice Reduction Methods" (Section 3.2)]
* [x] [Jochemsz-May method (modular roots)](shared/small_roots/jochemsz_may_modular.py) [More information: Jochemsz E., May A., "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants" (Section 2.1)]
* [x] [Jochemsz-May method (integer roots)](shared/small_roots/jochemsz_may_integer.py) [More information: Jochemsz E., May A., "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants" (Section 2.2)]
* [x] [Nitaj-Fouotsa method](shared/small_roots/nitaj_fouotsa.py) [More information: Nitaj A., Fouotsa E., "A New Attack on RSA and Demytko's Elliptic Curve Cryptosystem"]
