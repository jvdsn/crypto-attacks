## Introduction
Python implementations of cryptographic attacks and utilities.

## Requirements
* [SageMath](https://www.sagemath.org/) with Python 3.9
* [PyCryptodome](https://pycryptodome.readthedocs.io/)

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

p, q = attack(N, e, p_bits, delta=delta, m=3)
assert p * q == N
print(f"Found p = {p} and q = {q}")
```

Then you can simply execute the file using Sage. It does not matter where you execute it from, the Python path is automagically set (
you can also call the attacks from other Python files, but then you'll have to fix the Python path yourself):
```commandline
[crypto-attacks]$ sage -python attacks/rsa/boneh_durfee.py
INFO:root:Trying m = 3, t = 1...
DEBUG:root:Generating shifts...
DEBUG:root:Creating a lattice with 11 shifts (order = invlex, sort_shifts_reverse = False, sort_monomials_reverse = False)...
DEBUG:root:Reducing a 11 x 11 lattice...
DEBUG:root:Reconstructing polynomials (divide_original = True, modulus_bound = True, divide_gcd = True)...
DEBUG:root:Row 4 is too large, ignoring...
DEBUG:root:Row 5 is too large, ignoring...
DEBUG:root:Row 6 is too large, ignoring...
DEBUG:root:Row 7 is too large, ignoring...
DEBUG:root:Row 8 is too large, ignoring...
DEBUG:root:Row 9 is too large, ignoring...
DEBUG:root:Row 10 is too large, ignoring...
DEBUG:root:Reconstructed 4 polynomials
DEBUG:root:Computing pairwise gcds to find trivial roots...
DEBUG:root:Using Groebner basis method to find roots...
DEBUG:root:Sequence length: 4, Groebner basis length: 2
DEBUG:root:Found Groebner basis with length 2, trying to find roots...
Found p = 7866790440964395011005623971351568677139336343167390105188826934257986271072664643571727955882500173182140478082778193338086048035817634545367411924942763 and q = 11227048386374621771175649743442169526805922745751610531569607663416378302561807690656370394330458335919244239976798600743588701676542461805061598571009923
```

The parameters `m` and `t` as shown in the output log deserve special attention. These parameters are used in many lattice-based (small roots) algorithms to tune the lattice size. Conceptually, `m` (sometimes called `k`) and `t` represent the number of "shifts" used in the lattice, which is roughly equal or proportional to the number of rows. Therefore, increasing `m` and `t` will increase the size of the lattice, which also increases the time required to perform lattice reduction (currently using LLL). On the other hand, if `m` and `t` are too low, it is possible that the lattice reduction will not result in appropriate vectors, therefore wasting the time spent reducing. Hence, this is a trade-off.

In the current version of the project, `m` must always be provided by the user (the default value is set to `1`). `t` can, in some cases, be computed based on the specific small roots method used by the attack. However it can still be tweaked by the user. In general, there are two ways to use these kinds of parameters:
* Implement a loop which starts at `m = 1` until an answer is found (example below). This is a simple approach, but risks wasting time on futile computations with too small lattices.
```
m = 1
while True:
    res = attack(..., m=m)
    if res is not None:
        # The attack succeeded!
        break
    m += 1
```
* Implement a debug version of the attack you're trying to use (with known results), and determine the `m` value which results in good lattice vectors. Then directly call the attack method with the correct `m` value.


## Implemented attacks
### Approximate Common Divisor
* [x] [Multivariate polynomial attack](attacks/acd/mp.py) [^acd_mp]
* [x] [Orthogonal based attack](attacks/acd/ol.py) [^acd_ol]
* [x] [Simultaneous Diophantine approximation attack](attacks/acd/sda.py) [^acd_sda]

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
* [x] [Bit flipping attack](attacks/ctr/bit_flipping.py)
* [x] [CRIME attack](attacks/ctr/crime.py)
* [x] [Separator oracle attack](attacks/ctr/separator_oracle.py)

### ECB
* [x] [Plaintext recovery attack](attacks/ecb/plaintext_recovery.py)
* [x] [Plaintext recovery attack (harder variant)](attacks/ecb/plaintext_recovery_harder.py)
* [x] [Plaintext recovery attack (hardest variant)](attacks/ecb/plaintext_recovery_harder.py)

### Elliptic Curve Cryptography
* [x] [ECDSA nonce reuse attack](attacks/ecc/ecdsa_nonce_reuse.py)
* [x] [Frey-Ruck attack](attacks/ecc/frey_ruck_attack.py) [^ecc_frey_ruck_attack]
* [x] [MOV attack](attacks/ecc/mov_attack.py) [^ecc_mov_attack]
* [x] [Parameter recovery](attacks/ecc/parameter_recovery.py)
* [x] [Singular curve attack](attacks/ecc/singular_curve.py)
* [x] [Smart's attack](attacks/ecc/smart_attack.py) [^ecc_smart_attack]

### ElGamal Encryption
* [x] [Nonce reuse attack](attacks/elgamal_encryption/nonce_reuse.py)
* [x] [Unsafe generator attack](attacks/elgamal_encryption/unsafe_generator.py)

### ElgGamal Signature
* [ ] Bleichenbacher's attack
* [ ] Khadir's attack
* [x] [Nonce reuse attack](attacks/elgamal_signature/nonce_reuse.py)

### Factorization
* [x] [Base conversion factorization](attacks/factorization/base_conversion.py)
* [x] [Branch and prune attack](attacks/factorization/branch_and_prune.py) [^factorization_branch_and_prune]
* [x] [Complex multiplication (elliptic curve) factorization](attacks/factorization/complex_multiplication.py) [^factorization_complex_multiplication]
* [x] [Coppersmith factorization](attacks/factorization/coppersmith.py)
* [x] [Fermat factorization](attacks/factorization/fermat.py)
* [x] [Ghafar-Ariffin-Asbullah attack](attacks/factorization/gaa.py) [^factorization_gaa]
* [x] [Implicit factorization](attacks/factorization/implicit.py) [^factorization_implicit]
* [x] [Known phi factorization](attacks/factorization/known_phi.py) [^factorization_known_phi]
* [x] [ROCA](attacks/factorization/roca.py) [^factorization_roca]
* [x] [Shor's algorithm (classical)](attacks/factorization/shor.py) [^factorization_shor]
* [x] [Twin primes factorization](attacks/factorization/twin_primes.py)
* [x] [Factorization of unbalanced moduli](attacks/factorization/unbalanced.py) [^factorization_unbalanced]

### GCM
* [x] [Forbidden attack](attacks/gcm/forbidden_attack.py) [^gcm_forbidden_attack]

### Hidden Number Problem
* [x] [Extended hidden number problem](attacks/hnp/extended_hnp.py) [^hnp_extended_hnp]
* [ ] Fourier analysis attack
* [x] [Lattice-based attack](attacks/hnp/lattice_attack.py)

### IGE
* [x] [Padding oracle attack](attacks/ige/padding_oracle.py)

### Knapsack Cryptosystems
* [x] [Low density attack](attacks/knapsack/low_density.py) [^knapsack_low_density]

### Linear Congruential Generators

* [x] [LCG parameter recovery](attacks/lcg/parameter_recovery.py)
* [x] [Truncated LCG parameter recovery](attacks/lcg/truncated_parameter_recovery.py) [^lcg_truncated_parameter_recovery]
* [x] [Truncated LCG state recovery](attacks/lcg/truncated_state_recovery.py) [^lcg_truncated_state_recovery]

### Learning With Errors

* [x] [Arora-Ge attack](attacks/lwe/arora_ge.py) [^lwe_arora_ge]
* [ ] Blum-Kalai-Wasserman attack
* [ ] Lattice reduction attack

### Mersenne Twister

* [x] [State recovery](attacks/mersenne_twister/state_recovery.py)

### One-time Pad

* [x] [Key reuse](attacks/otp/key_reuse.py)

### Pseudoprimes

* [x] [Generating Miller-Rabin pseudoprimes](attacks/pseudoprimes/miller_rabin.py) [^pseudoprimes_miller_rabin]

### RC4

* [x] [Fluhrer-Mantin-Shamir attack](attacks/rc4/fms.py)

### RSA

* [x] [Bleichenbacher's attack](attacks/rsa/bleichenbacher.py) [^rsa_bleichenbacher]
* [x] [Bleichenbacher's signature forgery attack](attacks/rsa/bleichenbacher_signature_forgery.py)
* [x] [Boneh-Durfee attack](attacks/rsa/boneh_durfee.py) [^rsa_boneh_durfee]
* [x] [Cherkaoui-Semmouni's attack](attacks/rsa/cherkaoui_semmouni.py) [^rsa_cherkaoui_semmouni]
* [x] [Common modulus attack](attacks/rsa/common_modulus.py)
* [x] [CRT fault attack](attacks/rsa/crt_fault_attack.py)
* [x] [d fault attack](attacks/rsa/d_fault_attack.py)
* [x] [Desmedt-Odlyzko attack (selective forgery)](attacks/rsa/desmedt_odlyzko.py) [^rsa_desmedt_odlyzko]
* [x] [Extended Wiener's attack](attacks/rsa/extended_wiener_attack.py) [^rsa_extended_wiener_attack]
* [x] [Hastad's broadcast attack](attacks/rsa/hastad_attack.py)
* [x] [Known CRT exponents attack](attacks/rsa/known_crt_exponents.py) [^rsa_known_crt_exponents]
* [x] [Known private exponent attack](attacks/rsa/known_d.py)
* [x] [Low public exponent attack](attacks/rsa/low_exponent.py)
* [x] [LSB oracle (parity oracle) attack](attacks/rsa/lsb_oracle.py)
* [x] [Manger's attack](attacks/rsa/manger.py) [^rsa_manger]
* [x] [Nitaj's CRT-RSA attack](attacks/rsa/nitaj_crt_rsa.py) [^rsa_nitaj_crt_rsa]
* [x] [Non coprime public exponent attack](attacks/rsa/non_coprime_exponent.py) [^rsa_non_coprime_exponent]
* [x] [Partial key exposure](attacks/rsa/partial_key_exposure.py) [^rsa_partial_key_exposure1] [^rsa_partial_key_exposure2] [^rsa_partial_key_exposure3] 
* [x] [Related message attack](attacks/rsa/related_message.py)
* [x] [Stereotyped message attack](attacks/rsa/stereotyped_message.py)
* [x] [Wiener's attack](attacks/rsa/wiener_attack.py)
* [x] [Wiener's attack for Common Prime RSA](attacks/rsa/wiener_attack_common_prime.py) [^rsa_wiener_attack_common_prime]
* [x] [Wiener's attack (Heuristic lattice variant)](attacks/rsa/wiener_attack_lattice.py) [^rsa_wiener_attack_lattice] [^rsa_wiener_attack_lattice_extended] [^small_roots_aono]

### Shamir's Secret Sharing
* [x] [Deterministic coefficients](attacks/shamir_secret_sharing/deterministic_coefficients.py)
* [x] [Share forgery](attacks/shamir_secret_sharing/share_forgery.py)

## Other interesting implementations
* [x] [Adleman-Manders-Miller root extraction method](shared/__init__.py) [^adleman_manders_miller]
* [x] [Fast CRT using divide-and-conquer](shared/crt.py)
* [x] [Fast modular inverses](shared/__init__.py)
* [x] [Linear Hensel lifting](shared/hensel.py)
* [ ] Quadratic Hensel lifting
* [x] [Babai's Nearest Plane Algorithm](shared/lattice.py)
* [x] [Matrix discrete logarithm](shared/matrices.py)
* [x] [Matrix discrete logarithm (equation)](shared/matrices.py)
* [x] [PartialInteger](shared/partial_integer.py)
* [x] [Fast polynomial GCD using half GCD](shared/polynomial.py)

### Elliptic Curve Generation
* [x] [Complex multiplication](shared/ecc.py)
* [x] [Anomalous curves](shared/ecc.py)
* [x] [MNT curves](shared/ecc.py)
* [x] [Prescribed order](shared/ecc.py)
* [x] [Prescribed trace](shared/ecc.py)
* [x] [Supersingular curves](shared/ecc.py)

### Small Roots
* [x] [Polynomial roots using Groebner bases](shared/small_roots/__init__.py)
* [x] [Polynomial roots using resultants](shared/small_roots/__init__.py)
* [x] [Polynomial roots using Sage variety (triangular decomposition)](shared/small_roots/__init__.py)
* [x] [Aono method (Minkowski sum lattice)](shared/small_roots/aono.py) [^small_roots_aono]
* [x] [Blomer-May method](shared/small_roots/blomer_may.py) [^small_roots_blomer_may]
* [x] [Boneh-Durfee method](shared/small_roots/boneh_durfee.py) [^rsa_boneh_durfee]
* [x] [Coron method](shared/small_roots/coron.py) [^small_roots_coron]
* [x] [Coron method (direct)](shared/small_roots/coron_direct.py) [^small_roots_coron_direct]
* [x] [Ernst et al. methods](shared/small_roots/ernst.py) [^rsa_partial_key_exposure2]
* [x] [Herrmann-May method (unravelled linearization)](shared/small_roots/herrmann_may.py) [^small_roots_herrmann_may]
* [x] [Herrmann-May method (modular multivariate)](shared/small_roots/herrmann_may_multivariate.py) [^small_roots_herrmann_may_multivariate]
* [x] [Howgrave-Graham method](shared/small_roots/howgrave_graham.py) [^small_roots_howgrave_graham]
* [x] [Jochemsz-May method (modular roots)](shared/small_roots/jochemsz_may_modular.py) [^small_roots_jochemsz_may_modular]
* [x] [Jochemsz-May method (integer roots)](shared/small_roots/jochemsz_may_integer.py) [^small_roots_jochemsz_may_integer]
* [x] [Nitaj-Fouotsa method](shared/small_roots/nitaj_fouotsa.py) [^small_roots_nitaj_fouotsa]

[^acd_mp]: Galbraith D. S. et al., "Algorithms for the Approximate Common Divisor Problem" (Section 5)
[^acd_ol]: Galbraith D. S. et al., "Algorithms for the Approximate Common Divisor Problem" (Section 4)
[^acd_sda]: Galbraith D. S. et al., "Algorithms for the Approximate Common Divisor Problem" (Section 3)

[^ecc_frey_ruck_attack]: Harasawa R. et al., "Comparing the MOV and FR Reductions in Elliptic Curve Cryptography" (Section 3)
[^ecc_mov_attack]: Harasawa R. et al., "Comparing the MOV and FR Reductions in Elliptic Curve Cryptography" (Section 2)
[^ecc_smart_attack]: Smart N. P., "The discrete logarithm problem on elliptic curves of trace one"

[^factorization_branch_and_prune]: Heninger N., Shacham H., "Reconstructing RSA Private Keys from Random Key Bits"
[^factorization_complex_multiplication]: Sedlacek V. et al., "I want to break square-free: The 4p - 1 factorization method and its RSA backdoor viability"
[^factorization_gaa]: Ghafar AHA. et al., "A New LSB Attack on Special-Structured RSA Primes"
[^factorization_implicit]: Nitaj A., Ariffin MRK., "Implicit factorization of unbalanced RSA moduli"
[^factorization_known_phi]: Hinek M. J., Low M. K., Teske E., "On Some Attacks on Multi-prime RSA" (Section 3)
[^factorization_roca]: Nemec M. et al., "The Return of Coppersmith’s Attack: Practical Factorization of Widely Used RSA Moduli"
[^factorization_shor]: M. Johnston A., "Shor’s Algorithm and Factoring: Don’t Throw Away the Odd Orders"
[^factorization_unbalanced]: Brier E. et al., "Factoring Unbalanced Moduli with Known Bits" (Section 4)

[^gcm_forbidden_attack]: Joux A., "Authentication Failures in NIST version of GCM"

[^hnp_extended_hnp]: Hlavac M., Rosa T., "Extended Hidden Number Problem and Its Cryptanalytic Applications" (Section 4) 

[^knapsack_low_density]: Coster M. J. et al., "Improved low-density subset sum algorithms"

[^lcg_truncated_parameter_recovery]: Contini S., Shparlinski I. E., "On Stern's Attack Against Secret Truncated Linear Congruential Generators"
[^lcg_truncated_state_recovery]: Frieze, A. et al., "Reconstructing Truncated Integer Variables Satisfying Linear Congruences"

[^lwe_arora_ge]: ["The Learning with Errors Problem: Algorithms"](https://people.csail.mit.edu/vinodv/6876-Fall2018/lecture2.pdf) (Section 1)

[^pseudoprimes_miller_rabin]: R. Albrecht M. et al., "Prime and Prejudice: Primality Testing Under Adversarial Conditions"

[^rsa_bleichenbacher]: Bleichenbacher D., "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"
[^rsa_boneh_durfee]: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"
[^rsa_cherkaoui_semmouni]: Cherkaoui-Semmouni M. et al., "Cryptanalysis of RSA Variants with Primes Sharing Most Significant Bits"
[^rsa_desmedt_odlyzko]: Coron J. et al., "Practical Cryptanalysis of ISO 9796-2 and EMV Signatures (Section 3)"
[^rsa_extended_wiener_attack]: Dujella A., "Continued fractions and RSA with small secret exponent"
[^rsa_known_crt_exponents]: Campagna M., Sethi A., "Key Recovery Method for CRT Implementation of RSA"
[^rsa_manger]: Manger J., "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0"
[^rsa_nitaj_crt_rsa]: Nitaj A., "A new attack on RSA and CRT-RSA"
[^rsa_non_coprime_exponent]: Shumow D., "Incorrectly Generated RSA Keys: How To Recover Lost Plaintexts"
[^rsa_partial_key_exposure1]: Boneh D., Durfee G., Frankel Y., "An Attack on RSA Given a Small Fraction of the Private Key Bits"
[^rsa_partial_key_exposure2]: Ernst M. et al., "Partial Key Exposure Attacks on RSA Up to Full Size Exponents"
[^rsa_partial_key_exposure3]: Blomer J., May A., "New Partial Key Exposure Attacks on RSA"
[^rsa_wiener_attack_common_prime]: Jochemsz E., May A., "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants" (Section 5)
[^rsa_wiener_attack_lattice]: Nguyen P. Q., "Public-Key Cryptanalysis"
[^rsa_wiener_attack_lattice_extended]: Howgrave-Graham N., Seifert J., "Extending Wiener’s Attack in the Presence of Many Decrypting Exponents"

[^adleman_manders_miller]: Cao Z. et al., "Adleman-Manders-Miller Root Extraction Method Revisited" (Section 5)

[^small_roots_aono]: Aono Y., "Minkowski sum based lattice construction for multivariate simultaneous Coppersmith's technique and applications to RSA" (Section 4)
[^small_roots_blomer_may]: Blomer J., May A., "New Partial Key Exposure Attacks on RSA" (Section 6)
[^small_roots_coron]: Coron J., "Finding Small Roots of Bivariate Integer Polynomial Equations Revisited"
[^small_roots_coron_direct]: Coron J., "Finding Small Roots of Bivariate Integer Polynomial Equations: a Direct Approach"
[^small_roots_herrmann_may]: Herrmann M., May A., "Maximizing Small Root Bounds by Linearization and Applications to Small Secret Exponent RSA"
[^small_roots_herrmann_may_multivariate]: Herrmann M., May A., "Solving Linear Equations Modulo Divisors: On Factoring Given Any Bits" (Section 3 and 4)
[^small_roots_howgrave_graham]: May A., "New RSA Vulnerabilities Using Lattice Reduction Methods" (Section 3.2)
[^small_roots_jochemsz_may_modular]: Jochemsz E., May A., "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants" (Section 2.1)
[^small_roots_jochemsz_may_integer]: Jochemsz E., May A., "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants" (Section 2.2)
[^small_roots_nitaj_fouotsa]: Nitaj A., Fouotsa E., "A New Attack on RSA and Demytko's Elliptic Curve Cryptosystem"
