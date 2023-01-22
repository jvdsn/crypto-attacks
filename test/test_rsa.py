import os
import sys
from hashlib import sha256
from math import lcm
from random import getrandbits
from random import randrange
from unittest import TestCase

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from sage.all import crt

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.rsa import bleichenbacher
from attacks.rsa import bleichenbacher_signature_forgery
from attacks.rsa import boneh_durfee
from attacks.rsa import cherkaoui_semmouni
from attacks.rsa import common_modulus
from attacks.rsa import crt_fault_attack
from attacks.rsa import d_fault_attack
from attacks.rsa import desmedt_odlyzko
from attacks.rsa import extended_wiener_attack
from attacks.rsa import hastad_attack
from attacks.rsa import known_crt_exponents
from attacks.rsa import known_d
from attacks.rsa import low_exponent
from attacks.rsa import lsb_oracle
from attacks.rsa import manger
from attacks.rsa import nitaj_crt_rsa
from attacks.rsa import non_coprime_exponent
from attacks.rsa import partial_key_exposure
from attacks.rsa import related_message
from attacks.rsa import stereotyped_message
from attacks.rsa import wiener_attack
from attacks.rsa import wiener_attack_common_prime
from attacks.rsa import wiener_attack_lattice
from shared.partial_integer import PartialInteger


class TestRSA(TestCase):
    def _crt_faulty_sign(self, m, p, q, d):
        sp = pow(m, (d % (p - 1)), p)
        sq = pow(m, (d % (q - 1)), q)
        # Random bitflip?
        return crt([sp, sq ^ 1], [p, q])

    def _valid_padding_v1_5(self, cipher, k, c, sentinel):
        return cipher.decrypt(c.to_bytes(k, byteorder="big"), sentinel) != sentinel

    def _valid_padding_oaep(self, n, d, B, c):
        return pow(c, d, n) < B

    def test_bleichenbacher(self):
        p = 8371433218848358145038188834376952780015970046874950635276595345380605659774957836526221018721547441806561287602735774125878237978059976407232379361297183
        q = 11466377869587829648871708469119992174705652479796097233499813683057983019116298140412758762054846456284362676185136356912754651085919371755263313171141577
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        k = 128
        cipher = PKCS1_v1_5.new(RSA.construct((n, e, d)))
        sentinel = b"\x00" * k;

        # We know it doesn't take too long to decrypt this c using Bleichenbacher's attack (~7700 queries).
        c = 41825379700061736537842449489601003429572348310436151924728709132681706878857980459161227458335791180711615257337302674792944628957924785690808047623816090305399357488221035015598239161665727483209037254608986214222956682098319678174134123989991914343760644546568563066348494878863941359213637733834134515197
        m = pow(c, d, n)
        m_ = bleichenbacher.attack(lambda c: self._valid_padding_v1_5(cipher, k, c, sentinel), n, e, c)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)

    def test_bleichenbacher_signature_forgery(self):
        suffix_bit_length = 32
        suffix = getrandbits(suffix_bit_length) | 1
        s = bleichenbacher_signature_forgery.attack(suffix, suffix_bit_length)
        self.assertEqual(suffix, (s ** 3) % (2 ** suffix_bit_length))

    def test_boneh_durfee(self):
        p = 11227048386374621771175649743442169526805922745751610531569607663416378302561807690656370394330458335919244239976798600743588701676542461805061598571009923
        q = 7866790440964395011005623971351568677139336343167390105188826934257986271072664643571727955882500173182140478082778193338086048035817634545367411924942763
        N = p * q
        phi = (p - 1) * (q - 1)
        d = 186493804207318317888355025415200212277761144340233864189538741099969492009806507
        e = pow(d, -1, phi)
        p_, q_ = boneh_durfee.attack(N, e, 512, delta=0.26, m=3, t=1)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p = 7429785514579250742801544775265919278101812347596990219952070295565832940068576050760172625797740177649856558303705228580697611655581924559792513787731167
        q = 8956454992912744191779370381876516510424600089358399536385007696509658160926748770877487393045391618009844430934391226063349509549521733003051142111030287
        N = p * q
        phi = (p - 1) * (q - 1)
        d = 223183300830113475659369178959679373721083232456560212434233450629223847114638106475011
        e = pow(d, -1, phi)
        p_, q_ = boneh_durfee.attack(N, e, 512, partial_p=PartialInteger.lsb_of(p, 512, 128), delta=0.28, m=1, t=0)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p = 8325745168193178400972753040703564893084541200047412976661161282688302811539795532035273420999644691751298134426448708785219125098284622056451489331098141
        q = 7080360719238751828185760219712847628159086532214243460775078410347307461032019124186884558243018527644736008056891972556933157682087344942706360469169019
        r = 8317461401474723268496312721678641458178047856339708030999240370931245730754892293396238744093254583460495063266635764778620495121324799900121222370364617
        s = 13199869133047572552535353227205776086152310145389840540109659625854798126285664271625603061537083584881441157707264706431629568363715148727252158453179283
        N = p * q * r * s
        phi = (p - 1) * (q - 1) * (r - 1) * (s - 1)
        d = 49488085514473555048624238840378082040802728458021785503334637098083
        e = pow(d, -1, phi)
        p_, q_, r_, s_ = boneh_durfee.attack_multi_prime(N, e, 512, 4, delta=0.1, m=6, t=1)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertIsInstance(r_, int)
        self.assertIsInstance(s_, int)
        self.assertEqual(N, p_ * q_ * r_ * s_)

    def test_cherkaoui_semmouni(self):
        p = 6970095733639071098312656967411917275080643486698328141048794358773925405193762089371592275422356527243822408600697915626180888948121089544657377661918979
        q = 18449203001167453683629192798359337118936602406279119934040327468259582280616884846975771623742879592317716054643763931279691320991968677567970772946431553
        N = p * q
        e = 656004714415520925304508553062370903160906373260831418376155234031103953028701728516709845078613446850436012766664203901926239975184100878753982194671184344505363800201667709052712179034821539184811191176529116980190742276358408178606066309312751094947345719752727377127867556038310739729060906061649394093586530631375649773615277283004263492460300787257925544540880532938726325093230854039509246401675172466582706119200957333207569754235900939815154013060113002778680466566882320776451125153612349115209357634306021723449044334437447021870514950670965340761003414186271235218807491067981771194625563633604657797629
        d = pow(e, -1, (p ** 2 - 1) * (q ** 2 - 1))
        beta = 0.5
        delta = 0.54
        p_, q_, d_ = cherkaoui_semmouni.attack(N, e, beta, delta, m=5)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertIsInstance(d_, int)
        self.assertEqual(N, p_ * q_)
        self.assertEqual(d, d_)

    def test_common_modulus(self):
        p = 7533786619797084306332779503584785720237908463304409345290805538825354595934248304351730420702977327869673269459606431198799644428816355505475872341745119
        q = 11736209613542675168896166783523457796515430159358741698291601755512636680940041591293981708617818996457987754784026535146391007150954925977654218732583633
        n = p * q
        e1 = 65537
        c1 = pow(2, e1, n)
        e2 = 65539
        c2 = pow(2, e2, n)
        m = common_modulus.attack(n, e1, c1, e2, c2)
        self.assertIsInstance(m, int)
        self.assertEqual(2, m)

    def test_crt_fault_attack(self):
        p = 8150877473027126093427463792139267852911319917170724105457477564851230704467622727076433793531165751815106108729858930625206375479823641419198589291521783
        q = 8132196267040442193310214709294656320409440622341548548251972647317954574860663207153805527629987938053400479709802456536736870430458263552910515400645909
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        p_, q_ = crt_fault_attack.attack_known_m(n, e, 2, self._crt_faulty_sign(2, p, q, d))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

        p_, q_ = crt_fault_attack.attack_unknown_m(n, e, pow(2, d, n), self._crt_faulty_sign(2, p, q, d))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

    def test_d_fault_attack(self):
        p = 11711858679422576139240623353912034730578750025305511997160442356437636294934848077337818067479185593605531008093226275733420002636468432350557846723886129
        q = 11362676749997147110865246846859793005675832462810186294516539616676027025614775954113496330880795201537135407817378604172135795945348591541580522484363839
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        sv = pow(2, d, n)
        sf = []
        for i in range(d.bit_length()):
            sf.append(pow(2, d ^ (2 ** i), n))
        d_ = d_fault_attack.attack(n, e, sv, sf)
        self.assertIsInstance(d_, PartialInteger)
        lsb, lsb_bit_length = d_.get_known_lsb()
        self.assertIsInstance(lsb, int)
        self.assertIsInstance(lsb_bit_length, int)
        self.assertEqual(d, lsb)
        self.assertEqual(d.bit_length(), lsb_bit_length)

        sf = []
        for i in range(384):
            sf.append(pow(2, d ^ (2 ** i), n))
        d_ = d_fault_attack.attack(n, e, sv, sf)
        self.assertIsInstance(d_, PartialInteger)
        lsb, lsb_bit_length = d_.get_known_lsb()
        self.assertIsInstance(lsb, int)
        self.assertIsInstance(lsb_bit_length, int)
        self.assertEqual(d % (2 ** 384), lsb)
        self.assertEqual(384, lsb_bit_length)

    def test_desmedt_odlyzko(self):
        p = 97164923933597891368559775050432519012034358306405340946100833095770328943676411310628656642026913097035188965406025957744495809556827045737345114790763524883526919749849156670762148425581036752109600896844274905771163440683527068529651911795698170268844514398131442858441702974028897564993245872764301596397
        q = 109712022838692588796818474700409969126344450902860551087011803034678579584276407066098123240292070455715313066927016909739145402676756809804326474562269097078787526578676643824546284396305927118696509187348588587237261529370838503470176017203514480490343882354075192486431376267056466433423025173883070036753
        e = 65537
        N = p * q
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        hash_oracle = lambda m: int.from_bytes(sha256(int.to_bytes(m, length=256, byteorder="big")).digest()[:6], byteorder="big")
        sign_oracle = lambda m: pow(hash_oracle(m), d, N)
        m = 226572932144966770252674249388577138444
        s = desmedt_odlyzko.attack(hash_oracle, sign_oracle, N, e, m)
        self.assertIsInstance(s, int)
        self.assertEqual(sign_oracle(m), s)

    def test_extended_wiener_attack(self):
        p = 8962183829526343305205665485515731618546029297439020752534914809943234334520404067067844789415616008948709769282722944473756884384422045609586429488722819
        q = 11411892842209276999318813933411657011974573219176710970747439412565013759888750685922800578656539187278906477356731952452991129515326613660882430066260819
        n = p * q
        phi = (p - 1) * (q - 1)
        d = 440954678851095847880440879288062150659228888630394444179267052000328032629057
        e = pow(d, -1, phi)
        p_, q_, d_ = extended_wiener_attack.attack(n, e)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertIsInstance(d_, int)
        self.assertEqual(n, p_ * q_)
        self.assertEqual(d, d_)

    def test_hastad_attack(self):
        p1 = 12238840029255924128261773522963221621618780074771826797770294317526342852350770883811112904932108204101484192491928770368834167240882579171193850986455837
        q1 = 13306004827159916516668671929416638896131274743270820358013499224556726271497309928832980035890202435607219787395468188298808904166109749334050937132938949
        N1 = p1 * q1
        p2 = 9149751951348929830842108648504857237452181353320105251018875434647249480437833769024227357098540650986406158506119142206123567682084983914483649896955031
        q2 = 10962586930565548132182648587084973374856002202116447680609772870896293614345215136882972661918694230862242667644357410793563474164022674847478495643859707
        N2 = p2 * q2
        p3 = 11284208912156948389112340915544186206038140125122638896201517533912332670535585694142522536564438510193351757394235927874009400917334726959807635615623447
        q3 = 7144946753190813042748893143186445123501153567914769538177683884450935779036215877932244882643383332398676793582493702385999026643632800861421136743084943
        N3 = p3 * q3
        N = [N1, N2, N3]
        e = 3
        m = randrange(1, min(N))
        c = [pow(m, e, n) for n in N]
        m_ = hastad_attack.attack(N, e, c)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)

    def test_known_crt_exponents(self):
        p = 9734878849445118420073785869554836149487671692719552358756738189651079813869054963335880039395402041883956221923435780797276507555906725160774871585184181
        q = 11608927577332560028819160266239104364716512653498293226451614650722863458488829019269383773936258272349564355274218301207779572980847476544743569746719093
        N = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        dp = d % (p - 1)
        dq = d % (q - 1)

        p_, q_ = next(known_crt_exponents.attack(e, e + 2, N=N, dp=dp, dq=dq))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p_, q_ = next(known_crt_exponents.attack(e, e + 2, N=N, dp=dp))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p_, q_ = next(known_crt_exponents.attack(e, e + 2, N=N, dq=dq))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p_, q_ = next(known_crt_exponents.attack(e, e + 2, dp=dp, dq=dq, p_bit_length=512, q_bit_length=512))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p_ = next(known_crt_exponents.attack(e, e + 2, dp=dp, p_bit_length=512))
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)

        q_ = next(known_crt_exponents.attack(e, e + 2, dq=dq, q_bit_length=512))
        self.assertIsInstance(q_, int)
        self.assertEqual(q, q_)

    def test_known_d(self):
        p = 10999882285407021659159843781080979389814097626452668846482424135627220062700466847567575264657287989126943263999867722090759547565297969535143544253926071
        q = 12894820825544912052042889653649757120734073367261758361676140208842841153775542379620171049124260330205408767340830801133280422958906941622318918402459837
        N = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        p_, q_ = known_d.attack(N, e, d)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_low_exponent(self):
        p = 9986125479694016854025755367445175452530216355562157491330590823336719733036951311021826749434458567507026083133496160725058402273547442823833685509967273
        q = 12293819014809525648804227133537870654400268644981770162408394971640722282699968884616070906255021397809508228502095517082589847093280122278875399671016389
        N = p * q
        e = 3
        m = 2
        c = pow(m, e, N)
        m_ = low_exponent.attack(e, c)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)

    def test_lsb_oracle(self):
        p = 12985611093825944663135178568290848860236181456084556611626171071415242183946266010353415826192399871882183745902546414611421756977935905528192863016989159
        q = 13073385370532298716818627887268175297799825572859798576497950347156227722627325929275754625614964552408176766458085714046147326787707303279702573013743377
        N = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        m = randrange(1, N)
        c = pow(m, e, N)
        m_ = lsb_oracle.attack(N, e, c, lambda c: pow(c, d, N) & 1)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)

    def test_manger(self):
        p = 11550140397625831237795340388931764619590203348477070899900744712142057429184408396002838334752152208585447782690486121190515605653404086833126302256665293
        q = 11235144439517708878544315543777445305219755865213735904183809061384223163112309675101975657775860815518111926557521605302651507623721470417911684612028139
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        k = 128
        B = 2 ** (8 * (k - 1))

        # We know it doesn't take too long to decrypt this c using Manger's attack (~1000 queries).
        c = 88724310553655024406998673890906955926769391892532500091257501059546128411164957509885727337380526571122120832873601676837576704085217211100300291225160276367472411100146256463969941418608788600822191439544173046896875356040910136817300727665043174773434871223215069772985286442145129776197191070321384162933
        m = pow(c, d, n)
        m_ = manger.attack(lambda c: self._valid_padding_oaep(n, d, B, c), n, e, c)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)

    def test_nitaj_crt_rsa(self):
        # Section 5.1
        p = 1965268334695819089811552114253
        q = 1397509985733832541423163654649
        N = p * q
        e = 1908717316858446782674807627631

        p_, q_ = nitaj_crt_rsa.attack(N, e, 0.09, m=4, t=2)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_non_coprime_exponent(self):
        # Small primes because the attack needs to perform dlog with order p/q at some point.
        p = 274313782073159601209986688053803756589
        q = 232117885131324883095053819722121078767
        N = p * q
        phi = (p - 1) * (q - 1)

        for e in [3, 7, 31, 397]:
            m = randrange(1, N)
            c = pow(m, e, N)
            for m_ in non_coprime_exponent.attack(N, e, phi, c):
                self.assertIsInstance(m_, int)
                if m_ == m:
                    break
            else:
                self.fail()

    def test_partial_key_exposure(self):
        p = 10910578377493709111333790184427664202765704106579350486788097192764075505932456611273616722978391482349202742319580571195628069062856385333010738300159289
        q = 9543709188272129636130984528523762431366215631912419189389727421314687517826682117237804919302025420051881375430279526592105566649224606602944612854468009
        N = p * q
        phi = (p - 1) * (q - 1)

        e = 1888808636394051038122079426072690800814635584317577992534820937057888325091552888007695019685284192811882682070476179005
        d = pow(e, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.lsb_and_msb_of(d, 1024, 300, 400), m=4, t=4)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        e = 2537076837624948274678559350627766245659466751393060011134223900150777497232270599983842219210375152450024925559795004985
        d = pow(e, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.lsb_of(d, 1024, 900), m=3, t=1)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        e = 2105349305652912552595850746930492757880185195571479788917556245368402422744117397035736756548330291811495322726318885363734942001084342282438104629063513807868365772702460864019481
        d = pow(e, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.lsb_of(d, 1024, 1000), m=4, t=1)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        d = 3043512099664998067963851819644406828326540226040840386777757880704658912729542968149616478325704429171610434683689846221877333398784455635377825449441
        e = pow(d, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.lsb_of(d, 500, 450), m=2, t=1)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        e = 13
        d = pow(e, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.lsb_of(d, 1024, 300), m=4, t=4)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        e = 1342190465933073539882079424718736636251811109323478531285823066337637602613426487933457123523547784034204609585360266973
        d = pow(e, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.msb_of(d, 1024, 400), m=4, t=4)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        e = 2202357547053544325766272244614293754573709727782759369088138744825304061898264253795423228965992747533679851108128668707
        d = pow(e, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.msb_of(d, 1024, 700), factor_e=False)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        e = 3570933230773454036103400438523094494860730146879558128058270144959251135492234076661103748194173734451656482351563013457204873521151688759417651289937071689065482923
        d = pow(e, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.msb_of(d, 1024, 800), m=1, t=1)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        d = 1659574478146748254056351432273021460473735684664103384774766229138469185471407591788312141
        e = pow(d, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.msb_of(d, 300, 100), m=1, t=0)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        d = 1996027597381396159237243762593978890017801760275363686545665967267636096782071826097658259
        e = pow(d, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.msb_of(d, 300, 200), m=1, t=0)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        d = 3761842282390824725562943876986788316204251238160857472939673032260930840975186728596615197353278383991036677817804509912115342372613650607583423246001467907396859682584848725034711
        e = pow(d, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.msb_of(d, 600, 470), m=2, t=2)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        d = 3691180879554463786414032222552684036869061510418768071690705916691156971385612730312759706623469266619987662041149793023083742711174850519419974605626258130331917527225448076142783
        e = pow(d, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.msb_of(d, 600, 500), m=2, t=0)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        d = 4905300283357849777532376964856253872884896201321425321351015817211702681734510535471350537031834978240585713416514372877338525414401276727225442844983999756914527067870650280651385699873418363576218246007433933765243491292205
        e = pow(d, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.msb_of(d, 750, 745), m=2, t=1)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

        e = 4767842339321110001693689370200744188846086437972267976524065388471471723930990821354799430207822500359946317313395866439324920870720597904488739040160497744807293179379758447729820982374513639776505527597410218540393194583329
        d = pow(e, -1, phi)
        p_, q_, d_ = partial_key_exposure.attack(N, e, PartialInteger.msb_of(d, 1024, 1000), m=2, t=2)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        self.assertIsInstance(d_, int)
        self.assertEqual(d, d_)

    def test_related_message(self):
        p = 10690180235993276891093400056791694809626283946283502730568453512667872959585945785000451667658654678765261068382803043783613229940134674528737814179937039
        q = 7411762482525629906544393574184843204602167584303799343260372455173145005371192234447957537905840062346600154282121917547245422064154573318186796475819689
        N = p * q
        e = 1031

        m = 23666958939524101790258867720194152525320477517345668323487634285244809978431237084284966124443690088207420025855469792839817825751436552953357446092968581196135202083607268708161603982373715275645009539354114191781584252216616624903344208624218982897101882857866276445862837761774020714270528809722325935521
        m1 = m
        m2 = (m - 1) // 2
        c1 = pow(m1, e, N)
        c2 = pow(m2, e, N)
        m_ = related_message.attack(N, e, c1, c2, lambda x: x, lambda x: (x - 1) / 2)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)

        m = 42754674989053816443283755519950895884283393756241669686434758905157442774529527621615381748254419989786450757822289696411178987745998626455343863537512644055792678166036284930353109587229444597470543710233826871159008532286491252285935227027264995423631527072606598822086150352244744620473824760160714055480
        m1 = m
        m2 = m + 1234567
        c1 = pow(m1, e, N)
        c2 = pow(m2, e, N)
        m_ = related_message.attack(N, e, c1, c2, lambda x: x, lambda x: x + 1234567)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)

        m = 10136879005392890573742803235085883362530393373945578790262356784957820270668573158361435468800458889870260003849261075198298468522200348709133410088411354435142239153233867101217611563773642614889380571544851400417624723436256642495193929038862837559861769334382514380181448468789100535710415683242258774349
        m1 = m
        m2 = ((m - 1) // 2) + 1234567
        c1 = pow(m1, e, N)
        c2 = pow(m2, e, N)
        m_ = related_message.attack(N, e, c1, c2, lambda x: x, lambda x: (x - 1) / 2 + 1234567)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)

        e = 17

        m = 53224653000473859937061720210017815788685481409955481700796925475147904449592533666897613424328988025976813324933929389695967421938433152183621524617367658473414117389230777531628581382338897188548318700570777346991214418473859214104540988647266458412244959766884014484065581348909258828921355728259479695761
        # 2^10 possibilities, finishes quite quickly.
        x = ((1 << 900) | (1 << 800) | (1 << 700) | (1 << 600) | (1 << 500) | (1 << 400) | (1 << 300) | (1 << 200) | (1 << 100) | (1 << 0))
        m1 = m
        m2 = m ^ x
        c1 = pow(m1, e, N)
        c2 = pow(m2, e, N)
        for m_ in related_message.attack_xor(N, e, c1, c2, x):
            self.assertIsInstance(m_, int)
            if m_ == m:
                break
        else:
            self.fail()

    def test_stereotyped_message(self):
        p = 9427799621011951541928982832607077548740094159448220696315390638465327417349606285858243970722509063632354007970943596939810149951744601156359969671857449
        q = 11870402454659943941264241250285724555674252791764405289506083966512661811544805338494879563927626484667192683911307016139516417804102333067626665881499791
        N = p * q
        e = 7
        m = randrange(2 ** 1023, N)
        c = pow(m, e, N)

        m_ = stereotyped_message.attack(N, e, c, PartialInteger.lsb_of(m, 1024, 950), m=2)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)
        m_ = stereotyped_message.attack(N, e, c, PartialInteger.lsb_and_msb_of(m, 1024, 475, 475), m=2)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)
        m_ = stereotyped_message.attack(N, e, c, PartialInteger.msb_of(m, 1024, 950), m=2)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)

    def test_wiener_attack(self):
        p = 9216552630349497248854461148903581877939724838581072236002328187229938158716983013925360355301876965491548210304574562739493228847611293721830637308804193
        q = 6933923262781683366316472659407081840385285455077122235753449057801539822308174027541202209776857105782337372767555342676749125109168114988291773001406719
        N = p * q
        phi = (p - 1) * (q - 1)
        d = 82656209786119546586793013314401325784594131342654070912205833037942868600641
        e = pow(d, -1, phi)
        p_, q_, d_ = wiener_attack.attack(N, e)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertIsInstance(d_, int)
        self.assertEqual(N, p_ * q_)
        self.assertEqual(d, d_)

    def test_wiener_attack_common_prime(self):
        p = 6782064950424760710980284774219634491993236863153483768598482045213175969155112496910085683689731379194662789263026739644356045047675956598858137448376083
        q = 8504790992500016807878718231498496399986587899005250624106963488787126208070626038486629561793688885242005440622123291666782461185365857422920183086563257
        N = p * q
        # Need lcm here to force e to be smaller.
        phi = lcm(p - 1, q - 1)
        d = 23036500924799795486061779142562236752665840004239
        e = pow(d, -1, phi)
        delta = 0.1604
        p_, q_, d_ = wiener_attack_common_prime.attack(N, e, delta, m=1, t=0)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_wiener_attack_lattice(self):
        p = 10058836956790351250887686696724836874393543803785063208855808993934035100716802252422366234311980376453091436742252598818654765951361743967196495143096063
        q = 10874001113447900956838154496899246824857806872110954653566017237316332619466657937241496309167189150705694237173990171548696731451069336818563931754583387
        N = p * q
        phi = (p - 1) * (q - 1)
        d = 65497726446129917535365626530327009614546242659268294033768073839686674115671
        e = pow(d, -1, phi)
        p_, q_, d_ = wiener_attack_lattice.attack(N, e)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertIsInstance(d_, int)
        self.assertEqual(N, p_ * q_)
        self.assertEqual(d, d_)

        p = 9707373803482895302134377941530620744662741435056530454118604655267069802831286734100930399853708141102721652973554127197649680587921565049539702212698839
        q = 11374685136137203310158373170671675072705752349722317349866285582140309231812087871100889632499496096613924217040608367074870751492553593548559208079478557
        N = p * q
        phi = (p - 1) * (q - 1)
        d = [29896979653954399311751172291337375021672580779310033411186490650071193093363524464620071224022833837646114789024463,
             25019854538325061792107522866225799565927112598302865902080648493253018459108447971385795260436625922940902252013967,
             33452119777334311282342590383548706508886474905055793530578662627818750047465037484869963980006683951515949908786219,
             30902176945037488323367762338464400186721996670348084941392669024310917493670960101204134813192892530148698376953479,
             34365029755561497376760468700540970025939428887363568419050786877025924818487442157630749173355183822291724562936769]
        e = [pow(dk, -1, phi) for dk in d]
        p_, q_ = wiener_attack_lattice.attack_multiple_exponents_1(N, e, alpha=0.375)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p = 9610376535888820350441263004216300807757213335939445761929202141525695641129196390963964051051856250223687604455958313679422621134259277770246808689501543
        q = 10876741663314961593583004986176743880058095473762017590699463239387487301131642005673032882478524536830364724693892288182401553704334345687286569103637863
        N = p * q
        phi = (p - 1) * (q - 1)
        d = [20522228326090744624755016835235156729825931424580937329081408545393078837487022188538702300004614386298757746546061,
             27135032143777044064136798941245801906727565702470326573886220420774171519803529965228172508985262077535951244037307,
             28445544562457171120459201550759208975761283606631130491647251601696334323412204311690811198015516559492511378774121]
        e = [pow(dk, -1, phi) for dk in d]
        p_, q_ = wiener_attack_lattice.attack_multiple_exponents_2(N, e, d_bit_length=384)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
