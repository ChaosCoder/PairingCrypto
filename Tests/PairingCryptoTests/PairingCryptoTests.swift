import XCTest
import CPBC
@testable import PairingCrypto

class PairingCryptoTests: XCTestCase {

    var pC: PairingCrypto!

    override func setUp() {
        let params = ["type d",
            "q 15028799613985034465755506450771565229282832217860390155996483840017",
            "n 15028799613985034465755506450771561352583254744125520639296541195021",
            "h 1",
            "r 15028799613985034465755506450771561352583254744125520639296541195021",
            "a 4837927934107378423339066070805463849457380430819166138226504036334",
            "b 12600964080945706731203367184353424467571143684092960876304910375379",
            "k 6",
            "nk 11522474695025217370062603013790980334538096429455689114222024912184432319228393204650383661781864806076247259556378350541669994344878430136202714945761488385890619925553457668158504202786580559970945936657636855346713598888067516214634859330554634505767198415857150479345944721710356274047707536156296215573412763735135600953865419000398920292535215757291539307525639675204597938919504807427238735811520",
            "hk 51014915936684265604900487195256160848193571244274648855332475661658304506316301006112887177277345010864012988127829655449256424871024500368597989462373813062189274150916552689262852603254011248502356041206544262755481779137398040376281542938513970473990787064615734720",
            "coeff0 8334052607303635164691891746865640973284154931812505677242951979571",
            "coeff1 3027051524821510797913143245168551017133836010746368184681191225885",
            "coeff2 6737229276057263250214103422261275340563819001042860587073379446167",
            "nqr 14505649267566656033184254230892439487535867365418493728353989641536"].joined(separator: "\n")

        pC = PairingCrypto(params: params,
                           g: "[2422055706421764707298656884798525662694139066757400046351764396312,2368486078611089285604099976628163198421600488791888657767109387772]",
                           h: "[[1676759768174325156003241441740791590013598303793064886418947421476, 13349959736866478891045496775334347962196502297273549798310823806704, 14727859933506183895549904828293851795425233949062987470047599933879],[8961486908759489459110795117028822251760323447003281463137115691013, 6300058896299683989134423867160550956138105846221925003480628451909, 10029734123861349102791317103426840069297755775347263190520724149198]]")
        super.setUp()
    }
    
    func testElementSerialization() {
        let k = pC.generateKey()
        let d_k1 = k.k1.data(group: .G1)
        let d_k2 = k.k2.data(group: .G2)
        
        do {
            let k1Copy = try element_s(data: d_k1, pairingCrypto: pC)
            let k2Copy = try element_s(data: d_k2, pairingCrypto: pC)
            
            XCTAssertEqual(k.k1, k1Copy)
            XCTAssertEqual(k.k2, k2Copy)
        } catch {
            XCTFail()
        }
    }

    func testKeySerialization() {
        let k_a = pC.generateKey()
        let d = k_a.data()
        let k_b = PairingKey(data: d, pairingCrypto: pC)

        XCTAssertEqual(k_a, k_b)
    
        measure {
            let d = k_a.data()
            let _ = PairingKey(data: d, pairingCrypto: self.pC)
        }
    }
    
    func testCipherTextSerialization() {
        let k = pC.generateKey()
        let hashData = "ID".data(using: .ascii)!
        
        let cipherText = pC.encrypt(hashData: hashData, key: k)
        let d = cipherText.data()
        let cipherTextCopy = CipherText(data: d, pairingCrypto: pC)
        
        XCTAssertEqual(cipherText, cipherTextCopy)
        
        measure {
            let d = cipherText.data()
            let _ = CipherText(data: d, pairingCrypto: self.pC)
        }
    }
    
    func testTokenPartSerialization() {
        let k_a = pC.generateKey()
        let hashDataA = "A_ID".data(using: .ascii)!
        let hashDataB = "B_ID".data(using: .ascii)!
        
        let tokenPartA = pC.generateTokenPart(key: k_a, hashA: hashDataA, hashB: hashDataB)
        let d = tokenPartA.data()
        let tokenPartB = TokenPart(data: d, pairingCrypto: pC)
        
        XCTAssertEqual(tokenPartA, tokenPartB)
        
        measure {
            let d = tokenPartA.data()
            let _ = TokenPart(data: d, pairingCrypto: self.pC)
        }
    }
    
    func testTokenSerialization() {
        let k_a = pC.generateKey()
        let k_b = pC.generateKey()
        
        let hashDataA = "A_ID".data(using: .ascii)!
        let hashDataB = "B_ID".data(using: .ascii)!
        
        let tokenPartA = pC.generateTokenPart(key: k_a, hashA: hashDataA, hashB: hashDataB)
        let tokenPartB = pC.generateTokenPart(key: k_b, hashA: hashDataA, hashB: hashDataB)
        
        let token = Token(part1: tokenPartA, part2: tokenPartB)
        let d = token.data()
        let tokenCopy = Token(data: d, pairingCrypto: pC)
        
        XCTAssertEqual(token, tokenCopy)
        
        measure {
            let d = token.data()
            let _ = Token(data: d, pairingCrypto: self.pC)
        }
    }

    func testEquality() {
        let k_a = pC.generateKey()
        let k_b = pC.generateKey()
        
        let hashDataA = "A_ID".data(using: .ascii)!
        let hashDataB = "B_ID".data(using: .ascii)!
        
        let tokenPartA = pC.generateTokenPart(key: k_a, hashA: hashDataA, hashB: hashDataB)
        let tokenPartB = pC.generateTokenPart(key: k_b, hashA: hashDataA, hashB: hashDataB)
        
        let token = Token(part1: tokenPartA, part2: tokenPartB)
        
        let data = "ABCDEF".data(using: .ascii)!
        let c_a = pC.encrypt(hashData: data, key: k_a)
        let c_b = pC.encrypt(hashData: data, key: k_b)

        let equal = pC.testEquality(token: token, cipherTextA: c_a, cipherTextB: c_b)
        XCTAssertTrue(equal)
    }
    
    func testPerformanceEquality() {
        let k_a = pC.generateKey()
        let k_b = pC.generateKey()
        
        let hashDataA = "PRETTY_LONG_DATA_A".data(using: .ascii)!
        let hashDataB = "PRETTY_LONG_DATA_B".data(using: .ascii)!
        
        let tokenPartA = pC.generateTokenPart(key: k_a, hashA: hashDataA, hashB: hashDataB)
        let tokenPartB = pC.generateTokenPart(key: k_b, hashA: hashDataA, hashB: hashDataB)
        
        let token = Token(part1: tokenPartA, part2: tokenPartB)
        
        let data = "ABCDEF".data(using: .ascii)!
        let c_a = pC.encrypt(hashData: data, key: k_a)
        let c_b = pC.encrypt(hashData: data, key: k_b)

        measure {
            let _ = self.pC.testEquality(token: token, cipherTextA: c_a, cipherTextB: c_b)
        }
    }

    static var allTests : [(String, (PairingCryptoTests) -> () throws -> Void)] {
        return [
            ("testKeySerialization", testKeySerialization),
            ("testCipherTextSerialization", testCipherTextSerialization),
            ("testTokenPartSerialization", testTokenPartSerialization),
            ("testTokenSerialization", testTokenSerialization),
            ("testEquality", testEquality),
        ]
    }
}
