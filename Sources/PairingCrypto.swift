import CPBC
import Foundation

func element_copy(e: element_t) -> element_ptr {
    var e = e
    let c = element_new(e.field)!
    element_set(c, &e)
    return c
}

extension element_s: Equatable {
    public static func ==(lhs: element_s, rhs: element_s) -> Bool {
        var lhs = lhs, rhs = rhs
        return element_cmp(&lhs, &rhs) == 0
    }
}

public extension element_s {
    
    public enum Group: UInt8 {
        case G1
        case G2
        case GT
        case Zr
    }
    
    public func data(group: Group) -> Data {
        var varSelf = self
        let length = Int(element_length_in_bytes(&varSelf))
        
        var data = Data(count: length + 1)
        let _ = data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
            bytes.initialize(to: group.rawValue)
            element_to_bytes(bytes.advanced(by: 1), &varSelf)
        }
        
        return data
    }
    
    public init(data: Data, pairingCrypto: PairingCrypto) {
        self.init()
        
        let group = Group(rawValue: data.first!)!
        
        switch group {
        case .G1:
            element_init_G1(&self, pairingCrypto.pairing)
        case .G2:
            element_init_G2(&self, pairingCrypto.pairing)
        case .GT:
            element_init_GT(&self, pairingCrypto.pairing)
        case .Zr:
            element_init_Zr(&self, pairingCrypto.pairing)
        }
        
        var data = data
        let _ = data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
            element_from_bytes(&self, bytes.advanced(by: 1))
        }
    }
}

extension element_s: CustomDebugStringConvertible {
    public var debugDescription: String {
        var copy = self
        let bytes = UnsafeMutablePointer<Int8>.allocate(capacity: 512)
        element_snprint(bytes, 512, &copy)
        let string = String(cString: bytes)
        bytes.deallocate(capacity: 512)
        return string
    }
}

public protocol DataPairingCoding {
    
    init(data: Data, pairingCrypto: PairingCrypto)
    func data() -> Data
    
}

public class PairingCrypto {
    let pairing: pairing_ptr
    let g: element_ptr
    let h: element_ptr
    
    public convenience init(filePath: String, dictionary: [String: AnyObject]) {
        let str = try! String(contentsOfFile: filePath)
        let g = dictionary["g"] as! String
        let h = dictionary["h"] as! String
        self.init(params: str, g: g, h: h)
    }
    
    public init(params: String, g gStr: String, h hStr: String) {
        pairing = UnsafeMutablePointer<pairing_s>.allocate(capacity: 1)
        g = UnsafeMutablePointer<element_s>.allocate(capacity: 1)
        h = UnsafeMutablePointer<element_s>.allocate(capacity: 1)
        
        let _ = params.withCString { paramsCStr in
            pairing_init_set_str(pairing, paramsCStr)
        }
        
        element_init_G1(g, pairing);
        element_init_G2(h, pairing);
        
        let _ = gStr.withCString { gCStr in
            element_set_str(g, gCStr, 0)
        }
        
        let _ = hStr.withCString { hCStr in
            element_set_str(h, hCStr, 0)
        }
    }
    
    deinit {
        pairing.deallocate(capacity: 1)
        g.deallocate(capacity: 1)
        h.deallocate(capacity: 1)
    }
    
    public func generateKey() -> Key {
        var a = element_s()
        element_init_Zr(&a, pairing)
        element_random(&a)
        
        var k1 = element_s()
        var k2 = element_s()
        element_init_G1(&k1, pairing)
        element_init_G2(&k2, pairing)
        element_pow_zn(&k1, g, &a)
        element_pow_zn(&k2, h, &a)
        
        return Key(k1: k1, k2: k2)
    }
    
    public func generateTokenPart(key: Key, hashA hashAData: Data, hashB hashBData: Data) -> TokenPart {
        
        var hashA = element_s()
        var hashAData = hashAData
        element_init_Zr(&hashA, pairing)
        hashAData.withUnsafeMutableBytes { bytes in
            element_from_hash(&hashA, bytes, Int32(hashAData.count))
        }
        
        var hashB = element_s()
        var hashBData = hashBData
        element_init_Zr(&hashB, pairing)
        hashAData.withUnsafeMutableBytes { bytes in
            element_from_hash(&hashB, bytes, Int32(hashBData.count))
        }
        
        var r = element_s()
        element_init_Zr(&r, pairing)
        element_add(&r, &hashA, &hashB)
    
        var t_r = element_s()
        var t_ri = element_s()
        
        element_init_G2(&t_r, pairing)
        element_init_G2(&t_ri, pairing)
        
        element_pow_zn(&t_r, h, &r)
        
        var k2 = key.k2
        element_pow_zn(&t_ri, &k2, &r)
        
        return TokenPart(t_r: t_r, t_ri:t_ri)
    }
    
    public func encrypt(hashData: Data, key: Key) -> CipherText {
        var hash = element_s()
        element_init_G1(&hash, pairing)
        
        var hashData = hashData
        hashData.withUnsafeMutableBytes { bytes in
            element_from_hash(&hash, bytes, Int32(hashData.count))
        }
        
        var v = element_s()
        element_init_Zr(&v, pairing);
        element_random(&v);
        
        var c1 = element_s()
        var c2 = element_s()
        element_init_G1(&c1, pairing);
        element_init_G1(&c2, pairing);
        element_pow_zn(&c1, g, &v);
        
        var k1 = key.k1
        element_pow_zn(&c2, &k1, &v);
        element_mul(&c2, &c2, &hash);
        
        return CipherText(c1: c1, c2: c2)
    }
    
    public func testEquality(token t: Token, cipherTextA c_a: CipherText, cipherTextB c_b: CipherText) -> Bool {
        
        var temp1 = element_s()
        var temp2 = element_s()
        var temp3 = element_s()
        var temp4 = element_s()
        
        element_init_GT(&temp1, pairing)
        element_init_GT(&temp2, pairing)
        element_init_GT(&temp3, pairing)
        element_init_GT(&temp4, pairing)
        
        var c_a_c1 = c_a.c1
        var c_a_c2 = c_a.c2
        var c_b_c1 = c_b.c1
        var c_b_c2 = c_b.c2
        
        var t_r = t.t_r
        var t_ri = t.t_ri
        var t_rj = t.t_rj
        
        pairing_apply(&temp1, &c_a_c2, &t_r, pairing)
        pairing_apply(&temp2, &c_a_c1, &t_ri, pairing)
        
        pairing_apply(&temp3, &c_b_c2, &t_r, pairing)
        pairing_apply(&temp4, &c_b_c1, &t_rj, pairing)
        
        var result_a = element_s()
        element_init_GT(&result_a, pairing)
        element_div(&result_a, &temp1, &temp2)
        
        var result_b = element_s()
        element_init_GT(&result_b, pairing)
        element_div(&result_b, &temp3, &temp4)
        
        return result_a == result_b
    }
}
