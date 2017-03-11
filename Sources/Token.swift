//
//  Token.swift
//  PairingCrypto
//
//  Created by Andreas Ganske on 05.03.17.
//
//

import Foundation
import CPBC

public struct TokenPart {
    let t_r: element_s
    let t_ri: element_s
    
    init(t_r: element_s, t_ri: element_s) {
        self.t_r = t_r
        self.t_ri = t_ri
    }
}

extension TokenPart: Equatable {
    public static func ==(lhs: TokenPart, rhs: TokenPart) -> Bool {
        return lhs.t_r == rhs.t_r && lhs.t_ri == rhs.t_ri
    }
}

extension TokenPart: CustomDebugStringConvertible {
    public var debugDescription: String {
        return "[\(t_r), \(t_ri)]"
    }
}

extension TokenPart: DataPairingCoding {
    
    public init(data: Data, pairingCrypto: PairingCrypto) {
        var t_r = element_s()
        var t_ri = element_s()
        element_init_G2(&t_r, pairingCrypto.pairing)
        element_init_G2(&t_ri, pairingCrypto.pairing)
        
        var data = data
        data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
            let k1Length = Int(element_from_bytes(&t_r, bytes))
            element_from_bytes(&t_ri, bytes.advanced(by: k1Length))
        }
        
        self.init(t_r: t_r, t_ri: t_ri)
    }
    
    public func data() -> Data {
        
        var t_r = self.t_r, t_ri = self.t_ri
        let t_rLength = Int(element_length_in_bytes(&t_r))
        let t_riLength = Int(element_length_in_bytes(&t_ri))
        
        var data = Data(count: t_rLength + t_riLength)
        data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
            element_to_bytes(bytes, &t_r)
            element_to_bytes(bytes.advanced(by: t_rLength), &t_ri)
        }
        return data
    }
}

public struct Token {
    let t_r: element_s
    let t_ri: element_s
    let t_rj: element_s
    
    public init(t_r: element_s, t_ri: element_t, t_rj: element_t) {
        self.t_r = t_r
        self.t_ri = t_ri
        self.t_rj = t_rj
    }
    
    public init(t_r_data: Data, t_ri_data: Data, t_rj_data: Data, pairingCrypto: PairingCrypto) throws {
        let t_r = try element_s(data: t_r_data, pairingCrypto: pairingCrypto)
        let t_ri = try element_s(data: t_ri_data, pairingCrypto: pairingCrypto)
        let t_rj = try element_s(data: t_rj_data, pairingCrypto: pairingCrypto)
        self.init(t_r: t_r, t_ri: t_ri, t_rj: t_rj)
    }
    
    public init(part1: TokenPart, part2: TokenPart) {
        assert(part1.t_r == part2.t_r, "Nonce in token parts must be the same")
        self.init(t_r: part1.t_r, t_ri: part1.t_ri, t_rj: part2.t_ri)
    }
}

extension Token: Equatable {
    public static func ==(lhs: Token, rhs: Token) -> Bool {
        return lhs.t_r == rhs.t_r && lhs.t_ri == rhs.t_ri && lhs.t_rj == rhs.t_rj
    }
}

extension Token: CustomDebugStringConvertible {
    public var debugDescription: String {
        return "[\(t_r), \(t_ri), \(t_rj)]"
    }
}

extension Token: DataPairingCoding {
    
    public init(data: Data, pairingCrypto: PairingCrypto) {
        var t_r = element_s()
        var t_ri = element_s()
        var t_rj = element_s()
        element_init_G2(&t_r, pairingCrypto.pairing)
        element_init_G2(&t_ri, pairingCrypto.pairing)
        element_init_G2(&t_rj, pairingCrypto.pairing)
        
        var data = data
        data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
            let t_rLength = Int(element_from_bytes(&t_r, bytes))
            let t_riLength = Int(element_from_bytes(&t_ri, bytes.advanced(by: t_rLength)))
            element_from_bytes(&t_rj, bytes.advanced(by: t_rLength + t_riLength))
        }
        
        self.init(t_r: t_r, t_ri: t_ri, t_rj: t_rj)
    }
    
    public func data() -> Data {
        
        var t_r = self.t_r, t_ri = self.t_ri, t_rj = self.t_rj
        let t_rLength = Int(element_length_in_bytes(&t_r))
        let t_riLength = Int(element_length_in_bytes(&t_ri))
        let t_rjLength = Int(element_length_in_bytes(&t_rj))
        
        var data = Data(count: t_rLength + t_riLength + t_rjLength)
        data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
            element_to_bytes(bytes, &t_r)
            element_to_bytes(bytes.advanced(by: t_rLength), &t_ri)
            element_to_bytes(bytes.advanced(by: t_rLength + t_riLength), &t_rj)
        }
        return data
    }
}
