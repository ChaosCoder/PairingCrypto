//
//  Key.swift
//  PairingCrypto
//
//  Created by Andreas Ganske on 05.03.17.
//
//

import Foundation
import CPBC

public struct Key {
    let k1: element_s
    let k2: element_s
    
    public init(k1: element_s, k2: element_s) {
        self.k1 = k1
        self.k2 = k2
    }
}

extension Key: Equatable {
    public static func ==(lhs: Key, rhs: Key) -> Bool {
        return lhs.k1 == rhs.k1 && lhs.k2 == rhs.k2
    }
}

extension Key: CustomDebugStringConvertible {
    public var debugDescription: String {
        return "[\(k1), \(k2)]"
    }
}

extension Key: DataPairingCoding {
    
    public init(data: Data, pairingCrypto: PairingCrypto) {
        var k1 = element_s()
        var k2 = element_s()
        element_init_G1(&k1, pairingCrypto.pairing)
        element_init_G2(&k2, pairingCrypto.pairing)
        
        var data = data
        data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
            let k1Length = Int(element_from_bytes(&k1, bytes))
            element_from_bytes(&k2, bytes.advanced(by: k1Length))
        }
        
        self.init(k1: k1, k2: k2)
    }
    
    public func data() -> Data {
        
        var k1 = self.k1, k2 = self.k2
        let k1Length = Int(element_length_in_bytes(&k1))
        let k2Length = Int(element_length_in_bytes(&k2))
        
        var data = Data(count: k1Length + k2Length)
        data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
            element_to_bytes(bytes, &k1)
            element_to_bytes(bytes.advanced(by: k1Length), &k2)
        }
        return data
    }
    
}
