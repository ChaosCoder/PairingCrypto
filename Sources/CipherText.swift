//
//  CipherText.swift
//  PairingCrypto
//
//  Created by Andreas Ganske on 05.03.17.
//
//

import Foundation
import CPBC

public struct CipherText {
    let c1: element_t
    let c2: element_t
    
    public init(c1: element_t, c2: element_t) {
        self.c1 = c1
        self.c2 = c2
    }
}

extension CipherText: Equatable {
    public static func ==(lhs: CipherText, rhs: CipherText) -> Bool {
        return lhs.c1 == rhs.c1 && lhs.c2 == rhs.c2
    }
}

extension CipherText: CustomDebugStringConvertible {
    public var debugDescription: String {
        return "[\(c1), \(c2)]"
    }
}

extension CipherText: DataPairingCoding {
    
    public init(data: Data, pairing: pairing_ptr) {
        var c1 = element_s()
        var c2 = element_s()
        element_init_G1(&c1, pairing)
        element_init_G1(&c2, pairing)
        
        var data = data
        data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
            let c1Length = Int(element_from_bytes(&c1, bytes))
            element_from_bytes(&c2, bytes.advanced(by: c1Length))
        }
        
        self.init(c1: c1, c2: c2)
    }
    
    public func data() -> Data {
        
        var c1 = self.c1, c2 = self.c2
        let c1Length = Int(element_length_in_bytes(&c1))
        let c2Length = Int(element_length_in_bytes(&c2))
        
        var data = Data(count: c1Length + c2Length)
        data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
            element_to_bytes(bytes, &c1)
            element_to_bytes(bytes.advanced(by: c1Length), &c2)
        }
        return data
    }
    
}
