//
//  AES.swift
//  CryptoSwift
//
//  Created by Marcin Krzyzanowski on 21/11/14.
//  Copyright (c) 2014 Marcin Krzyzanowski. All rights reserved.
//

final public class AES {
    
    enum Error: ErrorType {
        case BlockSizeExceeded
    }
    
    public enum AESVariant:Int {
        case aes128 = 1, aes192, aes256
        
        var Nk:Int { // Nk words
            return [4,6,8][self.rawValue - 1]
        }
        
        var Nb:Int { // Nb words
            return 4
        }
        
        var Nr:Int { // Nr
            return Nk + 6
        }
    }
    
    public let blockMode:CipherBlockMode
    public static let blockSize:Int = 16 // 128 /8
    
    public var variant:AESVariant {
        switch (self.key.count * 8) {
        case 128:
            return .aes128
        case 192:
            return .aes192
        case 256:
            return .aes256
        default:
            preconditionFailure("Unknown AES variant for given key.")
        }
    }
    private let key:[UInt8]
    private let iv:[UInt8]?
    
    var keySchedule:[UInt32] = [UInt32](count: 15 * 4, repeatedValue: 0)
    var invKeySchedule:[UInt32] = [UInt32](count: 15 * 4, repeatedValue: 0)

    let RCON:[UInt32] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    var SBOX = [UInt32](count: 256, repeatedValue: 0)
    var INV_SBOX = [UInt32](count: 256, repeatedValue: 0)
    
    var SUB_MIX_0 = [UInt32](count: 256, repeatedValue: 0)
    var SUB_MIX_1 = [UInt32](count: 256, repeatedValue: 0)
    var SUB_MIX_2 = [UInt32](count: 256, repeatedValue: 0)
    var SUB_MIX_3 = [UInt32](count: 256, repeatedValue: 0)
    
    var INV_SUB_MIX_0 = [UInt32](count: 256, repeatedValue: 0)
    var INV_SUB_MIX_1 = [UInt32](count: 256, repeatedValue: 0)
    var INV_SUB_MIX_2 = [UInt32](count: 256, repeatedValue: 0)
    var INV_SUB_MIX_3 = [UInt32](count: 256, repeatedValue: 0)

    // MARK: Body
    
    public init?(key:[UInt8], iv:[UInt8], blockMode:CipherBlockMode = .CBC) {
        self.key = key
        self.iv = iv
        self.blockMode = blockMode
        
        self.computeTables()
        self.computeKeySchedule()
        
        if (blockMode.needIV && iv.count != AES.blockSize) {
            assert(false, "Block size and Initialization Vector must be the same length!")
            return nil
        }
    }
    
    convenience public init?(key:[UInt8], blockMode:CipherBlockMode = .CBC) {
        // default IV is all 0x00...
        let defaultIV = [UInt8](count: AES.blockSize, repeatedValue: 0)
        self.init(key: key, iv: defaultIV, blockMode: blockMode)
    }
        
    /**
    Encrypt message. If padding is necessary, then PKCS7 padding is added and needs to be removed after decryption.
    
    - parameter message: Plaintext data
    
    - returns: Encrypted data
    */
    
    public func encrypt(bytes:[UInt8], padding:Padding? = PKCS7()) throws -> [UInt8] {
        var finalBytes = bytes;
        
        if let padding = padding {
            finalBytes = padding.add(bytes, blockSize: AES.blockSize)
        } else if bytes.count % AES.blockSize != 0 {
            throw Error.BlockSizeExceeded
        }
        
        let blocks = finalBytes.chunks(AES.blockSize) // 0.34
        return try blockMode.encryptBlocks(blocks, iv: self.iv, cipherOperation: encryptBlock)
    }
    
    private func encryptBlock(block:[UInt8]) -> [UInt8]? {
        let nRounds = self.variant.Nr
        let M = block[block.startIndex..<block.endIndex].toUInt32Array(bigEndian: false)
        
        var s0 = M[0] ^ keySchedule[0]
        var s1 = M[1] ^ keySchedule[1]
        var s2 = M[2] ^ keySchedule[2]
        var s3 = M[3] ^ keySchedule[3]

        // Key schedule row counter
        var ksRow = 4
        
        // Rounds
        for _ in 1..<nRounds {
            // Shift rows, sub bytes, mix columns, add round key
            var t0 = SUB_MIX_0[s0 >> 24]
                t0 ^= SUB_MIX_1[(s1 >> 16) & 0xff]
                t0 ^= SUB_MIX_2[(s2 >> 8) & 0xff]
                t0 ^= SUB_MIX_3[s3 & 0xff]
                t0 ^= keySchedule[ksRow++]
            var t1 = SUB_MIX_0[s1 >> 24]
                t1 ^= SUB_MIX_1[(s2 >> 16) & 0xff]
                t1 ^= SUB_MIX_2[(s3 >> 8) & 0xff]
                t1 ^= SUB_MIX_3[s0 & 0xff]
                t1 ^= keySchedule[ksRow++]
            var t2 = SUB_MIX_0[s2 >> 24]
                t2 ^= SUB_MIX_1[(s3 >> 16) & 0xff]
                t2 ^= SUB_MIX_2[(s0 >> 8) & 0xff]
                t2 ^= SUB_MIX_3[s1 & 0xff]
                t2 ^= keySchedule[ksRow++]
            var t3 = SUB_MIX_0[s3 >> 24]
                t3 ^= SUB_MIX_1[(s0 >> 16) & 0xff]
                t3 ^= SUB_MIX_2[(s1 >> 8) & 0xff]
                t3 ^= SUB_MIX_3[s2 & 0xff]
                t3 ^= keySchedule[ksRow++]
            
            // Update state
            s0 = t0
            s1 = t1
            s2 = t2
            s3 = t3
        }
        
        // Shift rows, sub bytes, add round key
        var t0 =  SBOX[s0 >> 24] << 24
            t0 |= SBOX[(s1 >> 16) & 0xff] << 16
            t0 |= SBOX[(s2 >> 8) & 0xff] << 8
            t0 |= SBOX[s3 & 0xff]
            t0 ^= keySchedule[ksRow++]
        var t1 =  SBOX[s1 >> 24] << 24
            t1 |= SBOX[(s2 >> 16) & 0xff] << 16
            t1 |= SBOX[(s3 >> 8) & 0xff] << 8
            t1 |= SBOX[s0 & 0xff]
            t1 ^= keySchedule[ksRow++]
        var t2 =  SBOX[s2 >> 24] << 24
            t2 |= SBOX[(s3 >> 16) & 0xff] << 16
            t2 |= SBOX[(s0 >> 8) & 0xff] << 8
            t2 |= SBOX[s1 & 0xff]
            t2 ^= keySchedule[ksRow++]
        var t3 =  SBOX[s3 >> 24] << 24
            t3 |= SBOX[(s0 >> 16) & 0xff] << 16
            t3 |= SBOX[(s1 >> 8) & 0xff] << 8
            t3 |= SBOX[s2 & 0xff]
            t3 ^= keySchedule[ksRow++]
        
        // Set output
//        M[0] = t0
//        M[1] = t1
//        M[2] = t2
//        M[3] = t3
        
        var out = [UInt8]()
        out.reserveCapacity(M.count * 4)
        [t0, t1, t2, t3].forEach {
            out.append(UInt8(($0 >> 24) & 0xff))
            out.append(UInt8(($0 >> 16) & 0xff))
            out.append(UInt8(($0 >> 8) & 0xff))
            out.append(UInt8($0 & 0xff))
        }
        
        return out
    }
    
    public func decrypt(bytes:[UInt8], padding:Padding? = PKCS7()) throws -> [UInt8] {
        if bytes.count % AES.blockSize != 0 {
            throw Error.BlockSizeExceeded
        }
        
        let blocks = bytes.chunks(AES.blockSize)
        let out:[UInt8]
        switch (blockMode) {
        case .CFB, .CTR:
            // CFB, CTR uses encryptBlock to decrypt
            out = try blockMode.decryptBlocks(blocks, iv: self.iv, cipherOperation: encryptBlock)
        default:
            out = try blockMode.decryptBlocks(blocks, iv: self.iv, cipherOperation: decryptBlock)
        }
        
        if let padding = padding {
            return padding.remove(out, blockSize: nil)
        }
        
        return out
    }
    
    private func decryptBlock(block:[UInt8]) -> [UInt8]? {
        let nRounds = self.variant.Nr
        var M = block[block.startIndex..<block.endIndex].toUInt32Array(bigEndian: false)
        
        var s0 = M[0] ^ invKeySchedule[0]
        var s1 = M[3] ^ invKeySchedule[1]
        var s2 = M[2] ^ invKeySchedule[2]
        var s3 = M[1] ^ invKeySchedule[3]
        
        // Key schedule row counter
        var ksRow = 4
        
        // Rounds
        for _ in 1..<nRounds {
            // Shift rows, sub bytes, mix columns, add round key
            var t0 = INV_SUB_MIX_0[s0 >> 24]
                t0 ^= INV_SUB_MIX_1[(s1 >> 16) & 0xff]
                t0 ^= INV_SUB_MIX_2[(s2 >> 8) & 0xff]
                t0 ^= INV_SUB_MIX_3[s3 & 0xff]
                t0 ^= invKeySchedule[ksRow++]
            var t1 = INV_SUB_MIX_0[s1 >> 24]
                t1 ^= INV_SUB_MIX_1[(s2 >> 16) & 0xff]
                t1 ^= INV_SUB_MIX_2[(s3 >> 8) & 0xff]
                t1 ^= INV_SUB_MIX_3[s0 & 0xff]
                t1 ^= invKeySchedule[ksRow++]
            var t2 = INV_SUB_MIX_0[s2 >> 24]
                t2 ^= INV_SUB_MIX_1[(s3 >> 16) & 0xff]
                t2 ^= INV_SUB_MIX_2[(s0 >> 8) & 0xff]
                t2 ^= INV_SUB_MIX_3[s1 & 0xff]
                t2 ^= invKeySchedule[ksRow++]
            var t3 = INV_SUB_MIX_0[s3 >> 24]
                t3 ^= INV_SUB_MIX_1[(s0 >> 16) & 0xff]
                t3 ^= INV_SUB_MIX_2[(s1 >> 8) & 0xff]
                t3 ^= INV_SUB_MIX_3[s2 & 0xff]
                t3 ^= invKeySchedule[ksRow++]
            
            // Update state
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
        }
        
        // Shift rows, sub bytes, add round key
        var t0 =  INV_SBOX[s0 >> 24] << 24
            t0 |= INV_SBOX[(s1 >> 16) & 0xff] << 16
            t0 |= INV_SBOX[(s2 >> 8) & 0xff] << 8
            t0 |= INV_SBOX[s3 & 0xff]
            t0 ^= invKeySchedule[ksRow++]
        var t1 =  INV_SBOX[s1 >> 24] << 24
            t1 |= INV_SBOX[(s2 >> 16) & 0xff] << 16
            t1 |= INV_SBOX[(s3 >> 8) & 0xff] << 8
            t1 |= INV_SBOX[s0 & 0xff]
            t1 ^= invKeySchedule[ksRow++]
        var t2 =  INV_SBOX[s2 >> 24] << 24
            t2 |= INV_SBOX[(s3 >> 16) & 0xff] << 16
            t2 |= INV_SBOX[(s0 >> 8) & 0xff] << 8
            t2 |= INV_SBOX[s1 & 0xff]
            t2 ^= invKeySchedule[ksRow++]
        var t3 =  INV_SBOX[s3 >> 24] << 24
            t3 |= INV_SBOX[(s0 >> 16) & 0xff] << 16
            t3 |= INV_SBOX[(s1 >> 8) & 0xff] << 8
            t3 |= INV_SBOX[s2 & 0xff]
            t3 ^= invKeySchedule[ksRow++]
        
        // Set output
        M[0] = t0
        M[1] = t3
        M[2] = t2
        M[3] = t1
        
        var out = [UInt8]()
        out.reserveCapacity(M.count * 4)
        for e in M.lazy.enumerate() {
            let num = M[e.index]
            out.append(UInt8((num >> 24) & 0xff))
            out.append(UInt8((num >> 16) & 0xff))
            out.append(UInt8((num >> 8) & 0xff))
            out.append(UInt8(num & 0xff))
        }
        
        return out
    }
    
}

extension AES {
    
    func computeTables() {
        // Compute double table
        var d = [UInt32](count: 256, repeatedValue: 0)
        for i in 0..<256 {
            if (i < 128) {
                d[i] = UInt32(i << 1)
            } else {
                d[i] = UInt32(i << 1) ^ 0x11b
            }
        }
        
        // Walk GF(2^8)
        var x:UInt32 = 0;
        var xi:UInt32 = 0;
        for _ in 0..<256 {
            var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4)
            sx = (sx >> 8) ^ (sx & 0xff) ^ 0x63
            SBOX[x] = sx
            INV_SBOX[sx] = x
            
            // Compute multiplication
            let x2 = d[x]
            let x4 = d[x2]
            let x8 = d[x4]
            
            // Compute sub bytes, mix columns tables
            let t = (d[sx] * 0x101) ^ (sx * 0x1010100)
            SUB_MIX_0[x] = (t << 24) | (t >> 8)
            SUB_MIX_1[x] = (t << 16) | (t >> 16)
            SUB_MIX_2[x] = (t << 8)  | (t >> 24)
            SUB_MIX_3[x] = t
            
            // Compute inv sub bytes, inv mix columns tables
            let invt = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100)
            INV_SUB_MIX_0[sx] = (invt << 24) | (invt >> 8)
            INV_SUB_MIX_1[sx] = (invt << 16) | (invt >> 16)
            INV_SUB_MIX_2[sx] = (invt << 8)  | (invt >> 24)
            INV_SUB_MIX_3[sx] = invt
            
            // Compute next counter
            if (x == 0) {
                x = 1
                xi = 1
            } else {
                x = x2 ^ d[d[d[x8 ^ x2]]]
                xi ^= d[d[xi]]
            }
        }
    }
    
    ///  Compute key schedule
    func computeKeySchedule() {
        let nRounds = self.variant.Nr // TODO: remove later
        let ksRows = (nRounds + 1) * 4;
        let keySize = key.count / 4 // TODO: check!
        let keyWords = key.toUInt32Array(bigEndian: false)

        for ksRow in 0..<ksRows {
            if (ksRow < keySize) {
                keySchedule[ksRow] = keyWords[ksRow]
            } else {
                var t = keySchedule[ksRow - 1];
                
                if (ksRow % keySize == 0) {
                    // Rot word
                    t = (t << 8) | (t >> 24);
                    
                    // Sub word
                    t = (SBOX[t >> 24] << 24) | (SBOX[(t >> 16) & 0xff] << 16) | (SBOX[(t >> 8) & 0xff] << 8) | SBOX[t & 0xff]
                    
                    // Mix Rcon
                    t ^= RCON[(ksRow / keySize) | 0] << 24
                } else if (keySize > 6 && ksRow % keySize == 4) {
                    // Sub word
                    t = (SBOX[t >> 24] << 24) | (SBOX[(t >> 16) & 0xff] << 16) | (SBOX[(t >> 8) & 0xff] << 8) | SBOX[t & 0xff]
                }
                
                keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t
            }
        }

        // Compute inv key schedule
        for invKsRow in 0..<ksRows {
            let ksRow = ksRows - invKsRow;
            
            let t:UInt32
            if (invKsRow % 4) != 0 {
                t = keySchedule[ksRow];
            } else {
                t = keySchedule[ksRow - 4];
            }
            
            if (invKsRow < 4) || (ksRow <= 4) {
                invKeySchedule[invKsRow] = t;
            } else {
                invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >> 24]] ^ INV_SUB_MIX_1[SBOX[(t >> 16) & 0xff]] ^ INV_SUB_MIX_2[SBOX[(t >> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
            }
        }
    }
}