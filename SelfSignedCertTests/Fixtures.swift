// SelfSignedCert
//
// Copyright © 2022 Minsheng Liu. All rights reserved.

import Foundation
import Crypto

enum Fixtures {
    static let privateKeyPath: String = Bundle.module.path(forResource: "private", ofType: "pem")!
    static let publicKeyPath: String = Bundle.module.path(forResource: "public", ofType: "pem")!

    static let privateKey: P256.Signing.PrivateKey! = {
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: privateKeyPath))
            let pem = String(data: data, encoding: .utf8)!
            return try .init(pemRepresentation: pem)
        } catch {
            return nil
        }
    }()

    static let publicKey: P256.Signing.PublicKey! = {
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: publicKeyPath))
            let pem = String(data: data, encoding: .utf8)!
            return try .init(pemRepresentation: pem)
        } catch {
            return nil
        }
    }()

    static let docPath: String = Bundle.module.path(forResource: "doc", ofType: "txt")!
    static var docData: Data {
        get throws {
            try Data(contentsOf: URL(fileURLWithPath: docPath))
        }
    }

    static var tbsCertData: Data {
        get throws {
            let path = Bundle.module.path(forResource: "tbs-cert", ofType: "bin")!
            return try Data(contentsOf: URL(fileURLWithPath: path))
        }
    }
}
