// SelfSignedCert
//
// Copyright © 2022 Minsheng Liu. All rights reserved.

import XCTest
import Foundation
import Crypto

final class CryptoTests: XCTestCase {
    lazy var privateKey: P256.Signing.PrivateKey! = {
        do {
            let path = Bundle.module.path(forResource: "private", ofType: "pem")!
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let pem = String(data: data, encoding: .utf8)!
            return try .init(pemRepresentation: pem)
        } catch {
            return nil
        }
    }()

    lazy var publicKey: P256.Signing.PublicKey! = {
        do {
            let path = Bundle.module.path(forResource: "public", ofType: "pem")!
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let pem = String(data: data, encoding: .utf8)!
            return try .init(pemRepresentation: pem)
        } catch {
            return nil
        }
    }()

    func testLoadPrivateKey() throws {
        XCTAssertNotNil(privateKey)
    }

    func testLoadPublicKey() throws {
        XCTAssertNotNil(publicKey)
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey.rawRepresentation)
    }

    #if os(macOS) || os(Linux)
    @discardableResult
    func run(command: String) throws -> Data {
        let task = Process()
        task.launchPath = "/bin/sh"
        task.arguments = ["-c", command]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        XCTAssertEqual(task.terminationStatus, 0)
        return data
    }

    private var docPath: String {
        Bundle.module.path(forResource: "doc", ofType: "txt")!
    }

    private var docData: Data {
        get throws {
            try Data(contentsOf: URL(fileURLWithPath: docPath))
        }
    }

    func testCanValidateSignature() throws {
        let path = Bundle.module.path(forResource: "private", ofType: "pem")!
        let rawSignature = try run(command: "openssl dgst -sha256 -sign '\(path)' '\(docPath)'")
        let signature = try P256.Signing.ECDSASignature(derRepresentation: rawSignature)

        var sha256 = SHA256()
        try sha256.update(data: docData)
        let digest = sha256.finalize()

        XCTAssert(publicKey.isValidSignature(signature, for: digest))
    }

    func testCanSign() throws {
        var sha256 = SHA256()
        try sha256.update(data: docData)
        let digest = sha256.finalize()

        let signature = try privateKey.signature(for: digest)
        let signautrePath = "/tmp/\(UUID()).sig"
        try signature.derRepresentation.write(to: URL(fileURLWithPath: signautrePath))

        let keyPath = Bundle.module.path(forResource: "public", ofType: "pem")!
        try run(command: "openssl dgst -sha256 -verify '\(keyPath)' -signature '\(signautrePath)' '\(docPath)'")
    }
    #endif
}
