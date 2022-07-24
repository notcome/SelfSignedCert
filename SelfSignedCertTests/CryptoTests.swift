// SelfSignedCert
//
// Copyright © 2022 Minsheng Liu. All rights reserved.

import XCTest
import Foundation
import Crypto

final class CryptoTests: XCTestCase {
    func testLoadPrivateKey() throws {
        XCTAssertNotNil(Fixtures.privateKey)
    }

    func testLoadPublicKey() throws {
        XCTAssertNotNil(Fixtures.publicKey)
        XCTAssertEqual(
            Fixtures.privateKey.publicKey.rawRepresentation,
            Fixtures.publicKey.rawRepresentation)
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

    func testCanValidateSignature() throws {
        let rawSignature = try run(command: "openssl dgst -sha256 -sign '\(Fixtures.privateKeyPath)' '\(Fixtures.docPath)'")
        let signature = try P256.Signing.ECDSASignature(derRepresentation: rawSignature)

        var sha256 = SHA256()
        try sha256.update(data: Fixtures.docData)
        let digest = sha256.finalize()

        XCTAssert(Fixtures.publicKey.isValidSignature(signature, for: digest))
    }

    func testCanSign() throws {
        var sha256 = SHA256()
        try sha256.update(data: Fixtures.docData)
        let digest = sha256.finalize()

        let signature = try Fixtures.privateKey.signature(for: digest)
        let signautrePath = "/tmp/\(UUID()).sig"
        try signature.derRepresentation.write(to: URL(fileURLWithPath: signautrePath))

        let keyPath = Bundle.module.path(forResource: "public", ofType: "pem")!
        try run(command: "openssl dgst -sha256 -verify '\(keyPath)' -signature '\(signautrePath)' '\(Fixtures.docPath)'")
    }
    #endif
}
