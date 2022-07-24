// SelfSignedCert
//
// Copyright © 2022 Minsheng Liu. All rights reserved.

import XCTest
import Crypto

@testable import SelfSignedCert

final class CertGenTests: XCTestCase {
    var sampleTBSCert: Certificate.TBSCertificate {
        let serioNo: UInt64 = 0x12345687890
        let issuer = Certificate.Name(
            commonName: "Test",
            emailAddress: "test@example.com"
        )
        let validity = Certificate.Validity(from: Date(timeIntervalSinceReferenceDate: 0))
        let subjectPublicKeyInfo = Certificate.SubjectPublicKeyInfo.p256(Fixtures.publicKey)

        return Certificate.TBSCertificate(
            version: .v3,
            serialNo: serioNo,
            signature: .ecdsaWithSHA256,
            issuer: issuer,
            validity: validity,
            subject: issuer,
            subjectPublicKeyInfo: subjectPublicKeyInfo)
    }

    func testTBSCertDER() {
        let tbsCert = sampleTBSCert
        XCTAssertEqual(tbsCert.toDER(), try! Fixtures.tbsCertData.bytes)
    }

    func testGenerateCert() throws {
        let cert = try sampleTBSCert.sign(with: Fixtures.privateKey)
        let certData = Data(cert.toDER())

        let secCert = SecCertificateCreateWithData(nil, certData as CFData)!

        var cfCommonName: CFString?
        XCTAssertEqual(SecCertificateCopyCommonName(secCert, &cfCommonName), 0)
        XCTAssertEqual(cfCommonName! as String, "Test")

        var cfEmailAddresses: CFArray?
        XCTAssertEqual(SecCertificateCopyEmailAddresses(secCert, &cfEmailAddresses), 0)
        let emailAddresses = cfEmailAddresses! as! [String]
        XCTAssertEqual(emailAddresses, ["test@example.com"])

        let secPubKey = SecCertificateCopyKey(secCert)!
        let secPubKeyData = SecKeyCopyExternalRepresentation(secPubKey, nil)! as Data

        XCTAssertEqual(secPubKeyData, Fixtures.publicKey.x963Representation)
    }
}
