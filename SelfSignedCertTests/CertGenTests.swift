// SelfSignedCert
//
// Copyright © 2022 Minsheng Liu. All rights reserved.

import XCTest
import CryptoKit

@testable import SelfSignedCert

final class CertGenTests: XCTestCase {
    func testTBSCert() {
        let serioNo = UInt64(Date.timeIntervalSinceReferenceDate * 1000)
        let issuer = Certificate.Name(commonName: "Gika")
        let validity = Certificate.Validity(notBefore: Date())


//        let privateKey = try! P256.Signing.PrivateKey(pemRepresentation: """
//            -----BEGIN EC PRIVATE KEY-----
//            MHcCAQEEIFs4s4/t2T2IXS+ugL2+azsZxk+FF8YF5M10qOya+JSSoAoGCCqGSM49
//            AwEHoUQDQgAEukAEYEOAWhT+VEdOnQx1jTYtFr+X9/AUwv7JQXH2KR2YmWrXquOA
//            mT51cAdD1yVlWIwNde55owIMJLrNiKdOnA==
//            -----END EC PRIVATE KEY-----
//            """)
        let privateKey = try! P256.Signing.PrivateKey(pemRepresentation: """
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIFs4s4/t2T2IXS+ugL2+azsZxk+FF8YF5M10qOya+JSSoAoGCCqGSM49
            AwEHoUQDQgAEukAEYEOAWhT+VEdOnQx1jTYtFr+X9/AUwv7JQXH2KR2YmWrXquOA
            mT51cAdD1yVlWIwNde55owIMJLrNiKdOnA==
            -----END EC PRIVATE KEY-----
            """)
        let subjectPublicKeyInfo = Certificate.SubjectPublicKeyInfo.p256(privateKey.publicKey)

        let tbsCert = Certificate.TBSCertificate(
            version: .v3,
            serialNo: serioNo,
            signature: .ecdsaWithSHA256,
            issuer: issuer,
            validity: validity,
            subject: issuer,
            subjectPublicKeyInfo: subjectPublicKeyInfo)

        let toSign = Data(tbsCert.toDER())
//        var sha256 = SHA256()
//        sha256.update(data: toSign)
//        let digest = sha256.finalize()
        let signature = try! privateKey.signature(for: toSign)

        let cert = Certificate(
            tbsCertificate: tbsCert,
            signatureValue: .init(data: signature.derRepresentation))

        let certData = Data(cert.toDER())
        print(certData.base64EncodedString())

        let secCert = SecCertificateCreateWithData(nil, certData as CFData)!
        let secPubKey = SecCertificateCopyKey(secCert)!
        let secPubKeyData = SecKeyCopyExternalRepresentation(secPubKey, nil)! as Data

        XCTAssertEqual(secPubKeyData, privateKey.publicKey.x963Representation)
    }

    func testSignature() {
        let privateKey = try! P256.Signing.PrivateKey(pemRepresentation: """
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIFs4s4/t2T2IXS+ugL2+azsZxk+FF8YF5M10qOya+JSSoAoGCCqGSM49
            AwEHoUQDQgAEukAEYEOAWhT+VEdOnQx1jTYtFr+X9/AUwv7JQXH2KR2YmWrXquOA
            mT51cAdD1yVlWIwNde55owIMJLrNiKdOnA==
            -----END EC PRIVATE KEY-----
            """)

        let text = "Hello\n"
        var sha256 = SHA256()
        sha256.update(data: text.data(using: .utf8)!)
        let digest = sha256.finalize()
        let signature = try! privateKey.signature(for: digest)

        print(signature.derRepresentation.base64EncodedString())
    }

    func testVerify() {
        let privateKey = try! P256.Signing.PrivateKey(pemRepresentation: """
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIFs4s4/t2T2IXS+ugL2+azsZxk+FF8YF5M10qOya+JSSoAoGCCqGSM49
            AwEHoUQDQgAEukAEYEOAWhT+VEdOnQx1jTYtFr+X9/AUwv7JQXH2KR2YmWrXquOA
            mT51cAdD1yVlWIwNde55owIMJLrNiKdOnA==
            -----END EC PRIVATE KEY-----
            """)
        let publicKey = privateKey.publicKey
        let signatureRaw = Data(base64Encoded: "MEUCIQCiDyOzYRQm6EaKj+WSvcUdQOrsmM1rXHDpoYZ3JHhhXwIgeHItvbFUq1iBxtwkFvqf/hfb4acugthtzfYNV9rxM+4=".data(using: .utf8)!)!
        let text = "Hello\n"
        var sha256 = SHA256()
        sha256.update(data: text.data(using: .utf8)!)
        let digest = sha256.finalize()
        let signature = try! P256.Signing.ECDSASignature(derRepresentation: signatureRaw)
        print(publicKey.isValidSignature(signature, for: digest))
    }
}
