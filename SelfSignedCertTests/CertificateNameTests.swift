//  Copyright © 2016 Stefan van den Oord. All rights reserved.

import XCTest
import Quick
import Nimble
@testable import SelfSignedCert

class CertificateNameTests: QuickSpec {

    override func spec() {
        it("can be constructed") {
            expect(CertificateName()).toNot(throwError())
        }

        it("can have common name") {
            var cn = CertificateName()
            cn.commonName = "test"
            expect(cn.commonName) == "test"
        }

        it("can have email") {
            var cn = CertificateName()
            cn.emailAddress = "xx@example.com"
            expect(cn.emailAddress) == "xx@example.com"
        }

        it("can have both common name and email") {
            var cn = CertificateName()
            cn.commonName = "test"
            cn.emailAddress = "xx@example.com"
            expect(cn.commonName) == "test"
            expect(cn.emailAddress) == "xx@example.com"
        }

        it("can replace common name") {
            var cn = CertificateName()
            cn.commonName = "test"
            cn.commonName = "other"
            expect(cn.commonName) == "other"
        }

        xit("can replace email") {
            var cn = CertificateName()
            cn.emailAddress = "x@example.com"
            cn.emailAddress = "y@example.com"
            expect(cn.emailAddress) == "y@example.com"
        }

//        context("when setting common name") {
//            it("has correct internal structure") {
//                var cn = CertificateName()
//                cn.commonName = "test"
//                expect(cn.components.list.count) == 1
//                let set:Set = cn.components[0]
//                expect(set.count) == 1
//                let array:NSArray = set.first!
//                expect(array.count) == 2
//                #warning("Figure out what's going on")
////                expect(array[0]) === OID.commonName
//                expect(array[1] as? String) == "test"
//            }
//        }
//
//        context("when setting common name and email") {
//            it("has correct internal structure") {
//                var cn = CertificateName()
//                cn.commonName = "test"
//                cn.emailAddress = "xx@example.com"
//                expect(cn.components.list.count) == 2
//
//                var set:Set = cn.components[0]
//                expect(set.count) == 1
//                var array:NSArray = set.first!
//                expect(array.count) == 2
//                #warning("Figure out what's going on")
////                expect(array[0]) === OID.commonName
//                expect(array[1] as? String) == "test"
//
//                set = cn.components[1]
//                expect(set.count) == 1
//                array = set.first!
//                expect(array.count) == 2
//                #warning("Figure out what's going on")
////                expect(array[0]) === OID.email
//                expect(array[1] as? String) == "xx@example.com"
//            }
//        }
    }

}
