// SelfSignedCert
//
// Copyright © 2022 Minsheng Liu. All rights reserved.
// Copyright © 2016 Stefan van den Oord. All rights reserved.

import Foundation
import SwiftBytes

enum DERTag: UInt8 {
    case boolean = 1
    case integer = 2
    case bitString = 3
    case octetString = 4
    case null = 5
    case objectIdentifier = 6
    case utf8String = 12
    case printableString = 19
    case sequence = 16
    case `set` = 17
    // According to Wikipedia, this should be 22 instead of 20.
    // However, the original code from @svdo uses 20.
    case ia5String = 22
    case generalizedTime = 24
}

enum DERTagClass: UInt8 {
    case universal = 0
    case application = 1
    case contextSpecific = 2
    case `private` = 3
}

enum DERPrimitivity: UInt8 {
    case primitive = 0
    case construction = 1
}

struct DERHeader: Equatable {
    var tagValue: UInt8
    var tagClass: DERTagClass
    var primitivity: DERPrimitivity
    var byteCount: Int

    init(tagValue: UInt8, tagClass: DERTagClass = .universal, primitivity: DERPrimitivity = .primitive, byteCount: Int) {
        self.tagValue = tagValue
        self.tagClass = tagClass
        self.primitivity = primitivity
        self.byteCount = byteCount
    }

    init(tag: DERTag, primitivity: DERPrimitivity = .primitive, byteCount: Int) {
        self = .init(tagValue: tag.rawValue, primitivity: primitivity, byteCount: byteCount)
    }

    init(asn1Tag: UInt8, byteCount: Int) {
        self = .init(tagValue: asn1Tag, tagClass: .contextSpecific, primitivity: .construction, byteCount: byteCount)
    }
}

extension DERHeader {
    var headerByteCount: Int {
        var base = 2
        // Here we assume the additional byte can hold the tag completely.
        if tagValue >= 0b11111 {
            base += 1
        }
        if byteCount > 0x7F {
            base += Int.bitWidth / 8 - byteCount.leadingZeroBitCount / 8
        }
        return base
    }

    func encodeDER(to bytes: inout [UInt8]) {
        let identifier: UInt8 =
            (tagClass.rawValue << 6) +
            (primitivity.rawValue << 5) +
            min(tagValue, 0b11111)
        bytes.append(identifier)

        if tagValue >= 0b11111 {
            assert(tagValue.leadingZeroBitCount > 0)
            bytes.append(tagValue)
        }

        if byteCount <= 0x7F {
            bytes.append(UInt8(byteCount))
            return
        }

        let lengthByteCount = Int.bitWidth / 8 - byteCount.leadingZeroBitCount / 8
        bytes.append(0x80 + UInt8(lengthByteCount))
        let lengthBytes = UInt64(byteCount).bigEndianBytes.drop { $0 == 0 }
        bytes.append(contentsOf: lengthBytes)
    }
}

struct DERBuilder {
    private(set) var bytes: [UInt8] = []

    mutating func appendHeader(_ header: DERHeader) {
        header.encodeDER(to: &bytes)
    }

    mutating func append(_ byte: UInt8) {
        bytes.append(byte)
    }

    mutating func append<S: Sequence>(contentsOf data: S) where S.Element == UInt8 {
        bytes.append(contentsOf: data)
    }
}

protocol DEREncodable {
    var derHeader: DERHeader { get }
    func encodeDERContent(to builder: inout DERBuilder)
}

extension DEREncodable {
    func toDER() -> [UInt8] {
        var builder = DERBuilder()
        builder.appendHeader(derHeader)
        encodeDERContent(to: &builder)
        return builder.bytes
    }
}

extension Bool: DEREncodable {
    var derHeader: DERHeader {
        .init(tag: .boolean, byteCount: 1)
    }

    func encodeDERContent(to builder: inout DERBuilder) {
        builder.append(self ? 0xFF : 0)
    }
}

extension BinaryInteger {
    private var normalized: (bitPattern: UInt64, byteCount: Int) {
        guard Self.isSigned || UInt64(self).leadingZeroBitCount > 0 else {
            // In this case, we have to add a zero padding byte.
            return (UInt64(self), 9)
        }

        // Otherwise, the value can be held in Int64.
        let value = Int64(self)
        let isNegative = value < 0
        var bitPattern = UInt64(bitPattern: value)

        var detector = bitPattern
        if isNegative {
            detector = ~detector
        }
        // The spec requires the first 9 bits must not be the same.
        let bytesToDrop = max(detector.leadingZeroBitCount - 1, 0) / 8
        bitPattern <<= bytesToDrop * 8
        return (bitPattern, 8 - bytesToDrop)
    }

    var derHeader: DERHeader {
        .init(tag: .integer, byteCount: normalized.byteCount)
    }

    func encodeDERContent(to builder: inout DERBuilder) {
        let (bitPattern, byteCount) = normalized
        guard byteCount <= 8 else {
            builder.append(0)
            builder.append(contentsOf: UInt64(self).bigEndianBytes)
            return
        }
        builder.append(contentsOf: bitPattern.bigEndianBytes.prefix(byteCount))
    }
}

extension Int: DEREncodable {}
extension Int8: DEREncodable {}
extension Int16: DEREncodable {}
extension Int32: DEREncodable {}
extension Int64: DEREncodable {}
extension UInt: DEREncodable {}
extension UInt8: DEREncodable {}
extension UInt16: DEREncodable {}
extension UInt32: DEREncodable {}
extension UInt64: DEREncodable {}

extension BitString: DEREncodable {
    var derHeader: DERHeader {
        .init(tag: .bitString, byteCount: 1 + data.count)
    }

    func encodeDERContent(to builder: inout DERBuilder) {
        builder.append(UInt8(unusedBitCount))
        builder.append(contentsOf: data)
    }
}

extension Data: DEREncodable {
    var derHeader: DERHeader {
        .init(tag: .octetString, byteCount: count)
    }

    func encodeDERContent(to builder: inout DERBuilder) {
        builder.append(contentsOf: self)
    }
}

extension String: DEREncodable {
    private static let printableCharset: CharacterSet = {
        var charset = CharacterSet.alphanumerics
        charset.formUnion(.init(charactersIn: " '()+,-./:=?"))
        return charset
    }()

    private var tag: DERTag {
        for scalar in unicodeScalars {
            // It appears that X.509 spec disfavors the use of IA5String, which is only mentioned
            // for the emailAddress key. Hence we just use UTF8String and PrintableString.
            guard scalar.isASCII, Self.printableCharset.contains(scalar) else { return .utf8String }
        }
        return .printableString
    }

    var derHeader: DERHeader {
        .init(tag: tag, byteCount: utf8.count)
    }

    func encodeDERContent(to builder: inout DERBuilder) {
        builder.append(contentsOf: utf8)
    }
}

extension Date: DEREncodable, ASN1Node {
    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.locale = Locale(identifier: "nb")
        return formatter
    }()

    var derHeader: DERHeader {
        assert(Self.formatter.string(from: self).utf8.count == 15)
        return .init(tag: .generalizedTime, byteCount: 15)
    }

    func encodeDERContent(to builder: inout DERBuilder) {
        // The spec actually requires UTCTime for Year <= 2049.
        // However no parser seems to care...
        let formatted: String
        if self == .distantFuture {
            // Per RFC 5280 4.1.2.5.
            formatted = "99991231235959Z"
        } else {
            formatted = Self.formatter.string(from: self)
        }

        builder.append(contentsOf: formatted.utf8)
    }
}
