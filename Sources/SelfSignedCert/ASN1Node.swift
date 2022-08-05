// SelfSignedCert
//
// Copyright © 2022 Minsheng Liu. All rights reserved.

import Foundation

protocol ASN1Node {
    func toDER() -> [UInt8]
}

protocol ASN1Convertible: ASN1Node {
    associatedtype ASN1Tree: ASN1Node
    var asn1Tree: ASN1Tree { get }
}

extension ASN1Convertible {
    func toDER() -> [UInt8] {
        asn1Tree.toDER()
    }
}

enum ASN1 {}

extension Int: ASN1Node {}
extension Int8: ASN1Node {}
extension Int16: ASN1Node {}
extension Int32: ASN1Node {}
extension Int64: ASN1Node {}
extension UInt: ASN1Node {}
extension UInt8: ASN1Node {}
extension UInt16: ASN1Node {}
extension UInt32: ASN1Node {}
extension UInt64: ASN1Node {}

extension String: ASN1Node {}

extension ASN1 {
    struct Null: Equatable {}
}


extension ASN1.Null: DEREncodable {
    var derHeader: DERHeader {
        .init(tag: .null, byteCount: 0)
    }

    func encodeDERContent(to builder: inout DERBuilder) {
    }
}


extension ASN1 {
    struct IA5String: Hashable {
        var content: String

        init(_ content: String) {
            assert(content.utf8.allSatisfy { $0 <= 0x7F })
            self.content = content
        }
    }
}

extension ASN1.IA5String: DEREncodable, ASN1Node {
    var derHeader: DERHeader {
        .init(tag: .ia5String, byteCount: content.utf8.count)
    }

    func encodeDERContent(to builder: inout DERBuilder) {
        builder.append(contentsOf: content.utf8)
    }
}

@resultBuilder
struct ASN1Builder {
    static func buildExpression<T: ASN1Node>(_ value: T) -> [ASN1Node] {
        [value]
    }

    static func buildBlock(_ components: [ASN1Node]...) -> [ASN1Node] {
        components.reduce(into: []) { $0 += $1 }
    }

    static func buildEither(first component: [ASN1Node]) -> [ASN1Node] {
        component
    }

    static func buildEither(second component: [ASN1Node]) -> [ASN1Node] {
        component
    }

    static func buildOptional(_ component: [ASN1Node]?) -> [ASN1Node] {
        component ?? []
    }

    static func buildPartialBlock(first: [ASN1Node]) -> [ASN1Node] {
        first
    }

    static func buildPartialBlock(accumulated: [ASN1Node], next: [ASN1Node]) -> [ASN1Node] {
        accumulated + next
    }
}

struct ASN1Seq: ASN1Node {
    var children: [ASN1Node]

    init(children: [ASN1Node]) {
        self.children = children
    }

    init(@ASN1Builder content: () -> [ASN1Node]) {
        self.children = content()
    }

    func toDER() -> [UInt8] {
        let children = self.children.map { $0.toDER() }
        let byteCount = children.reduce(0) { $0 + $1.count }
        let header = DERHeader(tag: .sequence, primitivity: .construction, byteCount: byteCount)
        var bytes: [UInt8] = []
        header.encodeDER(to: &bytes)
        for child in children {
            bytes += child
        }
        return bytes
    }
}

struct ASN1Set: ASN1Node {
    var children: [ASN1Node]

    init(children: [ASN1Node]) {
        self.children = children
    }

    init(@ASN1Builder content: () -> [ASN1Node]) {
        self.children = content()
    }

    func toDER() -> [UInt8] {
        let children = self.children.map { $0.toDER() }
        let byteCount = children.reduce(0) { $0 + $1.count }
        let header = DERHeader(tag: .set, primitivity: .construction, byteCount: byteCount)
        var bytes: [UInt8] = []
        header.encodeDER(to: &bytes)
        for child in children {
            bytes += child
        }
        return bytes
    }
}

struct ASN1Obj: ASN1Node {
    var tag: UInt8
    var children: [ASN1Node]

    init(tag: UInt8, children: [ASN1Node]) {
        self.tag = tag
        self.children = children
    }

    init(tag: UInt8, @ASN1Builder content: () -> [ASN1Node]) {
        self.tag = tag
        self.children = content()
    }

    func toDER() -> [UInt8] {
        let children = self.children.map { $0.toDER() }
        let byteCount = children.reduce(0) { $0 + $1.count }
        let header = DERHeader(asn1Tag: tag, byteCount: byteCount)
        var bytes: [UInt8] = []
        header.encodeDER(to: &bytes)
        for child in children {
            bytes += child
        }
        return bytes
    }
}
