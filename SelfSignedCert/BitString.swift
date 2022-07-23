// SelfSignedCert
//
// Copyright © 2022 Minsheng Liu. All rights reserved.
// Copyright © 2016 Stefan van den Oord. All rights reserved.

import Foundation

struct BitString {
    var data: Data
    var unusedBitCount: Int = 0 {
        didSet {
            precondition((0..<8).contains(unusedBitCount))
            precondition(!data.isEmpty || unusedBitCount == 0)
        }
    }
}
