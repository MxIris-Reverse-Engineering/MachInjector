import Foundation

private enum ResultCodingKeys: String, CodingKey {
    case success
    case failure
}

extension Result where Success == RequestSuccess {
    public static func requestSuccess() -> Self {
        return .success(RequestSuccess())
    }
}

extension Result: @retroactive Codable where Success: Codable, Failure: Codable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: ResultCodingKeys.self)

        switch self {
        case let .success(value):
            try container.encode(value, forKey: .success)
        case let .failure(error):
            try container.encode(error, forKey: .failure)
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: ResultCodingKeys.self)

        if let success = try container.decodeIfPresent(Success.self, forKey: .success) {
            self = .success(success)
        } else if let failure = try container.decodeIfPresent(Failure.self, forKey: .failure) {
            self = .failure(failure)
        } else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: container.codingPath,
                    debugDescription: "Invalid Result: neither success nor failure value found"
                )
            )
        }
    }
}
