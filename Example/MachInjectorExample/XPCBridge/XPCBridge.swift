//
//  AppProtocol.swift
//  XPCBridge
//
//  Created by JH on 2024/11/21.
//

import Foundation

public let machService = "com.machinjector.example.injectd"

public struct MachInjectRequest: Codable {
    public let pid: pid_t
    public let dylibPath: String
    public init(pid: pid_t, dylibPath: String) {
        self.pid = pid
        self.dylibPath = dylibPath
    }
}

public typealias MachInjectResponse = Result<RequestSuccess, MachInjectError>

public struct MachInjectError: Error, Codable {
    public let message: String
    public init(message: String) {
        self.message = message
    }
}

public struct PingRequest: Codable {
    public init() {}
}

public typealias PingResponse = Result<RequestSuccess, PingError>

public struct RequestSuccess: Codable {}

public struct PingError: Codable, Error {}

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

@objc
public protocol MachInjectHost {}

@objc
public protocol MachInjectService {
    @objc func inject(pid: pid_t, dylibPath: String, with reply: @escaping (Error?) -> Void)
    @objc func ping(with reply: @escaping () -> Void)
}


public enum MachInjectIdentifiers {
    public static let inject = "MachInject.inject"
    public static let ping = "MachInject.ping"
}
