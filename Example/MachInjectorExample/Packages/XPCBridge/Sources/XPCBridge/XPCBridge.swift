import Foundation

public let machService = "com.machinjector.example.injectd"

public struct MachInjectRequest: Codable, Sendable {
    public let pid: pid_t
    public let dylibPath: String
    public init(pid: pid_t, dylibPath: String) {
        self.pid = pid
        self.dylibPath = dylibPath
    }
}

public typealias MachInjectResponse = Result<RequestSuccess, MachInjectError>

public struct MachInjectError: LocalizedError, Codable, Sendable {
    public let message: String
    public init(message: String) {
        self.message = message
    }
    
    public var errorDescription: String? { message }
}

public struct PingRequest: Codable, Sendable {
    public init() {}
}

public typealias PingResponse = Result<RequestSuccess, PingError>

public struct RequestSuccess: Codable, Sendable {}

public struct PingError: Codable, Error, Sendable {}



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
