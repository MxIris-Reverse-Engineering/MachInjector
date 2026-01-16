import Foundation

public let machService = "com.machinjector.example.injectd"

public struct MachInjectRequest: Codable, Sendable {
    public let pid: pid_t
    public let dylibPath: String
    public let isAsync: Bool
    public init(pid: pid_t, dylibPath: String, isAsync: Bool) {
        self.pid = pid
        self.dylibPath = dylibPath
        self.isAsync = isAsync
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


public enum MachInjectIdentifiers {
    public static let inject = "MachInject.inject"
    public static let ping = "MachInject.ping"
}
