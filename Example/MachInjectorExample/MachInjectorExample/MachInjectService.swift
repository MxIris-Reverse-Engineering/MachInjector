import AppKit
import XPCBridge
@preconcurrency import SwiftyXPC

class MachInjectService {
    private let connection: XPCConnection

    init() throws {
        self.connection = try .init(type: .remoteMachService(serviceName: machService, isPrivilegedHelperTool: true))
        connection.activate()
    }

    func inject(pid: pid_t, dylibPath: String, isAsync: Bool) async throws {
        let request = MachInjectRequest(pid: pid, dylibPath: dylibPath, isAsync: isAsync)
        let response: MachInjectResponse = try await connection.sendMessage(name: MachInjectIdentifiers.inject, request: request)
        switch response {
        case .success:
            break
        case .failure(let error):
            throw error
        }
    }

    func ping() async throws {
        let response: PingResponse = try await connection.sendMessage(name: MachInjectIdentifiers.ping, request: PingRequest())
        switch response {
        case .success:
            break
        case .failure(let error):
            throw error
        }
    }
}
