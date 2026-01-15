import AppKit
import XPCBridge
@preconcurrency import SwiftyXPC

class MachInjectHostDelegate {
    let connection: XPCConnection

    init() throws {
        self.connection = try .init(type: .remoteMachService(serviceName: machService, isPrivilegedHelperTool: true))
        connection.activate()
    }

    func inject(pid: pid_t, dylibPath: String) async throws {
        let request = MachInjectRequest(pid: pid, dylibPath: dylibPath)
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

import SMJobKit

class MachInjectClient: Client {
    override class var serviceIdentifier: String { machService }
}
