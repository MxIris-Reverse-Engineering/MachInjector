//
//  MachInjectHostDelegate.swift
//  MachInjectorExample
//
//  Created by JH on 11/22/24.
//

import AppKit
import XPCBridge
import SwiftyXPC

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
            print("Inject success")
        case let .failure(error):
            throw error
        }
    }

    func ping() async throws {
        let response: PingResponse = try await connection.sendMessage(name: MachInjectIdentifiers.ping, request: PingRequest())
        switch response {
        case .success:
            print("Ping success")
        case let .failure(error):
            throw error
        }
    }

//    let connection: NSXPCConnection
//    var service: MachInjectService!
//
//    deinit {
//        connection.invalidate()
//    }
//
//    override init() {
//        self.connection = NSXPCConnection(machServiceName: machService, options: .privileged)
//        super.init()
//        connection.exportedObject = self
//        connection.exportedInterface = NSXPCInterface(with: MachInjectHost.self)
//        connection.resume()
//        connection.remoteObjectInterface = NSXPCInterface(with: MachInjectService.self)
//        self.service = connection.remoteObjectProxyWithErrorHandler { error in
//            print(error)
//        } as? MachInjectService
//    }
//
//    func inject(pid: pid_t, dylibPath: String) async throws {
//        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
//            service.inject(pid: pid, dylibPath: dylibPath) { error in
//                if let error {
//                    continuation.resume(throwing: error)
//                } else {
//                    continuation.resume()
//                }
//            }
//        }
//    }
//
//    func ping() async throws {
//        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
//            service.ping {
//                continuation.resume()
//            }
//        }
//    }
}
