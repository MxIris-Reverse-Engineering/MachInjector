//
//  main.swift
//  com.machinjector.example.injectd
//
//  Created by JH on 2024/11/20.
//

import XPC
import XPCBridge
import Foundation
import MachInjector

//func handle(with message: XPCReceivedMessage) -> Encodable? {
//    if let request = try? message.decode(as: MachInjectRequest.self) {
//        do {
//            try MachInjector.inject(pid: request.pid, dylibPath: request.dylibPath)
//            return MachInjectResponse.requestSuccess()
//        } catch {
//            return MachInjectResponse.failure(MachInjectError(message: error.localizedDescription))
//        }
//    } else if let _ = try? message.decode(as: PingRequest.self) {
//        return PingResponse.requestSuccess()
//    } else {
//        return nil
//    }
//}

//let listener = try XPCListener(service: machService) { request in
//    request.accept { (message: XPCReceivedMessage) in
//        if let response = handle(with: message) {
//            message.reply(response)
//            return response
//        }
//        return nil
//    }
//}

//class XPCDelegate: NSObject, NSXPCListenerDelegate, MachInjectService {
//    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
//        newConnection.exportedInterface = NSXPCInterface(with: MachInjectService.self)
//        newConnection.exportedObject = self
//        newConnection.resume()
//        return true
//    }
//    
//    func inject(pid: pid_t, dylibPath: String, with reply: @escaping ((any Error)?) -> Void) {
//        do {
//            try MachInjector.inject(pid: pid, dylibPath: dylibPath)
//            reply(nil)
//        } catch {
//            reply(error)
//        }
//    }
//    
//    func ping(with reply: @escaping () -> Void) {
//        reply()
//    }
//}
//
//let delegate = XPCDelegate()
//let listener = NSXPCListener(machServiceName: machService)
//listener.delegate = delegate
//listener.resume()
//RunLoop.current.run()

import SwiftyXPC

let listener = try SwiftyXPC.XPCListener(type: .machService(name: machService), codeSigningRequirement: nil)

listener.setMessageHandler(name: MachInjectIdentifiers.inject) { (_, request: MachInjectRequest) -> MachInjectResponse in
    do {
        try MachInjector.inject(pid: request.pid, dylibPath: request.dylibPath)
        return .requestSuccess()
    } catch {
        return .failure(.init(message: error.localizedDescription))
    }
}

listener.setMessageHandler(name: MachInjectIdentifiers.ping) { (_, request: PingRequest) -> PingResponse in
    return .requestSuccess()
}

listener.activate()

RunLoop.current.run()
