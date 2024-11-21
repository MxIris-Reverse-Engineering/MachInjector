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

func handle(with message: XPCReceivedMessage) -> Encodable? {
    if let request = try? message.decode(as: MachInjectRequest.self) {
        do {
            try MachInjector.inject(pid: request.pid, dylibPath: request.dylibPath)
            return MachInjectResponse.requestSuccess()
        } catch {
            return MachInjectResponse.failure(MachInjectError(message: error.localizedDescription))
        }
    } else if let _ = try? message.decode(as: PingRequest.self) {
        return PingResponse.requestSuccess()
    } else {
        return nil
    }
}

let listener = try XPCListener(service: machService) { request in
    request.accept { (message: XPCReceivedMessage) in
        if let response = handle(with: message) {
            message.reply(response)
            return response
        }
        return nil
    }
}

dispatchMain()
