//
//  main.swift
//  com.machinjector.example.injectd
//
//  Created by JH on 2024/11/20.
//

import XPCBridge
import SwiftyXPC
import Foundation
import MachInjector

let listener = try SwiftyXPC.XPCListener(type: .machService(name: machService), codeSigningRequirement: nil)

listener.setMessageHandler(name: MachInjectIdentifiers.inject) { (_, request: MachInjectRequest) -> MachInjectResponse in
    do {
        try MachInjector.inject(pid: request.pid, dylibPath: request.dylibPath)
        return .requestSuccess()
    } catch {
        return .failure(.init(message: error.localizedDescription))
    }
}

listener.setMessageHandler(name: MachInjectIdentifiers.ping) { (_, _: PingRequest) -> PingResponse in
    return .requestSuccess()
}

listener.activate()

RunLoop.current.run()
