//
//  ViewController.swift
//  MachInjectorExample
//
//  Created by JH on 2024/11/20.
//

import XPC
import AppKit
import XPCBridge
import MachInjectorUI

class ViewController: NSViewController {
    var pid: pid_t?

    var serviceController: MachInjectServiceController?

    var dylibPath: String?

    override func viewDidLoad() {
        super.viewDidLoad()
    }

    @IBAction func pickerRunningApplicationAction(_ sender: Any) {
        let runningApplicationPickerViewController = RunningApplicationPickerViewController()
        runningApplicationPickerViewController.preferredContentSize = .init(width: 800, height: 600)
        runningApplicationPickerViewController.delegate = self
        presentAsSheet(runningApplicationPickerViewController)
    }

    @IBAction func selectDylibAction(_ sender: Any) {
        let openPanel = NSOpenPanel()
        openPanel.canChooseFiles = true
        openPanel.canChooseDirectories = false
        openPanel.allowsMultipleSelection = false
        openPanel.allowedContentTypes = [.unixExecutable]
        let result = openPanel.runModal()
        guard result == .OK else { return }
        guard let url = openPanel.urls.first else { return }
        dylibPath = url.path()
    }

    @IBAction func injectAction(_ sender: Any) {
        guard let pid, let dylibPath, let serviceController else {
            return
        }
        Task {
            do {
                try await serviceController.inject(pid: pid, dylibPath: dylibPath)
                print("Inject success")
            } catch {
                NSAlert(error: error).runModal()
            }
        }
    }

    @IBAction func connectMachServiceAction(_ sender: Any) {
        do {
            try serviceController = MachInjectServiceController()
            print("Connect success")
        } catch {
            NSAlert(error: error).runModal()
        }
    }
    @IBAction func installMachServiceAction(_ sender: Any) {
        do {
            try HelperInstaller.install()
            print("Install success")
        } catch {
            NSAlert(error: error).runModal()
        }
    }
    @IBAction func pingAction(_ sender: Any) {
        Task {
            do {
                try await serviceController?.ping()
                print("Ping success")
            } catch {
                NSAlert(error: error).runModal()
            }
        }
    }
}

extension ViewController: RunningApplicationPickerViewController.Delegate {
    func runningApplicationPickerViewController(_ viewController: MachInjectorUI.RunningApplicationPickerViewController, shouldSelectApplication application: NSRunningApplication) -> Bool {
        true
    }

    func runningApplicationPickerViewController(_ viewController: MachInjectorUI.RunningApplicationPickerViewController, didSelectApplication application: NSRunningApplication) {}

    func runningApplicationPickerViewController(_ viewController: MachInjectorUI.RunningApplicationPickerViewController, didConfirmApplication application: NSRunningApplication) {
        pid = application.processIdentifier
    }

    func runningApplicationPickerViewControllerWasCancel(_ viewController: MachInjectorUI.RunningApplicationPickerViewController) {}
}

class MachInjectServiceController {
    let session: XPCSession

    deinit {
        session.cancel(reason: "Terminate")
    }
    
    init() throws {
        self.session = try .init(machService: machService, options: .privileged)
//        try session.activate()
    }

    func inject(pid: pid_t, dylibPath: String) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            do {
                try session.send(MachInjectRequest(pid: pid, dylibPath: dylibPath)) { (result: Result<MachInjectResponse, Error>) in
                    switch result {
                    case let .success(innerResult):
                        switch innerResult {
                        case .success:
                            continuation.resume()
                        case .failure(let error):
                            continuation.resume(throwing: error)
                        }
                    case let .failure(error):
                        continuation.resume(throwing: error)
                    }
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
    
    func ping() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            do {
                try session.send(PingRequest()) { (result: Result<XPCReceivedMessage, XPCRichError>) in
                    do {
                        switch result {
                        case .success(let message):
                            let result = try message.decode(as: PingResponse.self)
                            switch result {
                            case .success:
                                continuation.resume()
                            case let .failure(error):
                                continuation.resume(throwing: error)
                            }
                        case .failure(let failure):
                            continuation.resume(throwing: failure)
                        }

                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
