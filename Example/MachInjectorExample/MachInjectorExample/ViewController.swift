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

    var hostDelegate: MachInjectHostDelegate?

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
        dylibPath = url.path
    }

    @IBAction func injectAction(_ sender: Any) {
        guard let pid, let dylibPath, let hostDelegate else {
            return
        }
        Task {
            do {
                try await hostDelegate.inject(pid: pid, dylibPath: dylibPath)
                print("Inject success")
            } catch {
                NSAlert(error: error).runModal()
            }
        }
    }

    @IBAction func connectMachServiceAction(_ sender: Any) {
        do {
            hostDelegate = try MachInjectHostDelegate()
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
                try await hostDelegate?.ping()
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
