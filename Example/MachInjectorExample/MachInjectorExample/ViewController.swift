//
//  ViewController.swift
//  MachInjectorExample
//
//  Created by JH on 2024/11/20.
//

import XPC
import AppKit
import XPCBridge
import RunningApplicationKit

class ViewController: NSViewController {
    var runningApplication: NSRunningApplication? {
        didSet {
            runningApplicationIconImageView.image = runningApplication?.icon
            runningApplicationNameLabel.stringValue = runningApplication?.localizedName ?? ""
        }
    }

    var hostDelegate: MachInjectHostDelegate?

    var dylibPath: String? {
        didSet {
            selectedDylibPathLabel.stringValue = dylibPath ?? ""
        }
    }

    @IBOutlet var runningApplicationIconImageView: NSImageView!

    @IBOutlet var runningApplicationNameLabel: NSTextField!

    @IBOutlet var selectedDylibPathLabel: NSTextField!

    @IBOutlet var injectButton: NSButton!

    @IBOutlet var pingButton: NSButton!

    override func viewDidLoad() {
        super.viewDidLoad()
        refreshInjectButton()
        refreshPingButton()
//        print(Bundle.allBundles.readableDescription)
        getLoadedFrameworks()
    }
    func getLoadedFrameworks() {
        let count = _dyld_image_count()
        for i in 0..<count {
            if let imagePath = String(cString: _dyld_get_image_name(i), encoding: .utf8) {
//                print(imagePath)
                // 过滤系统Framework
                if !imagePath.hasPrefix("/System/Library/"),
                   !imagePath.hasPrefix("/Library/"),
                   !imagePath.hasPrefix("/usr/lib/") {
                    print("Framework: \(imagePath)")
                }
            }
        }
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
        refreshInjectButton()
    }

    func refreshInjectButton() {
        injectButton.isEnabled = runningApplication != nil && dylibPath != nil && hostDelegate != nil
    }
    
    func refreshPingButton() {
        pingButton.isEnabled = hostDelegate != nil
    }
    
    @IBAction func injectAction(_ sender: Any) {
        guard let runningApplication, let dylibPath, let hostDelegate else {
            return
        }
        Task {
            do {
                try await hostDelegate.inject(pid: runningApplication.processIdentifier, dylibPath: dylibPath)
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
            refreshInjectButton()
            refreshPingButton()
        } catch {
            NSAlert(error: error).runModal()
        }
    }

    @IBAction func installMachServiceAction(_ sender: Any) {
        do {
            try MachInjectClient.installWithPrompt(prompt: nil)
        } catch {
            NSAlert(error: error).runModal()
        }
    }

    @IBAction func pingAction(_ sender: Any) {
        guard let hostDelegate else { return }
        Task {
            do {
                try await hostDelegate.ping()
                print("Ping success")
            } catch {
                NSAlert(error: error).runModal()
            }
        }
    }
}

extension ViewController: RunningApplicationPickerViewController.Delegate {
    func runningApplicationPickerViewController(_ viewController: RunningApplicationPickerViewController, shouldSelectApplication application: NSRunningApplication) -> Bool {
        true
    }

    func runningApplicationPickerViewController(_ viewController: RunningApplicationPickerViewController, didSelectApplication application: NSRunningApplication) {}

    func runningApplicationPickerViewController(_ viewController: RunningApplicationPickerViewController, didConfirmApplication application: NSRunningApplication) {
        runningApplication = application
        refreshInjectButton()
        viewController.dismiss(nil)
    }

    func runningApplicationPickerViewControllerWasCancel(_ viewController: RunningApplicationPickerViewController) {
        viewController.dismiss(nil)
    }
}


extension Array {
    var readableDescription: String {
        map { "\($0)" }.joined(separator: "\n")
    }
}
