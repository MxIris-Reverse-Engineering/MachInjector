import XPC
import AppKit
import XPCBridge
import RunningApplicationKit
import ServiceManagement

final class ViewController: NSViewController {
    var runningApplication: NSRunningApplication? {
        didSet {
            runningApplicationIconImageView.image = runningApplication?.icon
            runningApplicationNameLabel.stringValue = runningApplication?.localizedName ?? ""
        }
    }

    var service: MachInjectService?

    var dylibPath: String? {
        didSet {
            selectedDylibPathLabel.stringValue = dylibPath ?? ""
        }
    }

    @ViewLoading
    @IBOutlet var runningApplicationIconImageView: NSImageView

    @ViewLoading
    @IBOutlet var runningApplicationNameLabel: NSTextField

    @ViewLoading
    @IBOutlet var selectedDylibPathLabel: NSTextField

    @ViewLoading
    @IBOutlet var injectButton: NSButton

    @ViewLoading
    @IBOutlet var pingButton: NSButton

    override func viewDidLoad() {
        super.viewDidLoad()

        refreshInjectButton()
        refreshPingButton()
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
        injectButton.isEnabled = runningApplication != nil && dylibPath != nil && service != nil
    }

    func refreshPingButton() {
        pingButton.isEnabled = service != nil
    }

    @IBAction func injectAction(_ sender: Any) {
        guard let runningApplication, let dylibPath, let service else {
            return
        }
        Task { @MainActor in
            do {
                try await service.inject(pid: runningApplication.processIdentifier, dylibPath: dylibPath, isAsync: true)
                print("Inject success")
            } catch {
                showAlert(for: error)
            }
        }
    }
    
    private func showAlert(for error: Error) {
        print(error)
        if let window = view.window {
            NSAlert(error: error).beginSheetModal(for: window)
        } else {
            NSAlert(error: error).runModal()
        }
    }

    @IBAction func connectMachServiceAction(_ sender: Any) {
        do {
            service = try MachInjectService()
            print("Connect success")
            refreshInjectButton()
            refreshPingButton()
        } catch {
            showAlert(for: error)
        }
    }

    @IBAction func installMachServiceAction(_ sender: Any) {
        do {
            let daemonService = SMAppService.daemon(plistName: "com.machinjector.injectd.plist")
            try daemonService.register()
        } catch {
            showAlert(for: error)
        }
    }

    @IBAction func pingAction(_ sender: Any) {
        guard let service else { return }
        Task {
            do {
                try await service.ping()
                print("Ping success")
            } catch {
                showAlert(for: error)
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
    
    func runningApplicationPickerViewControllerWasCancelled(_ viewController: RunningApplicationPickerViewController) {
        viewController.dismiss(nil)
    }
}

extension Array {
    var readableDescription: String {
        map { "\($0)" }.joined(separator: "\n")
    }
}
