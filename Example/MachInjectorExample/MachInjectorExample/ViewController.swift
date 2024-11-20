//
//  ViewController.swift
//  MachInjectorExample
//
//  Created by JH on 2024/11/20.
//

import AppKit
import MachInjectorUI
import ApplicationsWrapper

class ViewController: NSViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
    }

    @IBAction func presentAction(_ sender: Any) {
        present()
    }

    func present() {
        let runningApplicationPickerViewController = RunningApplicationPickerViewController()
        runningApplicationPickerViewController.preferredContentSize = .init(width: 800, height: 600)
        runningApplicationPickerViewController.delegate = self
        presentAsSheet(runningApplicationPickerViewController)
    }

    override var representedObject: Any? {
        didSet {
            // Update the view, if already loaded.
        }
    }
}

extension ViewController: RunningApplicationPickerViewController.Delegate {
    func runningApplicationPickerViewController(_ viewController: MachInjectorUI.RunningApplicationPickerViewController, shouldSelectApplication application: NSRunningApplication) -> Bool {
        true
    }

    func runningApplicationPickerViewController(_ viewController: MachInjectorUI.RunningApplicationPickerViewController, didSelectApplication application: NSRunningApplication) {}

    func runningApplicationPickerViewController(_ viewController: MachInjectorUI.RunningApplicationPickerViewController, didConfirmApplication application: NSRunningApplication) {
        print(LSApplicationProxy(forIdentifier: application.bundleIdentifier!).isContainerized)
    }

    func runningApplicationPickerViewControllerWasCancel(_ viewController: MachInjectorUI.RunningApplicationPickerViewController) {}
}
