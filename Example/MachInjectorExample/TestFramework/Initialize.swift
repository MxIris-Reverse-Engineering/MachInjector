import Foundation
import os.log

private let logger = Logger(subsystem: "com.machinjector.testframework", category: "Initialization")

@_cdecl("swift_initializeTestFramework")
func initialize() {
    logger.info("TestFramework initialized in process \(ProcessInfo.processInfo.processName, privacy: .public) (PID: \(ProcessInfo.processInfo.processIdentifier, privacy: .public))")
}
