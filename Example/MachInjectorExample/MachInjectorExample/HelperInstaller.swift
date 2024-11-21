#if os(macOS)
import ServiceManagement
import XPCBridge

public enum HelperAuthorizationError: Error {
    case message(String)
}

public enum HelperInstaller {
    private static func executeAuthorizationFunction(_ authorizationFunction: () -> (OSStatus)) throws {
        let osStatus = authorizationFunction()
        guard osStatus == errAuthorizationSuccess else {
            throw HelperAuthorizationError.message(String(describing: SecCopyErrorMessageString(osStatus, nil)))
        }
    }

    private static func authorizationRef(
        _ rights: UnsafePointer<AuthorizationRights>?,
        _ environment: UnsafePointer<AuthorizationEnvironment>?,
        _ flags: AuthorizationFlags
    ) throws -> AuthorizationRef? {
        var authRef: AuthorizationRef?
        try executeAuthorizationFunction { AuthorizationCreate(rights, environment, flags, &authRef) }
        return authRef
    }

    public static func install() throws {
//        if #available(macOS 13.0, *) {
//            try SMAppService.daemon(plistName: machService + ".plist").register()
//        } else {
            var cfError: Unmanaged<CFError>?

            var authItem: AuthorizationItem = kSMRightBlessPrivilegedHelper.withCString {
                AuthorizationItem(name: $0, valueLength: 0, value: UnsafeMutableRawPointer(bitPattern: 0), flags: 0)
            }

            var authRights = AuthorizationRights(count: 1, items: withUnsafeMutablePointer(to: &authItem) { $0 })

            let authRef = try authorizationRef(&authRights, nil, [.interactionAllowed, .extendRights, .preAuthorize])
            SMJobBless(kSMDomainSystemLaunchd, machService as CFString, authRef, &cfError)
            if let error = cfError?.takeRetainedValue() {
                throw error
            }
//        }
    }
}
#endif
