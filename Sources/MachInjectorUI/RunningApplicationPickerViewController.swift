import AppKit
import LaunchServicesPrivate

public final class RunningApplicationPickerViewController: NSViewController {
    public struct Configuration {
        public var title: String
        public var description: String
        public var cancelButtonTitle: String
        public var confirmButtonTitle: String
        public var rowHeight: CGFloat
        public var allowsColumns: [Column]
        public var cellSpacing: CGSize
        public init(title: String? = nil, description: String? = nil, cancelButtonTitle: String? = nil, confirmButtonTitle: String? = nil, rowHeight: CGFloat? = nil, allowsColumns: [Column]? = nil, cellSpacing: CGSize? = nil) {
            self.title = title ?? "Running Applications"
            self.description = description ?? "Select an application"
            self.cancelButtonTitle = cancelButtonTitle ?? "Cancel"
            self.confirmButtonTitle = confirmButtonTitle ?? "Confirm"
            self.rowHeight = rowHeight ?? 25
            self.allowsColumns = allowsColumns ?? [.icon, .name, .bundleIdentifier, .pid, .architecture, .sandboxed]
            self.cellSpacing = cellSpacing ?? .init(width: 0, height: 10)
        }
    }

    public protocol Delegate: AnyObject {
        func runningApplicationPickerViewController(_ viewController: RunningApplicationPickerViewController, shouldSelectApplication application: NSRunningApplication) -> Bool
        func runningApplicationPickerViewController(_ viewController: RunningApplicationPickerViewController, didSelectApplication application: NSRunningApplication)
        func runningApplicationPickerViewController(_ viewController: RunningApplicationPickerViewController, didConfirmApplication application: NSRunningApplication)
        func runningApplicationPickerViewControllerWasCancel(_ viewController: RunningApplicationPickerViewController)
    }

    public enum Column: String, CaseIterable {
        case icon
        case name
        case bundleIdentifier
        case pid
        case architecture
        case sandboxed

        var title: String {
            switch self {
            case .icon:
                ""
            case .name:
                "Name"
            case .bundleIdentifier:
                "Bundle ID"
            case .pid:
                "PID"
            case .architecture:
                "Arch"
            case .sandboxed:
                "Sandboxed"
            }
        }

        var preferredWidth: CGFloat {
            switch self {
            case .icon:
                50
            case .name:
                200
            case .bundleIdentifier:
                200
            case .pid:
                50
            case .architecture:
                50
            case .sandboxed:
                70
            }
        }

        var minWidth: CGFloat? {
            switch self {
            case .icon:
                50
            case .name:
                nil
            case .bundleIdentifier:
                nil
            case .pid:
                50
            case .architecture:
                50
            case .sandboxed:
                70
            }
        }

        var maxWidth: CGFloat? {
            switch self {
            case .icon:
                50
            case .name:
                nil
            case .bundleIdentifier:
                nil
            case .pid:
                50
            case .architecture:
                50
            case .sandboxed:
                70
            }
        }
    }

    private enum Section: CaseIterable {
        case main
    }

    private typealias DataSource = NSTableViewDiffableDataSource<Section, NSRunningApplication>

    private typealias Snapshot = NSDiffableDataSourceSnapshot<Section, NSRunningApplication>

    public weak var delegate: Delegate?

    // MARK: - View

    private let scrollView = NSScrollView()

    private let tableView = NSTableView()

    private let titleLabel = NSTextField(labelWithString: "")

    private let descriptionLabel = NSTextField(labelWithString: "")

    private lazy var cancelButton = NSButton(title: "", target: self, action: #selector(cancelAction))

    private lazy var confirmButton = NSButton(title: "", target: self, action: #selector(confirmAction))

    private let topStackView = NSStackView()

    private let bottomStackView = NSStackView()

    private var workspace = NSWorkspace.shared

    private var runningApplicationObservation: NSKeyValueObservation?

    private lazy var dataSource = makeDataSource()

    private func makeDataSource() -> DataSource {
        .init(tableView: tableView) { tableView, tableColumn, _, runningApplication in
            guard let column = Column(rawValue: tableColumn.identifier.rawValue) else { return NSView() }
            switch column {
            case .icon:
                return tableView.makeView(ofClass: IconCellView.self) {
                    $0.image = runningApplication.icon
                }
            case .name:
                return tableView.makeView(ofClass: LabelCellView.self) {
                    $0.string = runningApplication.localizedName
                }
            case .bundleIdentifier:
                return tableView.makeView(ofClass: LabelCellView.self) {
                    $0.string = runningApplication.bundleIdentifier
                }
            case .pid:
                return tableView.makeView(ofClass: LabelCellView.self) {
                    $0.string = "\(runningApplication.processIdentifier)"
                }
            case .architecture:
                return tableView.makeView(ofClass: LabelCellView.self) {
                    $0.string = runningApplication.architecture.description
                }
            case .sandboxed:
                return tableView.makeView(ofClass: IconCellView.self) {
                    $0.image = runningApplication.isSandboxed ? .checkmarkImage : .xmarkImage
                    $0.tintColor = runningApplication.isSandboxed ? .systemGreen : .systemRed
                }
            }
        }
    }

    public private(set) var configuration: Configuration

    public init(configuration: Configuration = .init()) {
        self.configuration = configuration
        super.init(nibName: nil, bundle: nil)
        apply(configuration: configuration)
    }

    @available(*, unavailable)
    public required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    public override func loadView() {
        view = NSView()
    }

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.addSubview(scrollView)
        view.addSubview(topStackView)
        view.addSubview(bottomStackView)
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.hasVerticalScroller = true
        scrollView.scrollerStyle = .overlay
        topStackView.translatesAutoresizingMaskIntoConstraints = false
        bottomStackView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            topStackView.topAnchor.constraint(equalTo: view.topAnchor, constant: 20),
            topStackView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            topStackView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),

            scrollView.topAnchor.constraint(equalTo: topStackView.bottomAnchor, constant: 20),
            scrollView.bottomAnchor.constraint(equalTo: bottomStackView.topAnchor, constant: -20),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),

            bottomStackView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            bottomStackView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            bottomStackView.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -20),
        ])
        topStackView.orientation = .vertical
        topStackView.spacing = 10
        topStackView.distribution = .fill
        topStackView.alignment = .leading
        topStackView.addArrangedSubview(titleLabel)
        topStackView.addArrangedSubview(descriptionLabel)
        bottomStackView.orientation = .horizontal
        bottomStackView.spacing = 10
        bottomStackView.distribution = .gravityAreas
        bottomStackView.alignment = .centerY
        bottomStackView.addView(cancelButton, in: .trailing)
        bottomStackView.addView(confirmButton, in: .trailing)
        bottomStackView.setCustomSpacing(12, after: cancelButton)
        titleLabel.font = .systemFont(ofSize: 20, weight: .bold)
        titleLabel.textColor = .labelColor
        descriptionLabel.font = .systemFont(ofSize: 14, weight: .regular)
        descriptionLabel.textColor = .secondaryLabelColor
        confirmButton.keyEquivalent = "\r"
        confirmButton.isEnabled = false
        scrollView.documentView = tableView
        tableView.allowsEmptySelection = false
        tableView.allowsMultipleSelection = false
        tableView.style = .inset
        tableView.dataSource = dataSource
        tableView.delegate = self
        setupObservation()
        reloadData()
    }

    private func setupObservation() {
        runningApplicationObservation = workspace.observe(\.runningApplications) { [weak self] _, _ in
            guard let self else { return }
            reloadData()
        }
    }

    private func reloadData(newValue: [NSRunningApplication]? = nil) {
        let runningApplications = newValue ?? workspace.runningApplications
        var snapshot = Snapshot()
        snapshot.appendSections([.main])
        snapshot.appendItems(runningApplications.filter { $0.processIdentifier > 0 }, toSection: .main)
        dataSource.apply(snapshot, animatingDifferences: true)
    }

    private func setupColumns(_ columns: [Column]? = nil, isReload: Bool = true) {
        tableView.tableColumns.forEach { tableView.removeTableColumn($0) }
        for column in columns ?? configuration.allowsColumns {
            let tableColumn = NSTableColumn(identifier: .init(column.rawValue))
            if column == .sandboxed {
                tableColumn.headerCell.alignment = .center
            }
            tableColumn.title = column.title
            tableColumn.width = column.preferredWidth
            if let minWidth = column.minWidth {
                tableColumn.minWidth = minWidth
            }
            if let maxWidth = column.maxWidth {
                tableColumn.maxWidth = maxWidth
            }
            tableView.addTableColumn(tableColumn)
        }
        if isReload {
            reloadData()
        }
    }

    @objc private func cancelAction() {
        delegate?.runningApplicationPickerViewControllerWasCancel(self)
    }

    @objc private func confirmAction() {
        guard tableView.selectedRow != NSNotFound else { return }
        guard let delegate, let runningApplication = dataSource.itemIdentifier(forRow: tableView.selectedRow) else { return }
        delegate.runningApplicationPickerViewController(self, didConfirmApplication: runningApplication)
    }

    private func apply(configuration: Configuration) {
        titleLabel.stringValue = configuration.title
        descriptionLabel.stringValue = configuration.description
        cancelButton.title = configuration.cancelButtonTitle
        confirmButton.title = configuration.confirmButtonTitle
        tableView.rowHeight = configuration.rowHeight
        tableView.intercellSpacing = configuration.cellSpacing
        setupColumns(configuration.allowsColumns)
    }

    deinit {
        print("\(Self.self) deinit")
    }
}

extension RunningApplicationPickerViewController {
    private class CellView: NSTableCellView {
        override init(frame frameRect: NSRect) {
            super.init(frame: frameRect)
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) {
            fatalError("init(coder:) has not been implemented")
        }
    }

    private class IconCellView: CellView {
        
        var tintColor: NSColor? {
            didSet {
                iconImageView.contentTintColor = tintColor
            }
        }
        
        var image: NSImage? {
            didSet {
                iconImageView.image = image
            }
        }

        private let iconImageView = NSImageView()

        override init(frame frameRect: NSRect) {
            super.init(frame: frameRect)
            addSubview(iconImageView)
            iconImageView.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                iconImageView.centerYAnchor.constraint(equalTo: centerYAnchor),
                iconImageView.centerXAnchor.constraint(equalTo: centerXAnchor),
                iconImageView.heightAnchor.constraint(equalTo: heightAnchor),
                iconImageView.widthAnchor.constraint(equalTo: heightAnchor),
            ])
        }
    }

    private class LabelCellView: CellView {
        var string: String? {
            didSet {
                label.stringValue = string ?? ""
            }
        }

        var attributedString: NSAttributedString? {
            didSet {
                label.attributedStringValue = attributedString ?? NSAttributedString()
            }
        }

        private let label = NSTextField(labelWithString: "")

        override init(frame frameRect: NSRect) {
            super.init(frame: frameRect)
            addSubview(label)
            label.translatesAutoresizingMaskIntoConstraints = false
            label.font = .systemFont(ofSize: 12, weight: .regular)
            label.lineBreakMode = .byTruncatingTail
            NSLayoutConstraint.activate([
                label.centerYAnchor.constraint(equalTo: centerYAnchor),
                label.leadingAnchor.constraint(equalTo: leadingAnchor),
                label.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor),
                label.topAnchor.constraint(greaterThanOrEqualTo: topAnchor),
                label.bottomAnchor.constraint(lessThanOrEqualTo: bottomAnchor),
            ])
        }
    }

    private class CheckboxCellView: CellView {
        public var isChecked: Bool = false {
            didSet {
                checkbox.state = isChecked ? .on : .off
            }
        }

        public var isEnabled: Bool = false {
            didSet {
                checkbox.isEnabled = isEnabled
            }
        }

        private let checkbox = NSButton(checkboxWithTitle: "", target: nil, action: nil)
        
        override init(frame frameRect: NSRect) {
            super.init(frame: frameRect)
            addSubview(checkbox)
            checkbox.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                checkbox.centerYAnchor.constraint(equalTo: centerYAnchor),
                checkbox.centerXAnchor.constraint(equalTo: centerXAnchor),
            ])
        }
    }
}

extension RunningApplicationPickerViewController: NSTableViewDelegate {
    public func tableViewSelectionDidChange(_ notification: Notification) {
        confirmButton.isEnabled = tableView.selectedRow != NSNotFound
    }

    public func tableView(_ tableView: NSTableView, shouldSelectRow row: Int) -> Bool {
        guard let delegate, let runningApplication = dataSource.itemIdentifier(forRow: row) else { return true }
        return delegate.runningApplicationPickerViewController(self, shouldSelectApplication: runningApplication)
    }
}

extension NSTableView {
    func makeView<View: NSView>(ofClass viewClass: View.Type, modify: ((View) -> Void)? = nil) -> View {
        if let cellView = makeView(withIdentifier: .init(String(describing: viewClass)), owner: nil) as? View {
            modify?(cellView)
            return cellView
        } else {
            let cellView = View()
            cellView.identifier = .init(String(describing: viewClass))
            modify?(cellView)
            return cellView
        }
    }
}

extension NSRunningApplication {
    enum Architecture: CustomStringConvertible {
        case x86_64
        case arm64
        case i386
        case ppc
        case ppc64
        case unknown
        var description: String {
            switch self {
            case .x86_64:
                "x64"
            case .arm64:
                "arm64"
            case .i386:
                "i386"
            case .ppc:
                "PPC"
            case .ppc64:
                "PPC64"
            case .unknown:
                "Unknown"
            }
        }
    }

    var architecture: Architecture {
        switch executableArchitecture {
        case NSBundleExecutableArchitectureARM64:
            return .arm64
        case NSBundleExecutableArchitectureX86_64:
            return .x86_64
        case NSBundleExecutableArchitectureI386:
            return .i386
        case NSBundleExecutableArchitecturePPC:
            return .ppc
        case NSBundleExecutableArchitecturePPC64:
            return .ppc64
        default:
            return .unknown
        }
    }

    var applicationProxy: LSApplicationProxy? {
        guard let bundleIdentifier else { return nil }
        return LSApplicationProxy(forIdentifier: bundleIdentifier)
    }
    
    var isSandboxed: Bool {
        guard let entitlements = applicationProxy?.entitlements else { return false }
        guard let isSandboxed = entitlements["com.apple.security.app-sandbox"] as? Bool else { return false }
        return isSandboxed
    }
}

extension NSImage {
    static let checkmarkImage = NSImage(systemSymbolName: "checkmark.circle", accessibilityDescription: nil)
    static let xmarkImage = NSImage(systemSymbolName: "xmark.circle", accessibilityDescription: nil)
}
