import AppKit
import Combine
import Darwin
import Foundation
import Vision
import UniformTypeIdentifiers

@MainActor
final class AppState: ObservableObject {
    static let shared = AppState()

    @Published var profiles: [VPNProfile] = []
    @Published var selectedProfileID: UUID?
    @Published var stats: EngineStats = .empty
    @Published var unit: DataUnit = .kb
    @Published var isBusy = false
    @Published var isConnected = false
    @Published var statusText = "대기 중"
    @Published var alertMessage: String?
    @Published var editingProfile: VPNProfile?
    @Published var helperInstalled = false

    private let fm = FileManager.default
    private let appDir: URL
    private let profilesURL: URL
    private let activeConfigURL: URL
    private let statsURL: URL
    private let pidURL: URL
    private let logURL: URL
    private let routeStateURL: URL
    private var timer: Timer?

    private init() {
        appDir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("WireGuardC", isDirectory: true)
        profilesURL = appDir.appendingPathComponent("profiles.json")
        activeConfigURL = appDir.appendingPathComponent("active.conf")
        statsURL = appDir.appendingPathComponent("state.json")
        pidURL = appDir.appendingPathComponent("tunnel.pid")
        logURL = appDir.appendingPathComponent("tunnel.log")
        routeStateURL = appDir.appendingPathComponent("routes.json")

        try? fm.createDirectory(at: appDir, withIntermediateDirectories: true)
        helperInstalled = hasPrivilegedHelper
        loadProfiles()
        cleanupStaleRoutesIfPossible()
        startPolling()
    }

    var selectedProfile: VPNProfile? {
        profiles.first { $0.id == selectedProfileID }
    }

    var engineURL: URL? {
        if let bundled = Bundle.main.url(forResource: "wireguardc", withExtension: nil) {
            return bundled
        }
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("wireguardc")
        if fm.isExecutableFile(atPath: cwd.path) {
            return cwd
        }
        let sourceRelative = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("wireguardc")
        if fm.isExecutableFile(atPath: sourceRelative.path) {
            return sourceRelative
        }
        return nil
    }

    private var privilegedHelperURL: URL {
        URL(fileURLWithPath: "/usr/local/libexec/wireguardc/wireguardc-root")
    }

    private var hasPrivilegedHelper: Bool {
        fm.isExecutableFile(atPath: privilegedHelperURL.path)
    }

    private var bundledRootHelperURL: URL? {
        Bundle.main.url(forResource: "wireguardc-root", withExtension: "sh")
    }

    func toggleConnection() async {
        if isConnected {
            await disconnect()
        } else {
            await connect()
        }
    }

    func connect() async {
        guard let profile = selectedProfile else {
            alertMessage = "프로필을 선택하세요."
            return
        }
        guard let engine = engineURL else {
            alertMessage = ProfileError.engineMissing.localizedDescription
            return
        }

        isBusy = true
        statusText = "연결 중"
        do {
            try writeActiveConfig(profile)
            if hasPrivilegedHelper {
                try await runPasswordlessHelper("start", arguments: [String(getpid())])
            } else {
                let command = [
                    shellQuote(engine.path),
                    "run",
                    "-config", shellQuote(activeConfigURL.path),
                    "-stats-file", shellQuote(statsURL.path),
                    "-pid-file", shellQuote(pidURL.path),
                    "-route-state-file", shellQuote(routeStateURL.path),
                    "-owner-pid", String(getpid()),
                    "-handshake-timeout", "45s",
                    ">", shellQuote(logURL.path),
                    "2>&1",
                    "&"
                ].joined(separator: " ")
                try await runPrivilegedShell(command)
            }
            statusText = "연결 확인 중"
        } catch {
            alertMessage = error.localizedDescription
            statusText = "연결 실패"
        }
        isBusy = false
    }

    func disconnect() async {
        isBusy = true
        statusText = "해제 중"
        do {
            if hasPrivilegedHelper {
                try await runPasswordlessHelper("stop")
            } else if let pid = readPID() {
                try await runPrivilegedShell("/bin/kill -TERM \(pid)")
            }
            isConnected = false
            statusText = "해제됨"
        } catch {
            alertMessage = error.localizedDescription
            statusText = "해제 실패"
        }
        isBusy = false
    }

    func stopForApplicationTermination() {
        if hasPrivilegedHelper {
            _ = runHelperSynchronously("stop")
        } else if let pid = readPID() {
            let command = "/bin/kill -TERM \(pid)"
            _ = runPrivilegedShellSynchronously(command)
        }
    }

    func addManualProfile() {
        editingProfile = VPNProfile(
            name: "새 프로필",
            privateKey: "",
            address: "10.0.0.2/24",
            dns: "1.1.1.1",
            peerPublicKey: "",
            endpoint: "",
            allowedIPs: "0.0.0.0/0",
            persistentKeepalive: "25",
            mtu: "1420"
        )
    }

    func editSelectedProfile() {
        if let selectedProfile {
            editingProfile = selectedProfile
        }
    }

    func saveProfile(_ profile: VPNProfile) {
        if let index = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[index] = profile
        } else {
            profiles.append(profile)
        }
        selectedProfileID = profile.id
        saveProfiles()
    }

    func deleteSelectedProfile() {
        guard let id = selectedProfileID else { return }
        profiles.removeAll { $0.id == id }
        selectedProfileID = profiles.first?.id
        saveProfiles()
    }

    func installPrivilegedHelperFromApp() async {
        guard let engine = engineURL else {
            alertMessage = ProfileError.engineMissing.localizedDescription
            return
        }
        guard let rootHelper = bundledRootHelperURL else {
            alertMessage = "앱 번들 안에서 root helper를 찾지 못했습니다."
            return
        }

        isBusy = true
        statusText = "Helper 설치 중"
        do {
            let user = NSUserName()
            let helperPath = privilegedHelperURL.path
            let baseDir = URL(fileURLWithPath: helperPath).deletingLastPathComponent().path
            let sudoers = "/etc/sudoers.d/wireguardc"
            let sudoersBody = "\(user) ALL=(root) NOPASSWD: \(helperPath) start, \(helperPath) start *, \(helperPath) stop, \(helperPath) cleanup, \(helperPath) status\n"
            let command = """
            set -e
            install -d -o root -g wheel -m 755 \(shellQuote(baseDir))
            install -o root -g wheel -m 755 \(shellQuote(engine.path)) \(shellQuote(baseDir + "/wireguardc"))
            install -o root -g wheel -m 755 \(shellQuote(rootHelper.path)) \(shellQuote(helperPath))
            tmp=$(mktemp)
            printf %s \(shellQuote(sudoersBody)) > "$tmp"
            visudo -cf "$tmp" >/dev/null
            install -o root -g wheel -m 440 "$tmp" \(shellQuote(sudoers))
            rm -f "$tmp"
            """
            try await runPrivilegedShell(command)
            helperInstalled = hasPrivilegedHelper
            statusText = helperInstalled ? "Helper 설치됨" : "Helper 설치 확인 실패"
        } catch {
            alertMessage = error.localizedDescription
            statusText = "Helper 설치 실패"
        }
        isBusy = false
    }

    func importConfigFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [
            UTType(filenameExtension: "conf") ?? .plainText,
            .plainText
        ]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let text = try String(contentsOf: url, encoding: .utf8)
            let profile = try VPNProfile.parse(text, suggestedName: url.deletingPathExtension().lastPathComponent)
            saveProfile(profile)
        } catch {
            alertMessage = error.localizedDescription
        }
    }

    func importQRCode() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let payload = try decodeQRCode(at: url)
            let text = payload.removingPercentEncoding ?? payload
            let profile = try VPNProfile.parse(text, suggestedName: url.deletingPathExtension().lastPathComponent)
            saveProfile(profile)
        } catch {
            alertMessage = error.localizedDescription
        }
    }

    func formatted(_ bytes: UInt64, suffix: String = "") -> String {
        let value = Double(bytes) / unit.divisor
        return String(format: "%.2f %@%@", value, unit.rawValue, suffix)
    }

    func openLog() {
        NSWorkspace.shared.open(logURL)
    }

    private func loadProfiles() {
        do {
            let data = try Data(contentsOf: profilesURL)
            profiles = try JSONDecoder().decode([VPNProfile].self, from: data)
        } catch {
            profiles = defaultProfiles()
        }
        selectedProfileID = profiles.first?.id
    }

    private func saveProfiles() {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try fm.createDirectory(at: appDir, withIntermediateDirectories: true)
            try encoder.encode(profiles).write(to: profilesURL, options: .atomic)
        } catch {
            alertMessage = error.localizedDescription
        }
    }

    private func defaultProfiles() -> [VPNProfile] {
        let bundled = Bundle.main.url(forResource: "default", withExtension: "conf")
        let local = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("config/wireguardc.conf")
        for url in [bundled, local].compactMap({ $0 }) {
            if let text = try? String(contentsOf: url, encoding: .utf8),
               let profile = try? VPNProfile.parse(text, suggestedName: "기본 프로필") {
                return [profile]
            }
        }
        return []
    }

    private func writeActiveConfig(_ profile: VPNProfile) throws {
        try fm.createDirectory(at: appDir, withIntermediateDirectories: true)
        try profile.configText.write(to: activeConfigURL, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: activeConfigURL.path)
    }

    private func startPolling() {
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
        timer?.tolerance = 0.2
        refreshStatus()
    }

    private func cleanupStaleRoutesIfPossible() {
        guard fm.fileExists(atPath: routeStateURL.path) else { return }
        if let pid = readPID(), isProcessRunning(pid: pid) {
            return
        }
        if hasPrivilegedHelper {
            _ = runHelperSynchronously("cleanup")
        }
    }

    private func refreshStatus() {
        if let data = try? Data(contentsOf: statsURL) {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .custom { decoder in
                let container = try decoder.singleValueContainer()
                let value = try container.decode(String.self)
                let fractional = ISO8601DateFormatter()
                fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                let plain = ISO8601DateFormatter()
                plain.formatOptions = [.withInternetDateTime]
                if let date = fractional.date(from: value) ?? plain.date(from: value) {
                    return date
                }
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid date: \(value)")
            }
            if let decoded = try? decoder.decode(EngineStats.self, from: data) {
                stats = decoded
                isConnected = decoded.connected && readPID().map(isProcessRunning(pid:)) == true
                if let error = decoded.error, !error.isEmpty {
                    statusText = error
                } else if decoded.state == "connecting" {
                    statusText = "연결 중"
                } else if isConnected {
                    statusText = decoded.interface.map { "연결됨 \($0)" } ?? "연결됨"
                } else {
                    statusText = "해제됨"
                }
                return
            }
        }

        if let pid = readPID(), isProcessRunning(pid: pid) {
            isConnected = true
            statusText = "연결 확인 중"
        } else if !isBusy {
            isConnected = false
            statusText = "대기 중"
        }
    }

    private func readPID() -> Int32? {
        guard let text = try? String(contentsOf: pidURL, encoding: .utf8) else { return nil }
        return Int32(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private func isProcessRunning(pid: Int32) -> Bool {
        Darwin.kill(pid, 0) == 0 || errno == EPERM
    }

    private func decodeQRCode(at url: URL) throws -> String {
        guard let image = NSImage(contentsOf: url) else {
            throw ProfileError.noQRCode
        }
        var rect = CGRect(origin: .zero, size: image.size)
        guard let cgImage = image.cgImage(forProposedRect: &rect, context: nil, hints: nil) else {
            throw ProfileError.noQRCode
        }

        var result: String?
        let request = VNDetectBarcodesRequest { request, _ in
            let codes = request.results as? [VNBarcodeObservation] ?? []
            result = codes.first(where: { $0.symbology == .qr })?.payloadStringValue
        }
        let handler = VNImageRequestHandler(cgImage: cgImage)
        try handler.perform([request])
        guard let result, !result.isEmpty else {
            throw ProfileError.noQRCode
        }
        return result
    }

    private func runPrivilegedShell(_ command: String) async throws {
        let script = "do shell script \(appleScriptLiteral(command)) with administrator privileges"
        try await Task.detached {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", script]
            let pipe = Pipe()
            process.standardError = pipe
            try process.run()
            process.waitUntilExit()
            if process.terminationStatus != 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let message = String(data: data, encoding: .utf8) ?? "권한 명령 실패"
                throw NSError(domain: "WireGuardC", code: Int(process.terminationStatus), userInfo: [
                    NSLocalizedDescriptionKey: message.trimmingCharacters(in: .whitespacesAndNewlines)
                ])
            }
        }.value
    }

    private func runPasswordlessHelper(_ command: String, arguments: [String] = []) async throws {
        try await Task.detached { [helperPath = privilegedHelperURL.path, arguments] in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            process.arguments = ["-n", helperPath, command] + arguments
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            try process.run()
            process.waitUntilExit()
            if process.terminationStatus != 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let message = String(data: data, encoding: .utf8) ?? "helper command failed"
                throw NSError(domain: "WireGuardC", code: Int(process.terminationStatus), userInfo: [
                    NSLocalizedDescriptionKey: message.trimmingCharacters(in: .whitespacesAndNewlines)
                ])
            }
        }.value
    }

    private func runHelperSynchronously(_ command: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        process.arguments = ["-n", privilegedHelperURL.path, command]
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

    private func runPrivilegedShellSynchronously(_ command: String) -> Bool {
        let script = "do shell script \(appleScriptLiteral(command)) with administrator privileges"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

    private func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private func appleScriptLiteral(_ value: String) -> String {
        "\"" + value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

}
