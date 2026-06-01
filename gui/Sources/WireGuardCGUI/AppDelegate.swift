import AppKit
import Combine

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var cancellables = Set<AnyCancellable>()

    func applicationDidFinishLaunching(_ notification: Notification) {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem = item
        item.button?.image = NSImage(systemSymbolName: "shield.slash", accessibilityDescription: "VPN")
        item.button?.image?.isTemplate = true
        rebuildMenu()

        AppState.shared.$isConnected
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in self?.rebuildMenu() }
            .store(in: &cancellables)
        AppState.shared.$statusText
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in self?.rebuildMenu() }
            .store(in: &cancellables)
    }

    func applicationWillTerminate(_ notification: Notification) {
        AppState.shared.stopForApplicationTermination()
    }

    private func rebuildMenu() {
        let state = AppState.shared
        statusItem?.button?.image = NSImage(
            systemSymbolName: state.isConnected ? "shield.fill" : "shield.slash",
            accessibilityDescription: state.isConnected ? "VPN On" : "VPN Off"
        )
        statusItem?.button?.image?.isTemplate = true

        let menu = NSMenu()
        menu.addItem(withTitle: state.isConnected ? "VPN 켜짐" : "VPN 꺼짐", action: nil, keyEquivalent: "")
        menu.addItem(withTitle: state.statusText, action: nil, keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())

        let toggle = NSMenuItem(
            title: state.isConnected ? "끄기" : "켜기",
            action: #selector(toggleVPN),
            keyEquivalent: ""
        )
        toggle.target = self
        toggle.isEnabled = !state.isBusy
        menu.addItem(toggle)

        let show = NSMenuItem(title: "창 열기", action: #selector(showWindow), keyEquivalent: "")
        show.target = self
        menu.addItem(show)

        menu.addItem(NSMenuItem.separator())
        let quit = NSMenuItem(title: "종료", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        statusItem?.menu = menu
    }

    @objc private func toggleVPN() {
        Task { await AppState.shared.toggleConnection() }
    }

    @objc private func showWindow() {
        NSApp.activate(ignoringOtherApps: true)
        for window in NSApp.windows {
            window.makeKeyAndOrderFront(nil)
        }
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }
}
