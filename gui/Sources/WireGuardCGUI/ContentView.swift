import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var app: AppState

    var body: some View {
        VStack(spacing: 22) {
            profileBar
            Divider()
            powerButton
            statusBlock
            statsBlock
            Spacer(minLength: 0)
        }
        .padding(24)
        .alert("WireGuardC", isPresented: Binding(
            get: { app.alertMessage != nil },
            set: { if !$0 { app.alertMessage = nil } }
        )) {
            Button("확인", role: .cancel) { app.alertMessage = nil }
        } message: {
            Text(app.alertMessage ?? "")
        }
        .sheet(item: $app.editingProfile) { profile in
            ProfileEditorView(profile: profile) { saved in
                app.saveProfile(saved)
            }
        }
    }

    private var profileBar: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("프로필 설정")
                .font(.title3.weight(.semibold))

            HStack(spacing: 8) {
                Picker("", selection: Binding(
                    get: { app.selectedProfileID },
                    set: { app.selectedProfileID = $0 }
                )) {
                    ForEach(app.profiles) { profile in
                        Text(profile.name).tag(Optional(profile.id))
                    }
                }
                .labelsHidden()
                .frame(maxWidth: .infinity)

                iconButton("qrcode.viewfinder", "QR") { app.importQRCode() }
                iconButton("doc.badge.plus", "파일") { app.importConfigFile() }
                iconButton("plus", "추가") { app.addManualProfile() }
                iconButton("pencil", "수정") { app.editSelectedProfile() }
                    .disabled(app.selectedProfile == nil || app.isConnected)
                iconButton("trash", "삭제") { app.deleteSelectedProfile() }
                    .disabled(app.selectedProfile == nil || app.isConnected)
                iconButton(app.helperInstalled ? "lock.open.fill" : "lock.fill", app.helperInstalled ? "Helper 설치됨" : "Helper 설치") {
                    Task { await app.installPrivilegedHelperFromApp() }
                }
                .disabled(app.helperInstalled || app.isBusy)
            }
        }
    }

    private var powerButton: some View {
        Button {
            Task { await app.toggleConnection() }
        } label: {
            ZStack {
                Circle()
                    .fill(app.isConnected ? Color.green.opacity(0.92) : Color.gray.opacity(0.22))
                    .frame(width: 176, height: 176)
                    .shadow(color: app.isConnected ? .green.opacity(0.28) : .black.opacity(0.08), radius: 18, y: 8)

                Circle()
                    .strokeBorder(app.isConnected ? Color.green.opacity(0.35) : Color.gray.opacity(0.34), lineWidth: 8)
                    .frame(width: 194, height: 194)

                VStack(spacing: 10) {
                    Image(systemName: "power")
                        .font(.system(size: 48, weight: .medium))
                    Text(app.isConnected ? "ON" : "OFF")
                        .font(.system(size: 28, weight: .bold))
                }
                .foregroundStyle(app.isConnected ? .white : .primary)
            }
        }
        .buttonStyle(.plain)
        .disabled(app.isBusy || app.selectedProfile == nil)
        .accessibilityLabel(app.isConnected ? "VPN 끄기" : "VPN 켜기")
    }

    private var statusBlock: some View {
        VStack(spacing: 6) {
            Text(app.statusText)
                .font(.headline)
            if let profile = app.selectedProfile {
                Text(profile.endpoint)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var statsBlock: some View {
        VStack(spacing: 14) {
            Picker("", selection: $app.unit) {
                ForEach(DataUnit.allCases) { unit in
                    Text(unit.rawValue).tag(unit)
                }
            }
            .pickerStyle(.segmented)
            .frame(width: 180)

            Grid(horizontalSpacing: 18, verticalSpacing: 12) {
                GridRow {
                    StatTile(title: "다운로드", value: app.formatted(app.stats.rxRateBps, suffix: "/s"))
                    StatTile(title: "업로드", value: app.formatted(app.stats.txRateBps, suffix: "/s"))
                }
                GridRow {
                    StatTile(title: "받은 데이터", value: app.formatted(app.stats.rxBytes))
                    StatTile(title: "보낸 데이터", value: app.formatted(app.stats.txBytes))
                }
            }

            HStack {
                Button {
                    app.openLog()
                } label: {
                    Label("로그", systemImage: "doc.text.magnifyingglass")
                }
                .disabled(app.isConnected == false && app.stats.error == nil)
            }
        }
    }

    private func iconButton(_ systemName: String, _ title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: systemName)
                .frame(width: 18, height: 18)
        }
        .help(title)
    }
}

struct StatTile: View {
    var title: String
    var value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.title3, design: .monospaced).weight(.semibold))
                .lineLimit(1)
                .minimumScaleFactor(0.75)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(12)
        .frame(width: 212, height: 72, alignment: .leading)
        .background(.quaternary.opacity(0.7), in: RoundedRectangle(cornerRadius: 8))
    }
}
