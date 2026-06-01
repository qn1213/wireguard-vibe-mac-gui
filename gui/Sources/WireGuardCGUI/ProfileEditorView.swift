import SwiftUI

struct ProfileEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var profile: VPNProfile
    var onSave: (VPNProfile) -> Void

    init(profile: VPNProfile, onSave: @escaping (VPNProfile) -> Void) {
        _profile = State(initialValue: profile)
        self.onSave = onSave
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("프로필")
                .font(.title2.weight(.semibold))

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                field("이름", text: $profile.name)
                secure("PrivateKey", text: $profile.privateKey)
                field("PublicKey", text: $profile.publicKey)
                field("Address", text: $profile.address)
                field("DNS", text: $profile.dns)
                field("Peer PublicKey", text: $profile.peerPublicKey)
                secure("PresharedKey", text: $profile.presharedKey)
                field("Endpoint", text: $profile.endpoint)
                field("AllowedIPs", text: $profile.allowedIPs)
                field("Keepalive", text: $profile.persistentKeepalive)
                field("MTU", text: $profile.mtu)
            }

            HStack {
                Spacer()
                Button("취소") { dismiss() }
                Button("저장") {
                    onSave(profile)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!isValid)
            }
        }
        .padding(22)
        .frame(width: 560)
    }

    private var isValid: Bool {
        !profile.name.isEmpty &&
        !profile.privateKey.isEmpty &&
        !profile.address.isEmpty &&
        !profile.dns.isEmpty &&
        !profile.peerPublicKey.isEmpty &&
        !profile.endpoint.isEmpty &&
        !profile.allowedIPs.isEmpty
    }

    private func field(_ title: String, text: Binding<String>) -> some View {
        GridRow {
            Text(title)
                .foregroundStyle(.secondary)
                .frame(width: 118, alignment: .trailing)
            TextField(title, text: text)
                .textFieldStyle(.roundedBorder)
        }
    }

    private func secure(_ title: String, text: Binding<String>) -> some View {
        GridRow {
            Text(title)
                .foregroundStyle(.secondary)
                .frame(width: 118, alignment: .trailing)
            SecureField(title, text: text)
                .textFieldStyle(.roundedBorder)
        }
    }
}
