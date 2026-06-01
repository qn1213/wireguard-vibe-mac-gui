import Foundation

struct VPNProfile: Codable, Identifiable, Hashable {
    var id: UUID
    var name: String
    var privateKey: String
    var publicKey: String
    var address: String
    var dns: String
    var peerPublicKey: String
    var endpoint: String
    var allowedIPs: String
    var persistentKeepalive: String
    var mtu: String

    init(
        id: UUID = UUID(),
        name: String,
        privateKey: String,
        publicKey: String = "",
        address: String,
        dns: String,
        peerPublicKey: String,
        endpoint: String,
        allowedIPs: String,
        persistentKeepalive: String = "25",
        mtu: String = "1420"
    ) {
        self.id = id
        self.name = name
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.address = address
        self.dns = dns
        self.peerPublicKey = peerPublicKey
        self.endpoint = endpoint
        self.allowedIPs = allowedIPs
        self.persistentKeepalive = persistentKeepalive
        self.mtu = mtu
    }

    var configText: String {
        var interfaceLines = [
            "[Interface]",
            publicKey.isEmpty ? nil : "PublicKey = \(publicKey)",
            "PrivateKey = \(privateKey)",
            "Address = \(address)",
            "DNS = \(dns)",
            mtu.isEmpty ? nil : "MTU = \(mtu)"
        ].compactMap { $0 }

        if interfaceLines.last == "" {
            interfaceLines.removeLast()
        }

        return """
        \(interfaceLines.joined(separator: "\n"))

        [Peer]
        PublicKey = \(peerPublicKey)
        Endpoint = \(endpoint)
        AllowedIPs = \(allowedIPs)
        PersistentKeepalive = \(persistentKeepalive.isEmpty ? "25" : persistentKeepalive)
        """
    }

    static func parse(_ text: String, suggestedName: String) throws -> VPNProfile {
        var section = ""
        var values: [String: [String: String]] = [:]

        for rawLine in text.components(separatedBy: .newlines) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") {
                continue
            }
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                section = String(trimmed.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                values[section, default: [:]] = [:]
                continue
            }
            let parts = trimmed.split(separator: "=", maxSplits: 1).map {
                String($0).trimmingCharacters(in: .whitespaces)
            }
            guard parts.count == 2, !section.isEmpty else {
                continue
            }
            values[section, default: [:]][parts[0]] = parts[1]
        }

        guard let privateKey = values["Interface"]?["PrivateKey"], !privateKey.isEmpty else {
            throw ProfileError.invalidConfig("Interface PrivateKey가 없습니다.")
        }
        guard let address = values["Interface"]?["Address"], !address.isEmpty else {
            throw ProfileError.invalidConfig("Interface Address가 없습니다.")
        }
        guard let dns = values["Interface"]?["DNS"], !dns.isEmpty else {
            throw ProfileError.invalidConfig("Interface DNS가 없습니다.")
        }
        guard let peerPublicKey = values["Peer"]?["PublicKey"], !peerPublicKey.isEmpty else {
            throw ProfileError.invalidConfig("Peer PublicKey가 없습니다.")
        }
        guard let endpoint = values["Peer"]?["Endpoint"], !endpoint.isEmpty else {
            throw ProfileError.invalidConfig("Peer Endpoint가 없습니다.")
        }

        return VPNProfile(
            name: suggestedName,
            privateKey: privateKey,
            publicKey: values["Interface"]?["PublicKey"] ?? "",
            address: address,
            dns: dns,
            peerPublicKey: peerPublicKey,
            endpoint: endpoint,
            allowedIPs: values["Peer"]?["AllowedIPs"] ?? "0.0.0.0/0",
            persistentKeepalive: values["Peer"]?["PersistentKeepalive"] ?? "25",
            mtu: values["Interface"]?["MTU"] ?? "1420"
        )
    }
}

enum ProfileError: LocalizedError {
    case invalidConfig(String)
    case noQRCode
    case engineMissing

    var errorDescription: String? {
        switch self {
        case .invalidConfig(let message):
            return message
        case .noQRCode:
            return "QR 코드를 찾지 못했습니다."
        case .engineMissing:
            return "wireguardc 엔진을 찾지 못했습니다."
        }
    }
}

enum DataUnit: String, CaseIterable, Identifiable {
    case kb = "KB"
    case mb = "MB"

    var id: String { rawValue }
    var divisor: Double { self == .kb ? 1024 : 1024 * 1024 }
}

struct EngineStats: Codable {
    var state: String
    var connected: Bool
    var interface: String?
    var endpoint: String
    var txBytes: UInt64
    var rxBytes: UInt64
    var txRateBps: UInt64
    var rxRateBps: UInt64
    var startedAt: Date?
    var updatedAt: Date
    var error: String?

    static let empty = EngineStats(
        state: "disconnected",
        connected: false,
        interface: nil,
        endpoint: "",
        txBytes: 0,
        rxBytes: 0,
        txRateBps: 0,
        rxRateBps: 0,
        startedAt: nil,
        updatedAt: Date(),
        error: nil
    )
}
