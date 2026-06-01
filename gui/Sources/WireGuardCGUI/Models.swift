import Foundation

struct VPNProfile: Codable, Identifiable, Hashable {
    var id: UUID
    var name: String
    var privateKey: String
    var publicKey: String
    var address: String
    var dns: String
    var peerPublicKey: String
    var presharedKey: String
    var endpoint: String
    var allowedIPs: String
    var persistentKeepalive: String
    var mtu: String

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case privateKey
        case publicKey
        case address
        case dns
        case peerPublicKey
        case presharedKey
        case endpoint
        case allowedIPs
        case persistentKeepalive
        case mtu
    }

    init(
        id: UUID = UUID(),
        name: String,
        privateKey: String,
        publicKey: String = "",
        address: String,
        dns: String,
        peerPublicKey: String,
        presharedKey: String = "",
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
        self.presharedKey = presharedKey
        self.endpoint = endpoint
        self.allowedIPs = allowedIPs
        self.persistentKeepalive = persistentKeepalive
        self.mtu = mtu
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        privateKey = try container.decode(String.self, forKey: .privateKey)
        publicKey = try container.decodeIfPresent(String.self, forKey: .publicKey) ?? ""
        address = try container.decode(String.self, forKey: .address)
        dns = try container.decode(String.self, forKey: .dns)
        peerPublicKey = try container.decode(String.self, forKey: .peerPublicKey)
        presharedKey = try container.decodeIfPresent(String.self, forKey: .presharedKey) ?? ""
        endpoint = try container.decode(String.self, forKey: .endpoint)
        allowedIPs = try container.decode(String.self, forKey: .allowedIPs)
        persistentKeepalive = try container.decodeIfPresent(String.self, forKey: .persistentKeepalive) ?? "25"
        mtu = try container.decodeIfPresent(String.self, forKey: .mtu) ?? "1420"
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

        let peerLines = [
            "[Peer]",
            "PublicKey = \(peerPublicKey)",
            presharedKey.isEmpty ? nil : "PresharedKey = \(presharedKey)",
            "Endpoint = \(endpoint)",
            "AllowedIPs = \(allowedIPs)",
            "PersistentKeepalive = \(persistentKeepalive.isEmpty ? "25" : persistentKeepalive)"
        ].compactMap { $0 }

        return "\(interfaceLines.joined(separator: "\n"))\n\n\(peerLines.joined(separator: "\n"))"
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
                section = String(trimmed.dropFirst().dropLast())
                    .trimmingCharacters(in: .whitespaces)
                    .lowercased()
                values[section, default: [:]] = [:]
                continue
            }
            let parts = trimmed.split(separator: "=", maxSplits: 1).map {
                String($0).trimmingCharacters(in: .whitespaces)
            }
            guard parts.count == 2, !section.isEmpty else {
                continue
            }
            values[section, default: [:]][parts[0].lowercased()] = parts[1]
        }

        guard let privateKey = values["interface"]?["privatekey"], !privateKey.isEmpty else {
            throw ProfileError.invalidConfig("Interface PrivateKey가 없습니다.")
        }
        guard let address = values["interface"]?["address"], !address.isEmpty else {
            throw ProfileError.invalidConfig("Interface Address가 없습니다.")
        }
        guard let dns = values["interface"]?["dns"], !dns.isEmpty else {
            throw ProfileError.invalidConfig("Interface DNS가 없습니다.")
        }
        guard let peerPublicKey = values["peer"]?["publickey"], !peerPublicKey.isEmpty else {
            throw ProfileError.invalidConfig("Peer PublicKey가 없습니다.")
        }
        guard let endpoint = values["peer"]?["endpoint"], !endpoint.isEmpty else {
            throw ProfileError.invalidConfig("Peer Endpoint가 없습니다.")
        }

        return VPNProfile(
            name: suggestedName,
            privateKey: privateKey,
            publicKey: values["interface"]?["publickey"] ?? "",
            address: address,
            dns: dns,
            peerPublicKey: peerPublicKey,
            presharedKey: values["peer"]?["presharedkey"] ?? "",
            endpoint: endpoint,
            allowedIPs: values["peer"]?["allowedips"] ?? "0.0.0.0/0",
            persistentKeepalive: values["peer"]?["persistentkeepalive"] ?? "25",
            mtu: values["interface"]?["mtu"] ?? "1420"
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
