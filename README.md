# WireGuardC

macOS 전용 WireGuard 클라이언트 실험 프로젝트입니다.

이 프로젝트는 **바이브 코딩으로 만들었습니다.** 사람이 방향과 요구사항을 정하고, AI와 함께 빠르게 구현/수정/검증하면서 만든 앱입니다.

## What It Does

WireGuardC는 GUI 중심의 macOS VPN 클라이언트입니다.

- QR 이미지에서 WireGuard 설정 추출
- `.conf` 설정파일 import
- 수동 프로필 입력/수정/삭제
- 중앙 원형 버튼으로 VPN ON/OFF
- macOS 메뉴바 아이콘으로 연결 상태 확인 및 토글
- 실시간 업로드/다운로드 속도 표시
- 받은/보낸 누적 데이터 표시
- KB/MB 단위 전환
- 앱 종료 또는 비정상 종료 시 네트워크 라우트 복구 시도

## Important

이 앱은 `wg`, `wg-quick`, `wireguard-go`, WireGuard 공식 라이브러리를 호출하지 않고, Go로 WireGuard 핸드셰이크/transport 처리와 macOS `utun` 터널을 직접 구현한 실험용 클라이언트입니다.

보안 검증을 받은 공식 WireGuard 앱을 대체하는 생산용 소프트웨어로 사용하기 전에 충분히 검토하세요.

## Download / Run

배포 파일은 앱 번들을 zip으로 묶은 형태입니다.

```text
dist/WireGuardC.zip
```

사용자는 zip을 풀고 `WireGuardC.app`를 실행하면 됩니다. Go나 Swift를 설치할 필요는 없습니다.

Gatekeeper 경고가 뜨면 우클릭 후 `열기`를 사용하세요. 제대로 배포하려면 Apple Developer ID 코드서명과 notarization이 필요합니다.

## GUI 사용법

1. 앱을 실행합니다.
2. 상단의 `프로필 설정` 영역에서 프로필을 선택하거나 추가합니다.
3. QR 버튼으로 WireGuard QR 이미지를 가져올 수 있습니다.
4. 파일 버튼으로 WireGuard `.conf` 파일을 가져올 수 있습니다.
5. `+` 버튼으로 수동 입력 프로필을 만들 수 있습니다.
6. 중앙의 원형 버튼을 눌러 VPN을 켜고 끕니다.
7. 오른쪽 상단 macOS 메뉴바 아이콘에서도 상태 확인과 ON/OFF가 가능합니다.
8. 하단 통계 영역에서 실시간 업/다운 속도와 누적 전송량을 확인합니다.
9. `KB` / `MB` segmented control로 표시 단위를 바꿉니다.

## Passwordless ON/OFF

macOS에서 VPN 터널 생성과 라우팅 변경은 root 권한이 필요합니다.

앱은 처음 실행 후 상단의 자물쇠 버튼을 통해 privileged helper를 설치할 수 있습니다. 이때만 관리자 비밀번호가 필요합니다. 설치 후에는 VPN ON/OFF 시 매번 비밀번호를 입력하지 않아도 됩니다.

설치되는 항목:

- `/usr/local/libexec/wireguardc/wireguardc`
- `/usr/local/libexec/wireguardc/wireguardc-root`
- `/etc/sudoers.d/wireguardc`

sudoers 규칙은 현재 사용자에게 아래 helper 명령만 `NOPASSWD`로 허용합니다.

- `start`
- `stop`
- `cleanup`
- `status`

개발 폴더에서 직접 설치하려면:

```bash
make install-helper
```

제거:

```bash
make uninstall-helper
```

## Failure Recovery

앱은 네트워크 라우트가 남아 인터넷이 끊기는 상황을 줄이기 위해 다음 복구 흐름을 사용합니다.

- 정상 종료 시 터널을 먼저 내리고 라우트를 삭제합니다.
- GUI가 예외로 종료되면 Go 엔진이 GUI PID를 감시하다가 자동으로 터널을 내립니다.
- 엔진이 비정상 종료되어도 route cleanup 목록을 `routes.json`에 저장해 다음 실행 시 정리합니다.

강제 전원 종료, 커널 panic, `kill -9`처럼 cleanup 코드가 실행될 기회가 없는 경우에는 즉시 복구가 불가능할 수 있습니다. 이런 경우 앱을 다시 실행하면 남은 route-state cleanup을 시도합니다.

## Build From Source

개발 환경:

- macOS
- Xcode / Swift
- Go

빌드:

```bash
make app
```

생성물:

```text
dist/WireGuardC.app
```

zip 패키징:

```bash
cd dist
zip -r WireGuardC.zip WireGuardC.app
```

CLI 엔진만 빌드:

```bash
make build
```

테스트:

```bash
go test ./...
```

## Config Example

앱은 표준 WireGuard 스타일 설정을 가져옵니다.

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.0.0.2/24
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

실제 private key나 개인 서버 설정은 GitHub에 올리지 마세요.

## Repository Hygiene

공유 전에 민감한 파일은 제거했습니다.

- 실제 `config/wireguardc.conf`는 포함하지 않습니다.
- 로그와 프로파일 파일은 포함하지 않습니다.
- 빌드 캐시는 포함하지 않습니다.
- 앱 번들에는 예시 설정만 포함합니다.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

## Disclaimer

이 프로젝트는 학습/실험용입니다. 자체 WireGuard 구현은 암호 프로토콜, 라우팅, macOS 네트워크 동작을 직접 다루므로 충분한 보안 리뷰와 테스트 없이 중요한 환경에 사용하지 마세요.

---

# WireGuardC English Guide

WireGuardC is an experimental macOS WireGuard client.

This project was built through **vibe coding**: a human set the direction and requirements, then implemented, tested, and iterated quickly together with AI.

## What It Does

WireGuardC is a GUI-first macOS VPN client.

- Import WireGuard profiles from QR images
- Import `.conf` configuration files
- Create and edit profiles manually
- Turn VPN ON/OFF with a large circular button
- Check and toggle VPN state from the macOS menu bar
- View real-time upload/download speed
- View total sent/received traffic
- Switch displayed units between KB and MB
- Attempt route cleanup when the app exits or crashes

## Important

This app does not call `wg`, `wg-quick`, `wireguard-go`, or official WireGuard libraries. The WireGuard handshake, transport packet handling, and macOS `utun` tunnel are implemented directly in Go.

Treat this as an experimental client. Do not use it as a production replacement for the official WireGuard app without proper review and testing.

## Download / Run

The distributable app is packaged as:

```text
dist/WireGuardC.zip
```

Users can unzip it and run `WireGuardC.app`. They do not need Go or Swift installed.

If macOS Gatekeeper shows a warning, use right-click then `Open`. For proper public distribution, sign and notarize the app with an Apple Developer ID.

## GUI Usage

1. Launch the app.
2. Choose or add a profile in the `프로필 설정` profile area.
3. Use the QR button to import a WireGuard QR image.
4. Use the file button to import a WireGuard `.conf` file.
5. Use the `+` button to create a profile manually.
6. Press the large circular button to turn the VPN on or off.
7. Use the macOS menu bar icon to check status and toggle ON/OFF.
8. View real-time upload/download speed and total traffic in the stats area.
9. Switch between `KB` and `MB` display units.

## Passwordless ON/OFF

Creating a VPN tunnel and changing routes on macOS requires root privileges.

The app includes a privileged helper installer. Press the lock button in the app once, enter the administrator password, and future VPN ON/OFF actions will not ask for a password.

Installed files:

- `/usr/local/libexec/wireguardc/wireguardc`
- `/usr/local/libexec/wireguardc/wireguardc-root`
- `/etc/sudoers.d/wireguardc`

The sudoers rule only allows the current user to run these helper commands without a password:

- `start`
- `stop`
- `cleanup`
- `status`

If you are developing from source, you can also install the helper with:

```bash
make install-helper
```

Uninstall:

```bash
make uninstall-helper
```

## Failure Recovery

The app tries to avoid leaving stale routes behind.

- On normal app exit, it stops the tunnel and removes routes.
- If the GUI crashes, the Go engine watches the GUI PID and stops the tunnel automatically.
- If the engine exits unexpectedly, cleanup commands are persisted in `routes.json` and retried on the next app launch.

Immediate cleanup is not possible after events like forced power-off, kernel panic, or `kill -9`, because the process has no chance to run cleanup code. In those cases, relaunching the app attempts stale route cleanup.

## Build From Source

Requirements:

- macOS
- Xcode / Swift
- Go

Build the app:

```bash
make app
```

Output:

```text
dist/WireGuardC.app
```

Package as zip:

```bash
cd dist
zip -r WireGuardC.zip WireGuardC.app
```

Build only the CLI engine:

```bash
make build
```

Run tests:

```bash
go test ./...
```

## Config Example

The app accepts standard WireGuard-style configuration files.

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.0.0.2/24
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Do not commit real private keys or personal server configuration to GitHub.

## Repository Hygiene

Sensitive local files have been removed.

- Real `config/wireguardc.conf` is not included.
- Logs and profiling files are not included.
- Build caches are not included.
- The bundled app contains only an example config.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

## Disclaimer

This project is for learning and experimentation. A custom WireGuard implementation touches cryptographic protocol logic, routing, and macOS networking internals. Do not rely on it in critical environments without proper security review and testing.
