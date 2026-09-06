# PacketLens

🔍 **Android Network Traffic Inspector** — like HTTP Canary, but free and open source.

## Features

- 📡 **Capture ALL network traffic** without root
- 🌐 **HTTP/HTTPS** request/response inspection
- 🌐 **DNS** query monitoring
- 🔒 **TLS** handshake info + SNI extraction
- 📱 **App attribution** — see which app generates each connection
- 📊 **Real-time stats** — packets, bytes, protocols
- 🔍 **Protocol filtering** — HTTP, DNS, TLS, TCP, UDP
- 📦 **Payload preview** — hex/text view

## Architecture

```
VPNService (TUN) → Packet Parser → Protocol Decoder → Room DB → Compose UI
```

- **VPNService** captures all device traffic via TUN interface
- **PacketParser** decodes IP/TCP/UDP/HTTP/DNS/TLS
- **AppResolver** maps UIDs to package names
- **Compose UI** displays connections in real-time

## Tech Stack

- Kotlin + Jetpack Compose + Material3
- Hilt (DI) + Room (DB)
- Android VPNService
- BouncyCastle (cert generation for Phase 2)
- minSdk 26, targetSdk 35

## Build

```bash
# Using GitHub Actions (recommended)
# Push to main triggers CI build
# Download APK from Actions > Artifacts

# Local build (needs Android SDK)
gradle assembleDebug
```

## How It Works

1. Tap **Start** → VPN permission dialog
2. VPNService creates TUN interface
3. All traffic passes through TUN
4. Packets are parsed in real-time
5. Connections appear in the list with app names
6. Tap any connection to see full details

## Roadmap

- [x] Phase 1: MVP — Capture + Display
- [ ] Phase 2: HTTPS Decrypt (User Certificate)
- [ ] Phase 3: Request/Response Modification
- [ ] Phase 4: Export PCAP
- [ ] Phase 5: Script Injection

## License

MIT License
