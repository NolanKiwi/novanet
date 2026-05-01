# NovaNet Deployment Model

Version: 0.1-draft

---

## 1. Deployment Philosophy

NovaNet does not require changes to the global Internet to be useful. It follows the same path QUIC took: start userspace-only over UDP, prove value in controlled environments, then expand.

The deployment model has six levels. Each level adds capability and complexity. Start at Level 1.

---

## 2. Level 1: Rust Library + UDP (Phase 1–5)

**Description**: Applications link `novanet-transport` as a Rust library and use it directly.

```
Application binary
  └── novanet-transport (Rust library)
        └── OS UDP socket (standard socket API)
              └── Linux IP stack
                    └── Network
```

**Requirements**:
- Rust application.
- Any OS with UDP socket support.
- No root/CAP_NET_ADMIN needed.
- Outbound UDP allowed (port 443 recommended; most firewalls allow it).

**Limitations**:
- Only Rust applications can use NovaNet directly.
- Existing TCP applications are not affected.
- UDP may be blocked by strict firewalls.

**Target environments**: localhost tests, Docker containers, VMs, cloud instances, Kubernetes pods.

---

## 3. Level 2: Proxy / Sidecar Mode (Phase 5+)

**Description**: A NovaNet proxy process sits beside existing applications. Applications connect to the proxy over TCP; the proxy forwards traffic over NovaNet.

```
App (uses TCP) → local TCP → novanet-proxy → NovaNet (UDP) → novanet-proxy → App (TCP)
```

Similar to: Envoy sidecar in a service mesh, WireGuard proxy mode.

**Requirements**:
- One NovaNet proxy process per host.
- No application code changes.
- No OS changes.
- No root (if using high ports).

**Use case**: Retrofitting NovaNet benefits onto existing non-Rust services. Service mesh replacement with NovaNet as the data plane.

---

## 4. Level 3: TUN/TAP Overlay (Phase 7)

**Description**: A `novanet-tunnel` daemon creates a TUN virtual network interface. IP packets sent to the TUN device are encapsulated in NovaNet sessions and forwarded over UDP.

```
App (any TCP/UDP) → kernel TCP/IP stack → TUN device → novanet-tunnel → UDP → Network
```

Similar to: WireGuard, OpenVPN, Tailscale.

**Requirements**:
- `CAP_NET_ADMIN` or root (to create TUN device).
- Linux kernel ≥ 3.8 for TUN/TAP.
- All other requirements as Level 1.

**Use case**: Any existing application benefits from NovaNet without code changes. Full network-layer overlay.

---

## 5. Level 4: eBPF/XDP Acceleration (Phase 8+, Research)

**Description**: XDP programs attached to NICs process NovaNet packet headers in the kernel fast path, short-circuiting the full network stack for ACK generation and path classification.

```
NIC → XDP program (eBPF) → {ACK generation, session lookup, path classification}
                          → userspace novanet-transport (for complex logic)
```

**Requirements**:
- Linux ≥ 5.6 for XDP redirect.
- Root / CAP_BPF.
- eBPF programs compiled with Rust + `aya` crate or C.

**Use case**: High-throughput servers (100Gbps+) where userspace interrupt-driven I/O is too slow. Datacenter deployments.

---

## 6. Level 5: DPDK Kernel Bypass (Research)

**Description**: NovaNet runs directly on DPDK-managed NICs, bypassing the Linux kernel entirely. All packet processing in userspace.

**Requirements**:
- DPDK-compatible NIC.
- Root / huge pages allocation.
- Dedicated CPU cores.

**Use case**: Line-rate packet processing (hundreds of Gbps). Network function virtualization. Research only; complex to operate.

---

## 7. Level 6: Kernel Module (Long-Term Research)

**Description**: NovaNet implemented as a Linux kernel module, exposing sessions as file descriptors via the socket API. Applications use `socket(AF_NOVANET, SOCK_STREAM, 0)` etc.

**Requirements**:
- Custom kernel module.
- Root for installation.
- Kernel API compatibility management.

**Status**: Not planned for any concrete phase. Would require an OS vendor partnership or Linux kernel community acceptance. Included for completeness.

---

## 8. Container and Kubernetes Deployment

Level 1 (library) and Level 2 (sidecar) work natively in containers:

```yaml
# Docker Compose example (Level 1):
services:
  novanet-server:
    image: my-novanet-app
    ports:
      - "9999:9999/udp"   # NovaNet UDP port
    environment:
      RUST_LOG: "novanet=info"
```

```yaml
# Kubernetes (Level 2 sidecar):
containers:
  - name: app
    image: my-app
  - name: novanet-proxy
    image: novanet-proxy
    ports:
      - containerPort: 9999
        protocol: UDP
    securityContext:
      capabilities:
        add: []   # no special caps needed for Level 2
```

NAT traversal: Level 1 and 2 work through NAT (like QUIC). The server needs a stable UDP port; clients can be behind NAT.

---

## 9. Network Namespace Lab Setup

For local testing with realistic network conditions:

```bash
# /scripts/setup-netns-lab.sh
ip netns add nova-client
ip netns add nova-server
ip link add nova0 type veth peer name nova1
ip link set nova0 netns nova-client
ip link set nova1 netns nova-server
ip netns exec nova-client ip addr add 10.99.0.1/24 dev nova0
ip netns exec nova-server ip addr add 10.99.0.2/24 dev nova1
ip netns exec nova-client ip link set nova0 up lo up
ip netns exec nova-server ip link set nova1 up lo up

# Apply WAN-like emulation:
ip netns exec nova-client tc qdisc add dev nova0 root netem delay 40ms 5ms loss 0.1%
```

Then:
```bash
ip netns exec nova-server ./target/debug/echo-server --addr 10.99.0.2:9999 &
ip netns exec nova-client ./target/debug/echo-client --addr 10.99.0.2:9999
```

---

## 10. Private Network Use Cases

The realistic deployment targets where NovaNet adds value today:

| Environment | Why NovaNet | Deployment Level |
|---|---|---|
| Service mesh (datacenter) | Low latency, multiplexing, observability | 1 or 2 |
| CDN edge → origin | Multipath for failover, observability | 1 |
| Mobile app backend | Mobility over Wi-Fi/LTE transitions | 1 |
| IoT sensor networks | Lightweight, encrypted, multiple delivery modes | 1 |
| Private WAN overlay | Encrypted overlay replacing MPLS | 3 (TUN) |
| High-frequency trading | Deterministic low latency, kernel bypass | 4 or 5 |
| Lab research | All features, controlled environment | All |

---

## 11. What Is NOT Realistic

| Goal | Why Unrealistic |
|---|---|
| Global Internet replacement | Requires ISP, router, and OS vendor adoption; decades of work |
| Browser support | Requires browser vendor API design and standardization |
| NIC offload (standard) | Requires NIC firmware and OS driver changes; vendor-specific |
| BGP/routing integration | NovaNet over UDP; IP routing is unchanged |
| Universal NAT traversal | STUN/TURN rendezvous is still needed for symmetric NAT |
| Replacing TLS for HTTPS | HTTP/3 over QUIC is already deployed; would require browser changes |
