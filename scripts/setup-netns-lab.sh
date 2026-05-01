#!/usr/bin/env bash
# Set up a Linux network namespace lab for NovaNet testing.
# Creates two namespaces (nova-client, nova-server) connected by a veth pair.
# Requires: root or CAP_NET_ADMIN
set -euo pipefail

NS_CLIENT="nova-client"
NS_SERVER="nova-server"
VETH_CLIENT="novac0"
VETH_SERVER="novas0"
CLIENT_IP="10.99.0.1"
SERVER_IP="10.99.0.2"
PREFIX="24"

# --- Network condition presets ---
PRESET="${1:-loopback}"
case "$PRESET" in
    loopback)   DELAY="0ms"; LOSS="0%";    JITTER="0ms"  ;;
    lan)        DELAY="1ms"; LOSS="0.01%"; JITTER="0.5ms" ;;
    wan)        DELAY="40ms"; LOSS="0.1%"; JITTER="5ms"  ;;
    lossy)      DELAY="40ms"; LOSS="2%";   JITTER="5ms"  ;;
    very-lossy) DELAY="80ms"; LOSS="5%";   JITTER="10ms" ;;
    satellite)  DELAY="600ms"; LOSS="0.5%"; JITTER="20ms" ;;
    mobile)     DELAY="50ms"; LOSS="1%";   JITTER="15ms" ;;
    datacenter) DELAY="0.5ms"; LOSS="0.001%"; JITTER="0.1ms" ;;
    *)
        echo "Unknown preset: $PRESET"
        echo "Available: loopback lan wan lossy very-lossy satellite mobile datacenter"
        exit 1
        ;;
esac

echo "=== NovaNet Network Namespace Lab Setup ==="
echo "Preset: $PRESET (delay=$DELAY, loss=$LOSS, jitter=$JITTER)"
echo ""

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "Error: this script requires root (sudo $0 $*)"
    exit 1
fi

# Clean up existing namespaces
echo "Cleaning up existing namespaces..."
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip netns del "$NS_SERVER" 2>/dev/null || true
ip link del "$VETH_CLIENT" 2>/dev/null || true

# Create namespaces
echo "Creating network namespaces..."
ip netns add "$NS_CLIENT"
ip netns add "$NS_SERVER"

# Create veth pair
echo "Creating veth pair ($VETH_CLIENT <-> $VETH_SERVER)..."
ip link add "$VETH_CLIENT" type veth peer name "$VETH_SERVER"
ip link set "$VETH_CLIENT" netns "$NS_CLIENT"
ip link set "$VETH_SERVER" netns "$NS_SERVER"

# Configure addresses
echo "Configuring IP addresses..."
ip netns exec "$NS_CLIENT" ip addr add "${CLIENT_IP}/${PREFIX}" dev "$VETH_CLIENT"
ip netns exec "$NS_SERVER" ip addr add "${SERVER_IP}/${PREFIX}" dev "$VETH_SERVER"
ip netns exec "$NS_CLIENT" ip link set "$VETH_CLIENT" up
ip netns exec "$NS_CLIENT" ip link set lo up
ip netns exec "$NS_SERVER" ip link set "$VETH_SERVER" up
ip netns exec "$NS_SERVER" ip link set lo up

# Apply network emulation conditions
if [[ "$PRESET" != "loopback" ]]; then
    echo "Applying tc netem conditions to $NS_CLIENT ($VETH_CLIENT)..."
    ip netns exec "$NS_CLIENT" \
        tc qdisc add dev "$VETH_CLIENT" root netem \
        delay "$DELAY" "$JITTER" \
        loss "$LOSS"
fi

echo ""
echo "=== Lab ready ==="
echo "  Client: ip netns exec $NS_CLIENT <command>  (addr: $CLIENT_IP)"
echo "  Server: ip netns exec $NS_SERVER <command>  (addr: $SERVER_IP)"
echo ""
echo "Example:"
echo "  ip netns exec $NS_SERVER cargo run --bin echo-server -- --addr ${SERVER_IP}:9999 &"
echo "  ip netns exec $NS_CLIENT cargo run --bin echo-client -- --server ${SERVER_IP}:9999"
echo ""
echo "To tear down:"
echo "  ip netns del $NS_CLIENT && ip netns del $NS_SERVER"
