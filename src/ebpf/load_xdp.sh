#!/bin/bash
# Script to load the modified XDP program with endianness fix

set -e

# Parameters
IFACE="lo"
PORT=443
MAP_PATH="/sys/fs/bpf/xdp/globals/target_port"

echo "Building modified XDP program..."
clang -g -O2 -Wall -target bpf -I/usr/include/bpf -I/usr/include -c xdp_tcp_capture.c -o build/xdp_tcp_capture.o

# Remove any existing program
echo "Removing any existing XDP program..."
sudo ip link set dev $IFACE xdp off 2>/dev/null || true

echo "Loading modified XDP program on $IFACE..."
sudo ip link set dev $IFACE xdp obj build/xdp_tcp_capture.o sec xdp

if ! ip link show dev $IFACE | grep -q "xdp"; then
    echo "Failed to load XDP program on $IFACE"
    exit 1
fi

echo "XDP program loaded successfully!"

# Check if map was pinned correctly
if [ ! -e "$MAP_PATH" ]; then
    echo "ERROR: Map not pinned correctly. It should be at $MAP_PATH"
    echo "Available maps:"
    sudo bpftool map
    sudo ls -l /sys/fs/bpf/xdp/globals/ 2>/dev/null || echo "No pinned maps found"
    echo "Unloading program..."
    sudo ip link set dev $IFACE xdp off
    exit 1
fi

echo "Found pinned map at $MAP_PATH"

# Fix for port endianness issue
# Convert port to network byte order (big endian) for 32-bit value
PORT_HEX=$(printf '%08x' $PORT)
echo "Setting target port to $PORT (0x$PORT_HEX)..."

# Try different ways to set the port value
sudo bpftool map update pinned $MAP_PATH key 0 0 0 0 value $PORT 0 0 0
# Also verify with hex value
sudo bpftool map update pinned $MAP_PATH key 0 0 0 0 value 0x$PORT_HEX 0 0 0

# Verify the map contents
echo "Map contents:"
sudo bpftool map dump pinned $MAP_PATH

# Get the eth0 IP address
ETH_IP=$(ip -4 addr show dev $IFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [ -z "$ETH_IP" ]; then
    echo "Could not determine $IFACE IP address. Using hostname."
    ETH_IP=$(hostname -I | awk '{print $1}')
fi

echo ""
echo "XDP program is now running with debug output!"
echo ""
echo "For testing, use (in a different terminal):"
echo "  echo 'test' | nc -v $ETH_IP $PORT"
echo ""
echo "Monitoring trace_pipe for debug output..."
echo "Press Ctrl+C to stop monitoring"
echo ""
sudo cat /sys/kernel/debug/tracing/trace_pipe
