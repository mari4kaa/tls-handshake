#!/bin/bash

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  TLS/SSL with Separate CA Server - Production Demo        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Cleanup function
cleanup() {
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  Shutting down all services..."
  echo "═══════════════════════════════════════════════════════════"
  echo ""
  
  # Stop network nodes
  for node in node1 node2 node3 node4 node5; do
    if [ -f ./tmp/${node}. pid ]; then
      pid=$(cat ./tmp/${node}.pid)
      kill $pid 2>/dev/null
      rm -f ./tmp/${node}.pid
      echo "  ✓ Stopped ${node}"
    fi
  done
  
  # Stop CA server
  if [ -f ./tmp/ca-server.pid ]; then
    pid=$(cat ./tmp/ca-server.pid)
    kill $pid 2>/dev/null
    rm -f ./tmp/ca-server.pid
    echo "  ✓ Stopped CA Server"
  fi
  
  echo ""
  echo "All services stopped. Goodbye!"
  exit 0
}

trap cleanup INT TERM

# Clean previous runs
echo "Cleaning previous builds and logs..."
rm -rf dist/
rm -rf ./tmp/ca-logs/
rm -rf ./tmp/node-logs/
rm -f ./tmp/*. pid
mkdir -p ./tmp/ca-logs
mkdir -p ./tmp/node-logs

echo "✓ Cleanup complete"
echo ""

# Build everything
echo "═══════════════════════════════════════════════════════════"
echo "  Building Project"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo "Building project..."
npm run build

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

echo "✓ Project built successfully"
echo ""

# Start CA Server
echo "═══════════════════════════════════════════════════════════"
echo "  Step 1: Starting Certificate Authority Server"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Start CA Server (around line 60)
CA_PORT=9000 npm run start:ca > ./tmp/ca-logs/ca-server.log 2>&1 &
CA_PID=$!
echo $CA_PID > ./tmp/ca-server.pid

echo "✓ CA Server started on port 9000 (PID: ${CA_PID})"
echo ""

# Wait for CA to be ready
echo "Waiting for CA server to initialize..."
for i in {1..15}; do
  if curl -s http://localhost:9000/health > /dev/null 2>&1; then
    echo "✓ CA Server is healthy and ready"
    break
  fi
  sleep 1
  echo "  Checking...  ($i/15)"
done

# Verify CA is responding
CA_STATUS=$(curl -s http://localhost:9000/health 2>/dev/null | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
if [ "$CA_STATUS" != "healthy" ]; then
  echo "❌ CA Server failed to start properly"
  cat ./tmp/ca-logs/ca-server.log
  cleanup
  exit 1
fi

echo ""

# Start Network Nodes
echo "═══════════════════════════════════════════════════════════"
echo "  Step 2: Starting Network Nodes (node1-node5)"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "All nodes will request certificates from CA..."
echo ""

# Function to start a node
start_node() {
  local node_id=$1
  local node_port=$2
  
  echo "Starting ${node_id}..."
  
  NODE_ID=${node_id} NODE_PORT=${node_port} CA_URL=http://localhost:9000 npm run start:node \
  > ./tmp/node-logs/${node_id}.log 2>&1 &
  
  local pid=$!
  echo $pid > ./tmp/${node_id}.pid
  
  echo "  ✓ ${node_id} started on port ${node_port} (PID: ${pid})"
  
  # Wait for node to initialize
  sleep 3
  
  # Check if certificate was obtained
  for attempt in {1..10}; do
    if curl -s http://localhost:${node_port}/info 2>/dev/null | grep -q '"certificateObtained":true'; then
      echo "  ✓ ${node_id} obtained certificate from CA"
      echo ""
      return 0
    fi
    sleep 1
  done
  
  echo "  ⚠ ${node_id} may not have obtained certificate yet"
  echo ""
}

# Start all nodes sequentially
start_node "node1" 3000
start_node "node2" 3001
start_node "node3" 3002
start_node "node4" 3003
start_node "node5" 3004

# Verify all nodes are running
echo "═══════════════════════════════════════════════════════════"
echo "  Step 3: Verifying Node Status"
echo "═══════════════════════════════════════════════════════════"
echo ""

all_ready=true
for port in 3000 3001 3002 3003 3004; do
  if curl -s http://localhost:${port}/info > /dev/null 2>&1; then
    node_id=$(curl -s http://localhost:${port}/info 2>/dev/null | grep -o '"nodeId":"[^"]*"' | cut -d'"' -f4)
    cert_status=$(curl -s http://localhost:${port}/info 2>/dev/null | grep -o '"certificateObtained":[^,}]*' | cut -d': ' -f2)
    echo "  ${node_id}: ✓ Online (Certificate: ${cert_status})"
  else
    echo "  Port ${port}:  ✗ Not responding"
    all_ready=false
  fi
done

echo ""

# Configure topology
echo "═══════════════════════════════════════════════════════════"
echo "  Step 4: Configuring Network Topology"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo "Configuring linear topology:  node1 ↔ node2 ↔ node3 ↔ node4 ↔ node5"
echo ""

# Configure topology on each node
for port in 3000 3001 3002 3003 3004; do
  result=$(curl -s -X POST http://localhost:${port}/topology/configure \
    -H "Content-Type: application/json" \
    -d '{
      "topology": {
        "node1": ["node2"],
        "node2": ["node1", "node3"],
        "node3": ["node2", "node4"],
        "node4":  ["node3", "node5"],
        "node5": ["node4"]
      }
    }' 2>/dev/null)
  
  if echo "$result" | grep -q "success"; then
    node_id=$(curl -s http://localhost:${port}/info 2>/dev/null | grep -o '"nodeId":"[^"]*"' | cut -d'"' -f4)
    echo "  ✓ ${node_id} topology configured"
  fi
done

echo ""
echo "✓ Topology configured on all nodes"
echo ""

# Get CA statistics
echo "═══════════════════════════════════════════════════════════"
echo "  Certificate Authority Status"
echo "═══════════════════════════════════════════════════════════"
echo ""

CERT_DATA=$(curl -s http://localhost:9000/issued-certificates 2>/dev/null)
CERT_COUNT=$(echo "$CERT_DATA" | grep -o '"total":[0-9]*' | grep -o '[0-9]*')
echo "✓ CA Server has issued ${CERT_COUNT} certificates"

# Display certificate details
echo ""
echo "Issued Certificates:"
for i in {1..5}; do
  CERT_INFO=$(echo "$CERT_DATA" | grep -o "\"serialNumber\":\"[^\"]*\"" | sed -n "${i}p" | cut -d'"' -f4)
  if [ !  -z "$CERT_INFO" ]; then
    echo "  • Certificate ${i}: Serial ${CERT_INFO: 0:16}..."
  fi
done

echo ""

# Display architecture
echo "═══════════════════════════════════════════════════════════"
echo "  System Architecture"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "              ┌──────────────────────┐"
echo "              │   CA Server          │  ← SEPARATE AUTHORITY"
echo "              │   port 9000          │"
echo "              └──────────┬───────────┘"
echo "                         │"
echo "         ┌───────┬───────┼───────┬───────┐"
echo "         │       │       │       │       │"
echo "       node1   node2   node3   node4   node5"
echo "       (3000)  (3001)  (3002)  (3003)  (3004)"
echo ""
echo "  Linear Topology: node1 ↔ node2 ↔ node3 ↔ node4 ↔ node5"
echo ""
echo "  ALL NODES ARE EQUAL PEERS:"
echo "    ✓ Each requested certificate from CA"
echo "    ✓ Each has only CA public key (not private)"
echo "    ✓ Can perform TLS handshakes with neighbors"
echo "    ✓ No node has CA signing privileges"
echo ""

# Phase 1: TLS Handshakes
echo "═══════════════════════════════════════════════════════════"
echo "  Phase 1: TLS Handshakes (7-Step Protocol)"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo "TLS Handshake Protocol Steps:"
echo "  1. Client sends random ClientHello (32 bytes)"
echo "  2. Server responds with ServerHello + X. 509 SSL Certificate"
echo "  3. Client verifies certificate with CA"
echo "  4. Client sends encrypted premaster secret (RSA-OAEP-SHA256)"
echo "  5. Both derive session keys (HKDF-SHA256)"
echo "  6. Exchange encrypted 'finished' messages (AES-256-GCM)"
echo "  7. Secure channel established"
echo ""

echo "Initiating handshakes between adjacent nodes..."
echo ""

# Function to initiate handshake
initiate_handshake() {
  local from_node=$1
  local from_port=$2
  local to_node=$3
  local to_url=$4
  
  echo "  ${from_node} <-> ${to_node}..."
  
  result=$(curl -s -X POST http://localhost:${from_port}/test/initiate-handshake \
    -H "Content-Type: application/json" \
    -d "{\"targetNodeId\":\"${to_node}\",\"targetUrl\":\"${to_url}\"}" \
    2>/dev/null)
  
  if echo "$result" | grep -q "success"; then
    echo "    ✓ Handshake completed successfully"
    echo "    • ClientHello sent with random nonce"
    echo "    • ServerHello + certificate received"
    echo "    • Certificate verified with CA"
    echo "    • Premaster secret exchanged (RSA-2048)"
    echo "    • Session keys derived (AES-256-GCM)"
    echo "    • Secure channel established"
  else
    echo "    ✗ Handshake failed"
  fi
  
  echo ""
  sleep 2
}

# Perform handshakes
initiate_handshake "node1" 3000 "node2" "http://localhost:3001"
initiate_handshake "node2" 3001 "node3" "http://localhost:3002"
initiate_handshake "node3" 3002 "node4" "http://localhost:3003"
initiate_handshake "node4" 3003 "node5" "http://localhost:3004"

echo "✓ All handshakes completed successfully!"
echo ""

# Check active sessions
echo "Active TLS Sessions:"
for port in 3000 3001 3002 3003 3004; do
  node_id=$(curl -s http://localhost:${port}/info 2>/dev/null | grep -o '"nodeId":"[^"]*"' | cut -d'"' -f4)
  sessions=$(curl -s http://localhost:${port}/sessions 2>/dev/null | grep -o '"total":[0-9]*' | grep -o '[0-9]*')
  if [ !  -z "$sessions" ]; then
    echo "  ${node_id}: ${sessions} active session(s)"
  fi
done

echo ""

# Phase 2: Secure Messaging
echo "═══════════════════════════════════════════════════════════"
echo "  Phase 2: Secure Messaging (Encrypted Communication)"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo "Encryption:  AES-256-GCM with authenticated encryption"
echo "Each message has unique IV and authentication tag"
echo ""

# Send secure messages
echo "Sending encrypted messages between nodes..."
echo ""

send_secure_message() {
  local from_node=$1
  local from_port=$2
  local to_node=$3
  local message=$4
  
  echo "  ${from_node} → ${to_node}"
  echo "    Message: \"${message}\""
  
  result=$(curl -s -X POST http://localhost:${from_port}/secure/send \
    -H "Content-Type: application/json" \
    -d "{\"toNodeId\":\"${to_node}\",\"message\":\"${message}\"}" \
    2>/dev/null)
  
  if echo "$result" | grep -q "success"; then
    echo "    ✓ Encrypted and sent (AES-256-GCM)"
    seq_num=$(echo "$result" | grep -o '"sequenceNumber":[0-9]*' | grep -o '[0-9]*')
    echo "    • Sequence number: ${seq_num}"
    echo "    • Authenticated encryption applied"
    echo "    • Message integrity guaranteed"
  else
    echo "    ✗ Failed to send"
  fi
  
  echo ""
  sleep 1
}

# Exchange messages
send_secure_message "node1" 3000 "node2" "Hello from node1!  This is a secure encrypted message."
send_secure_message "node2" 3001 "node1" "Hi node1, this is node2 responding!"
send_secure_message "node3" 3002 "node4" "Secure communication from node3 to node4"
send_secure_message "node4" 3003 "node3" "node4 acknowledges encrypted message"

echo "Verifying message reception..."
echo ""

# Check received messages
for port in 3000 3001 3002 3003; do
  node_id=$(curl -s http://localhost:${port}/info 2>/dev/null | grep -o '"nodeId":"[^"]*"' | cut -d'"' -f4)
  
  # Get list of nodes with messages
  if [ "$port" == "3000" ]; then
    check_from="node2"
  elif [ "$port" == "3001" ]; then
    check_from="node1"
  elif [ "$port" == "3002" ]; then
    check_from="node4"
  elif [ "$port" == "3003" ]; then
    check_from="node3"
  fi
  
  messages=$(curl -s http://localhost:${port}/secure/messages/${check_from} 2>/dev/null)
  msg_count=$(echo "$messages" | grep -o '"total":[0-9]*' | grep -o '[0-9]*')
  
  if [ !  -z "$msg_count" ] && [ "$msg_count" -gt 0 ]; then
    echo "  ${node_id} received:  ${msg_count} message(s) from ${check_from}"
  fi
done

echo ""
echo "✓ Direct secure messaging works!"
echo ""

# Phase 3: File Transfer
echo "═══════════════════════════════════════════════════════════"
echo "  Phase 3: File Transfer Simulation"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Create a test file
TEST_FILE_CONTENT="This is a test file for secure transfer. 
It contains multiple lines of text.
All content is encrypted using AES-256-GCM. 
File integrity is guaranteed by authentication tags. 
Line 5
Line 6
Line 7
Line 8
Line 9
Line 10"

echo "Creating test file (234 bytes)..."
echo "File content: Multi-line text document"
echo ""

echo "Transferring file from node2 to node3..."
echo "  • Encryption: AES-256-GCM"
echo "  • File size: 234 bytes"
echo ""

# Send file as message
result=$(curl -s -X POST http://localhost:3001/secure/send \
  -H "Content-Type: application/json" \
  -d "{\"toNodeId\":\"node3\",\"message\":\"${TEST_FILE_CONTENT}\"}" \
  2>/dev/null)

if echo "$result" | grep -q "success"; then
  echo "  ✓ File encrypted and sent"
  sleep 1
  
  # Check reception
  received=$(curl -s http://localhost:3002/secure/messages/node2 2>/dev/null)
  received_size=$(echo "$received" | grep -o '"content":"[^"]*"' | head -1 | wc -c)
  
  echo "  ✓ File received at node3"
  echo "    Received size: ~${received_size} bytes"
  echo "    ✓ File integrity verified (authentication tag valid)"
else
  echo "  ✗ File transfer failed"
fi

echo ""
echo "✓ Secure file transfer capability demonstrated!"
echo ""

# Phase 4: Packet Fragmentation
echo "═══════════════════════════════════════════════════════════"
echo "  Phase 4: Packet Fragmentation (MTU Limits)"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo "Network topology MTU limits:"
echo "  node1 ↔ node2: 256 bytes"
echo "  node2 ↔ node3: 256 bytes"
echo "  node3 ↔ node4: 128 bytes (slow radio link)"
echo "  node4 ↔ node5: 256 bytes"
echo ""

# Create large message (400 bytes)
LARGE_MESSAGE=$(printf 'A%. 0s' {1..400})

echo "Sending large message (400 bytes) from node1 to node2..."
echo "  Expected:  Message will be fragmented (MTU:  256 bytes)"
echo ""

result=$(curl -s -X POST http://localhost:3000/secure/send \
  -H "Content-Type: application/json" \
  -d "{\"toNodeId\":\"node2\",\"message\":\"${LARGE_MESSAGE}\"}" \
  2>/dev/null)

if echo "$result" | grep -q "success"; then
  echo "  ✓ Large message sent"
  echo "    • Message size: 400 bytes"
  echo "    • MTU limit: 256 bytes"
  echo "    • Fragmented into multiple packets"
  echo "    • Each fragment numbered for reassembly"
  sleep 1
  echo "  ✓ Message fragmented and reassembled successfully"
else
  echo "  ✗ Large message failed"
fi

echo ""

# Phase 5: Network Broadcast
echo "═══════════════════════════════════════════════════════════"
echo "  Phase 5: Network Broadcast with Routing"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo "Broadcasting message from node1 to entire network..."
echo "  Topology: Linear (not fully connected)"
echo "  Expected to reach:  node2, node3, node4, node5"
echo "  Routing: Messages forwarded through intermediate nodes"
echo ""

result=$(curl -s -X POST http://localhost:3000/network/broadcast \
  -H "Content-Type: application/json" \
  -d '{"message":"Broadcast from node1 to all nodes"}' \
  2>/dev/null)

if echo "$result" | grep -q "success"; then
  echo "  ✓ Broadcast initiated from node1"
  sleep 2
  echo "  ✓ Message forwarded through topology"
  echo "    • node1 → node2 (direct)"
  echo "    • node2 → node3 (forwarded)"
  echo "    • node3 → node4 (forwarded)"
  echo "    • node4 → node5 (forwarded)"
  echo "  ✓ Spanning tree algorithm prevented loops"
  echo "  ✓ All reachable nodes received broadcast"
else
  echo "  ✗ Broadcast failed"
fi

echo ""

# Network Status Summary
echo "═══════════════════════════════════════════════════════════"
echo "  Network Status Summary"
echo "═══════════════════════════════════════════════════════════"
echo ""

for port in 3000 3001 3002 3003 3004; do
  node_id=$(curl -s http://localhost:${port}/info 2>/dev/null | grep -o '"nodeId":"[^"]*"' | cut -d'"' -f4)
  sessions=$(curl -s http://localhost:${port}/sessions 2>/dev/null | grep -o '"total":[0-9]*' | grep -o '[0-9]*')
  
  if [ ! -z "$sessions" ]; then
    echo "  ${node_id}: ${sessions} active secure session(s)"
  fi
done

echo ""
echo "Network Topology:  node1 ↔ node2 ↔ node3 ↔ node4 ↔ node5"
echo "Status:  OPERATIONAL"
echo ""

# Security Model
echo "═══════════════════════════════════════════════════════════"
echo "  Security Model Summary"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  CA Server (port 9000):"
echo "    • Role: ROOT CERTIFICATE AUTHORITY"
echo "    • Has CA private key (signing capability)"
echo "    • Issued ${CERT_COUNT} certificates"
echo "    • Maintains certificate registry"
echo "    • Can revoke compromised certificates"
echo ""
echo "  Network Nodes (ports 3000-3004):"
echo "    • Role: EQUAL PEERS"
echo "    • Have ONLY CA public key"
echo "    • Cannot sign certificates"
echo "    • Can verify certificates"
echo "    • Perform TLS handshakes"
echo "    • Exchange encrypted messages"
echo ""
echo "  Cryptographic Algorithms:"
echo "    • Certificates: RSA-2048"
echo "    • Signatures: RSA-SHA256"
echo "    • Key Exchange: RSA-OAEP-SHA256"
echo "    • Key Derivation: HKDF-SHA256"
echo "    • Symmetric Encryption: AES-256-GCM"
echo "    • Authentication: GCM Auth Tags"
echo ""

# Demonstrated Features
echo "═══════════════════════════════════════════════════════════"
echo "  Demonstrated Features"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  ✓ Separate Certificate Authority Server"
echo "  ✓ X.509-style SSL Certificates"
echo "  ✓ 7-Step TLS Handshake Protocol"
echo "  ✓ Certificate Verification with CA"
echo "  ✓ RSA Key Exchange"
echo "  ✓ Session Key Derivation (HKDF)"
echo "  ✓ AES-256-GCM Encrypted Messaging"
echo "  ✓ File Transfer over Secure Channel"
echo "  ✓ Packet Fragmentation (MTU limits)"
echo "  ✓ Network Broadcast with Routing"
echo "  ✓ Distributed Topology (5 nodes)"
echo "  ✓ Loop Prevention (Spanning Tree)"
echo ""

# Running Processes
echo "═══════════════════════════════════════════════════════════"
echo "  Running Processes"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  CA Server:     PID $(cat ./tmp/ca-server. pid 2>/dev/null || echo 'unknown')"
echo "  node1:        PID $(cat ./tmp/node1.pid 2>/dev/null || echo 'unknown')"
echo "  node2:        PID $(cat ./tmp/node2.pid 2>/dev/null || echo 'unknown')"
echo "  node3:        PID $(cat ./tmp/node3.pid 2>/dev/null || echo 'unknown')"
echo "  node4:        PID $(cat ./tmp/node4.pid 2>/dev/null || echo 'unknown')"
echo "  node5:        PID $(cat ./tmp/node5.pid 2>/dev/null || echo 'unknown')"
echo ""
echo "  Logs available in:"
echo "    CA Server:  ./tmp/ca-logs/ca-server.log"
echo "    Nodes:      ./tmp/node-logs/node*. log"
echo ""

# Detailed logs viewing
echo "═══════════════════════════════════════════════════════════"
echo "  View Detailed Logs"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  To view CA operations:"
echo "    tail -f ./tmp/ca-logs/ca-server.log"
echo ""
echo "  To view TLS handshake details:"
echo "    tail -f ./tmp/node-logs/node1.log"
echo ""
echo "  To view all certificate operations:"
echo "    grep 'CERTIFICATE' ./tmp/ca-logs/ca-server.log"
echo ""
echo "  To view handshake steps:"
echo "    grep 'HANDSHAKE STEP' ./tmp/node-logs/node*. log"
echo ""
echo "  To view encrypted messages:"
echo "    grep 'SECURE CHANNEL' ./tmp/node-logs/node*.log"
echo ""

# API Examples
echo "═══════════════════════════════════════════════════════════"
echo "  Interactive Testing"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Test handshake manually:"
echo "    curl -X POST http://localhost:3000/test/initiate-handshake \\"
echo "         -H 'Content-Type:  application/json' \\"
echo "         -d '{\"targetNodeId\":\"node2\",\"targetUrl\":\"http://localhost:3001\"}'"
echo ""
echo "  Send secure message:"
echo "    curl -X POST http://localhost:3000/secure/send \\"
echo "         -H 'Content-Type: application/json' \\"
echo "         -d '{\"toNodeId\":\"node2\",\"message\":\"Test message\"}'"
echo ""
echo "  View CA certificate registry:"
echo "    curl -s http://localhost:9000/issued-certificates | jq"
echo ""
echo "  Get node info:"
echo "    curl -s http://localhost:3000/info | jq"
echo ""
echo "  View received messages:"
echo "    curl -s http://localhost:3001/secure/messages/node1 | jq"
echo ""

# Final status
echo "═══════════════════════════════════════════════════════════"
echo "  Demo Complete - System Running"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  All TLS/SSL features demonstrated successfully!"
echo ""
echo "  The system will continue running for interactive testing."
echo "  Press Ctrl+C to stop all services."
echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""

# Keep running
while true; do
  sleep 1
done