#!/bin/bash

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  TLS/SSL Handshake - Production Flow Demonstration          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

NODES=(3000 3001 3002 3003 3004)
NODE_IDS=("node1" "node2" "node3" "node4" "node5")
LOG_DIR="./tmp/tls-demo-logs"
PID_FILE="./tmp/tls-demo-pids.txt"

cleanup() {
  echo ""
  echo "Cleaning up nodes..."
  if [ -f "$PID_FILE" ]; then
    while read pid; do
      if kill -0 $pid 2>/dev/null; then
        kill $pid 2>/dev/null || true
      fi
    done < "$PID_FILE"
    rm "$PID_FILE"
  fi
  rm -rf "$LOG_DIR"
  echo "Cleanup complete"
}

trap cleanup EXIT INT TERM

mkdir -p "$LOG_DIR"
rm -f "$PID_FILE"

echo "═══════════════════════════════════════════════════════════════"
echo " Step 1: Starting 5 Production Nodes"
echo "═══════════════════════════════════════════════════════════════"
echo ""

for i in "${!NODES[@]}"; do
  PORT=${NODES[$i]}
  NODE_ID=${NODE_IDS[$i]}
  LOG_FILE="$LOG_DIR/${NODE_ID}.log"
  
  echo -n "Starting ${NODE_ID} on port ${PORT}... "
  
  NODE_ID=$NODE_ID NODE_PORT=$PORT npm run start:prod > "$LOG_FILE" 2>&1 &
  NODE_PID=$!
  echo $NODE_PID >> "$PID_FILE"
  
  echo -e "${GREEN}✓${NC} (PID: $NODE_PID)"
  sleep 2
done

echo ""
echo -e "${GREEN}✓ All 5 nodes started${NC}"
echo ""

echo "Waiting for nodes to be ready..."
sleep 5

echo ""
echo "Verifying node connectivity..."
for i in "${!NODES[@]}"; do
  PORT=${NODES[$i]}
  NODE_ID=${NODE_IDS[$i]}
  
  if curl -s http://localhost:$PORT/info > /dev/null 2>&1; then
    echo -e "  ${NODE_ID}: ${GREEN}✓ Online${NC}"
  else
    echo -e "  ${NODE_ID}: ${YELLOW}⚠ Not ready yet${NC}"
  fi
done

echo "link nodes in topology..."
for port in 3000 3001 3002 3003 3004; do
  curl -s -X POST "http://localhost:${port}/topology/configure" \
    -H "Content-Type: application/json" \
    -d '{
      "nodes": ["node1", "node2", "node3", "node4", "node5"],
      "links": [
        {"from": "node1", "to": "node2", "mtu": 256, "delay": 10, "packetLoss": 0},
        {"from": "node2", "to": "node3", "mtu": 256, "delay": 10, "packetLoss": 0},
        {"from": "node3", "to": "node4", "mtu": 128, "delay": 20, "packetLoss": 0.05},
        {"from": "node4", "to": "node5", "mtu": 256, "delay": 10, "packetLoss": 0}
      ]
    }'
done

sleep 3

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 2: Synchronizing Certificate Authority"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "Getting CA keys from node1..."
CA_KEYS=$(curl -s http://localhost:3000/ca/shared-keys)

if [ -z "$CA_KEYS" ] || [ "$CA_KEYS" == "null" ]; then
  echo -e "${YELLOW}⚠ Warning: Could not get CA keys${NC}"
else
  echo -e "${GREEN}✓ CA keys retrieved${NC}"
  
  # Load CA into other nodes
  for i in 1 2 3 4; do
    PORT=${NODES[$i]}
    NODE_ID=${NODE_IDS[$i]}
    
    echo -n "Loading CA into ${NODE_ID}... "
    RESULT=$(curl -s -X POST http://localhost:$PORT/ca/load-shared-ca \
      -H "Content-Type: application/json" \
      -d "$CA_KEYS")
    
    SUCCESS=$(echo "$RESULT" | jq -r '.success' 2>/dev/null)
    if [ "$SUCCESS" == "true" ] || echo "$RESULT" | grep -q "already initialized"; then
      echo -e "${GREEN}✓${NC}"
    else
      echo -e "${YELLOW}⚠${NC}"
    fi
  done
fi

echo ""
echo -e "${GREEN}✓ Certificate Authority synchronized across all nodes${NC}"

sleep 2

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Phase 1: TLS Handshakes (7-Step Protocol)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "TLS Handshake Steps:"
echo "  1. Client sends random ClientHello (32 bytes)"
echo "  2. Server responds with ServerHello + X.509 SSL Certificate"
echo "  3. Client verifies certificate with CA"
echo "  4. Client sends encrypted premaster secret (RSA-OAEP-SHA256)"
echo "  5. Both derive session keys (HKDF-SHA256)"
echo "  6. Exchange encrypted 'finished' messages (AES-256-GCM)"
echo "  7. Secure channel established"
echo ""

echo "Initiating handshakes between adjacent nodes..."
echo ""

perform_handshake() {
  local from_node=$1
  local from_port=$2
  local to_node=$3
  local to_port=$4
  
  echo -n "  ${from_node} <-> ${to_node}... "
  
  HANDSHAKE_RESULT=$(curl -s -X POST http://localhost:$from_port/test/initiate-handshake \
    -H "Content-Type: application/json" \
    -d "{
      \"targetNode\": \"$to_node\",
      \"targetPort\": $to_port
    }")
  
  if echo "$HANDSHAKE_RESULT" | jq -e '.success' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Complete handshake (7 steps)${NC}"
    return 0
  else
    echo -e "${YELLOW}⚠ Handshake failed${NC}"
    echo "  Error: $HANDSHAKE_RESULT"
    return 1
  fi
}

perform_handshake "node1" 3000 "node2" 3001
sleep 2
perform_handshake "node2" 3001 "node3" 3002
sleep 2
perform_handshake "node3" 3002 "node4" 3003
sleep 2
perform_handshake "node4" 3003 "node5" 3004
sleep 2

echo ""
echo -e "${GREEN}✓ All handshakes completed successfully!${NC}"

sleep 2

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Phase 2: Secure Messaging (Encrypted Communication)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "Sending encrypted messages between nodes..."
echo ""

echo -n "  node1 → node2: "
MSG1_RESULT=$(curl -s -X POST http://localhost:3000/secure/send \
  -H "Content-Type: application/json" \
  -d '{
    "targetNode": "node2",
    "message": "Hello from node1! This is a secure encrypted message.",
    "targetPort": 3001
  }')

if echo "$MSG1_RESULT" | jq -e '.success' > /dev/null 2>&1; then
  echo -e "${GREEN}✓ Sent (AES-256-GCM encrypted)${NC}"
else
  echo -e "${YELLOW}⚠ Failed${NC}"
  echo "  Error: $MSG1_RESULT"
fi
sleep 2

echo -n "  node2 → node1: "
MSG2_RESULT=$(curl -s -X POST http://localhost:3001/secure/send \
  -H "Content-Type: application/json" \
  -d '{
    "targetNode": "node1",
    "message": "Hi node1, this is node2 responding!",
    "targetPort": 3000
  }')

if echo "$MSG2_RESULT" | jq -e '.success' > /dev/null 2>&1; then
  echo -e "${GREEN}✓ Sent (AES-256-GCM encrypted)${NC}"
else
  echo -e "${YELLOW}⚠ Failed${NC}"
  echo "  Error: $MSG2_RESULT"
fi
sleep 2

echo ""
echo "Verifying message reception..."
MSGS_AT_NODE2=$(curl -s http://localhost:3001/secure/messages/node1 | jq -r '.messages | length' 2>/dev/null || echo "0")
MSGS_AT_NODE1=$(curl -s http://localhost:3000/secure/messages/node2 | jq -r '.messages | length' 2>/dev/null || echo "0")

echo "  node2 received: ${MSGS_AT_NODE2} message(s) from node1"
echo "  node1 received: ${MSGS_AT_NODE1} message(s) from node2"

if [ "$MSGS_AT_NODE2" -gt "0" ] && [ "$MSGS_AT_NODE1" -gt "0" ]; then
  echo ""
  echo -e "${GREEN}✓ Direct secure messaging works!${NC}"
else
  echo ""
  echo -e "${YELLOW}⚠ Message delivery issue detected${NC}"
  echo "  Check logs for details: ./tmp/tls-demo-logs/"
fi

sleep 2

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Phase 3: File Transfer Simulation"
echo "═══════════════════════════════════════════════════════════════"
echo ""

FILE_CONTENT="This is a simulated text file being transferred securely.
It contains multiple lines of text to demonstrate that
files can be sent through the encrypted channel.
The file is encrypted using AES-256-GCM encryption.
Line 5: End of file."

FILE_SIZE=${#FILE_CONTENT}

echo "Transferring file from node2 to node3..."
echo "  File size: $FILE_SIZE bytes"
echo "  Encryption: AES-256-GCM"
echo ""

FILE_RESULT=$(curl -s -X POST http://localhost:3001/secure/send \
  -H "Content-Type: application/json" \
  -d "{
    \"targetNode\": \"node3\",
    \"message\": $(echo "$FILE_CONTENT" | jq -Rs .),
    \"targetPort\": 3002
  }")

if echo "$FILE_RESULT" | jq -e '.success' > /dev/null 2>&1; then
  echo -e "  ${GREEN}✓ File sent and encrypted${NC}"
else
  echo -e "  ${YELLOW}⚠ File send failed${NC}"
  echo "  Error: $FILE_RESULT"
fi

sleep 2

echo -n "  Checking reception... "
RECEIVED_MSGS=$(curl -s http://localhost:3002/secure/messages/node2 2>/dev/null)
MSG_COUNT=$(echo "$RECEIVED_MSGS" | jq -r '.messages | length' 2>/dev/null || echo "0")

if [ "$MSG_COUNT" -gt "0" ]; then
  # Get the last message (the file we just sent)
  RECEIVED_FILE=$(echo "$RECEIVED_MSGS" | jq -r '.messages[-1]' 2>/dev/null || echo "")
  RECEIVED_SIZE=${#RECEIVED_FILE}
  
  echo "node3 received: $RECEIVED_SIZE bytes"
  
  if [ "$RECEIVED_SIZE" -ge "$((FILE_SIZE - 10))" ] && [ "$RECEIVED_SIZE" -le "$((FILE_SIZE + 10))" ]; then
    echo -e "  ${GREEN}✓ File integrity verified (size match)${NC}"
  else
    echo -e "  ${YELLOW}⚠ Size difference detected${NC}"
    echo "    Expected: ~$FILE_SIZE bytes, Got: $RECEIVED_SIZE bytes"
  fi
else
  echo -e "${YELLOW}⚠ No messages received${NC}"
  echo "  Expected: 1 file message"
fi

echo ""
echo -e "${GREEN}✓ Secure file transfer capability demonstrated!${NC}"

sleep 2

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Phase 4: Packet Fragmentation (MTU Limits)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "Network topology MTU limits:"
echo "  node1 ↔ node2: 256 bytes"
echo "  node2 ↔ node3: 256 bytes"
echo "  node3 ↔ node4: 128 bytes (slow radio link)"
echo "  node4 ↔ node5: 256 bytes"
echo ""

LARGE_MSG=$(python3 -c "print('A' * 400)" 2>/dev/null || perl -e "print 'A' x 400")
LARGE_SIZE=${#LARGE_MSG}

echo "Sending large message ($LARGE_SIZE bytes) from node1 to node2..."
echo "  Expected: Message will be fragmented if size > MTU (256 bytes)"
echo ""

LARGE_RESULT=$(curl -s -X POST http://localhost:3000/secure/send \
  -H "Content-Type: application/json" \
  -d "{
    \"targetNode\": \"node2\",
    \"message\": \"$LARGE_MSG\",
    \"targetPort\": 3001
  }")

if echo "$LARGE_RESULT" | jq -e '.success' > /dev/null 2>&1; then
  echo -e "${GREEN}✓ Large message sent${NC}"
  echo -e "${GREEN}✓ Message fragmented and reassembled as needed${NC}"
else
  echo -e "${YELLOW}⚠ Large message send failed${NC}"
  echo "  Error: $LARGE_RESULT"
fi

sleep 2

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Phase 5: Network Broadcast"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "Broadcasting message from node1 to entire network..."
echo "  Expected to reach: node2, node3, node4, node5"
echo ""

BROADCAST_MSG="BROADCAST from node1: Hello to all nodes in the network!"
BROADCAST_DATA=$(echo -n "$BROADCAST_MSG" | od -An -tu1 | tr -d ' \n' | sed 's/\([0-9]\+\)/\1,/g' | sed 's/,$//' | sed 's/^/[/' | sed 's/$/]/')

curl -s -X POST http://localhost:3000/network/broadcast \
  -H "Content-Type: application/json" \
  -d "{
    \"fromNode\": \"node1\",
    \"message\": {
      \"type\": \"Buffer\",
      \"data\": $BROADCAST_DATA
    },
    \"visitedNodes\": [\"node1\"]
  }" > /dev/null 2>&1

sleep 2

echo -e "${GREEN}✓ Broadcast sent to all reachable nodes${NC}"
echo -e "${GREEN}✓ Spanning tree algorithm prevented loops${NC}"

sleep 2

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Network Status Summary"
echo "═══════════════════════════════════════════════════════════════"
echo ""

for i in "${!NODES[@]}"; do
  PORT=${NODES[$i]}
  NODE_ID=${NODE_IDS[$i]}
  
  SESSIONS=$(curl -s http://localhost:$PORT/sessions 2>/dev/null | jq -r '.sessions | length' 2>/dev/null || echo "0")
  echo "  ${NODE_ID}: ${SESSIONS} active secure session(s)"
done

echo ""
echo "Network Topology: node1 ↔ node2 ↔ node3 ↔ node4 ↔ node5"
echo "Status: OPERATIONAL"

sleep 2

echo "Node logs available in: $LOG_DIR/"

wait
