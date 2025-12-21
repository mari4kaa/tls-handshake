// Protocol message types
export interface ClientHello {
  clientRandom: Buffer;
}

export interface ServerHello {
  serverRandom: Buffer;
  certificate: string; // PEM format or public key
}

export interface EncryptedPremaster {
  payload: Buffer;
}

export interface FinishedMessage {
  encryptedPayload: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export interface SecureMessage {
  sequenceNumber: number;
  iv: Buffer;
  ciphertext: Buffer;
  authTag: Buffer;
}

// Certificate types
export interface Certificate {
  publicKey: string;
  privateKey?: string;
  pemCertificate?: string;
  issuedBy?: string;
  subject?: string;
  validFrom?: Date;
  validTo?: Date;
}

// Session types
export interface SessionKeys {
  encryptionKey: Buffer;
  ivSeed: Buffer;
  hmacKey?: Buffer;
}

export interface HandshakeSession {
  nodeId: string;
  clientRandom?: Buffer;
  serverRandom?: Buffer;
  premasterSecret?: Buffer;
  sessionKeys?: SessionKeys;
  isComplete: boolean;
  isClient: boolean;
}

// Network types
export interface NetworkPacket {
  source: string;
  destination: string;
  payload: Buffer;
  sequenceNumber: number;
  isFragment?: boolean;
  fragmentId?: string;
  fragmentIndex?: number;
  totalFragments?: number;
}

export interface NetworkLink {
  from: string;
  to: string;
  mtu: number;
  delay?: number;
  packetLoss?: number;
}

export interface NetworkTopology {
  nodes: string[];
  links: NetworkLink[];
}

export interface RouteInfo {
  path: string[];
  hops: number;
}

// HTTP endpoint types
export interface HandshakeRequest {
  fromNode: string;
  toNode: string;
  data: any;
}

export interface HandshakeResponse {
  success: boolean;
  data?: any;
  error?: string;
}

export interface SecureMessageRequest {
  fromNode: string;
  toNode: string;
  message: SecureMessage;
}

export interface BroadcastRequest {
  fromNode: string;
  message: Buffer;
  visitedNodes?: string[];
}
