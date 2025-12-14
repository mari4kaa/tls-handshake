export function bufferToBase64(buffer: Buffer): string {
  return buffer.toString("base64");
}

export function base64ToBuffer(base64: string): Buffer {
  return Buffer.from(base64, "base64");
}

export function serializeBuffers(obj: any): any {
  if (Buffer.isBuffer(obj)) {
    return { type: "Buffer", data: bufferToBase64(obj) };
  }

  if (Array.isArray(obj)) {
    return obj.map(serializeBuffers);
  }

  if (obj && typeof obj === "object") {
    const result: any = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        result[key] = serializeBuffers(obj[key]);
      }
    }
    return result;
  }

  return obj;
}

export function deserializeBuffers(obj: any): any {
  if (obj && typeof obj === "object" && obj.type === "Buffer") {
    if (typeof obj.data === "string") {
      return base64ToBuffer(obj.data);
    } else if (Array.isArray(obj.data)) {
      return Buffer.from(obj.data);
    }
  }

  if (Array.isArray(obj)) {
    return obj.map(deserializeBuffers);
  }

  if (obj && typeof obj === "object") {
    const result: any = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        result[key] = deserializeBuffers(obj[key]);
      }
    }
    return result;
  }

  return obj;
}
