import { Transform, TransformCallback } from "node:stream";

/**
 * Sliding-Window SSE (Server-Sent Events) DLP Transform Stream.
 * Maintains a trailing lookbehind buffer to catch secrets split across chunk boundaries.
 */
export class SSEDlpTransformStream extends Transform {
  private buffer: string = "";
  private lookbehindSize: number;
  private secretRegex: RegExp;

  constructor(secretRegex: RegExp = /AKIA[0-9A-Z]{16}/g, lookbehindSize: number = 64) {
    super();
    this.secretRegex = secretRegex;
    this.lookbehindSize = lookbehindSize;
  }

  _transform(chunk: Buffer | string, _encoding: BufferEncoding, callback: TransformCallback): void {
    try {
      const chunkStr = chunk.toString();
      this.buffer += chunkStr;

      // If buffer gets large, process up to the safe processing boundary,
      // retaining the lookbehind window for potential split secrets.
      if (this.buffer.length > this.lookbehindSize * 2) {
        const splitIndex = this.buffer.length - this.lookbehindSize;
        let safePart = this.buffer.slice(0, splitIndex);
        this.buffer = this.buffer.slice(splitIndex);

        // Apply DLP redaction on the safe part
        safePart = safePart.replace(this.secretRegex, "[REDACTED_SECRET]");
        this.push(safePart);
      }

      callback();
    } catch (err: any) {
      callback(err);
    }
  }

  _flush(callback: TransformCallback): void {
    try {
      if (this.buffer.length > 0) {
        let finalPart = this.buffer.replace(this.secretRegex, "[REDACTED_SECRET]");
        this.push(finalPart);
        this.buffer = "";
      }
      callback();
    } catch (err: any) {
      callback(err);
    }
  }
}
