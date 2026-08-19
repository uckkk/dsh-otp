// dsh-otp — 一次性密码（DeepSeek Harness）。TOTP/HOTP（RFC 6238/4226）。纯 Node。
import { defineTool } from "@deepseek-ai/dsh-tools";
import { createHmac } from "node:crypto";

const name = "一次性密码";
const inject = ["tools"];

function base32Decode(s) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  s = s.toUpperCase().replace(/[= ]/g, "");
  let bits = "", out = [];
  for (const c of s) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

function hotp(secret, counter, digits = 6) {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", key).update(buf).digest();
  const offset = h[h.length - 1] & 0x0f;
  const code = ((h[offset] & 0x7f) << 24 | h[offset + 1] << 16 | h[offset + 2] << 8 | h[offset + 3]) % 10 ** digits;
  return String(code).padStart(digits, "0");
}

async function apply(ctx, _config) {
  ctx.tools.register(defineTool({
    name: "totp",
    description: "生成 TOTP（RFC 6238，基于时间的一次性密码，6 位）。`secret` 传 base32 密钥（如 Google Authenticator）；`period` 默认 30 秒。",
    parameters: {
      secret: { type: "string", required: true, description: "base32 密钥。" },
      period: { type: "integer", description: "周期秒数，默认 30。" },
    },
    output: { schema: { type: "object", additionalProperties: false, properties: { code: { type: "string", required: true }, remaining: { type: "integer", required: true } } }, render: (_a, v) => [{ type: "text", text: `${v.code}（${v.remaining} 秒后刷新）` }] },
    execute: async (args) => {
      const period = args.period || 30;
      const counter = Math.floor(Date.now() / 1000 / period);
      const remaining = period - (Math.floor(Date.now() / 1000) % period);
      return { code: hotp(args.secret, counter, 6), remaining };
    },
  }));

  ctx.tools.register(defineTool({
    name: "hotp",
    description: "生成 HOTP（RFC 4226，基于计数器的一次性密码）。`secret` 传 base32 密钥；`counter` 传计数器；`digits` 默认 6。",
    parameters: {
      secret: { type: "string", required: true, description: "base32 密钥。" },
      counter: { type: "integer", required: true, description: "计数器。" },
      digits: { type: "integer", description: "位数，默认 6。" },
    },
    output: { schema: { type: "object", additionalProperties: false, properties: { code: { type: "string", required: true } } }, render: (_a, v) => [{ type: "text", text: v.code }] },
    execute: async (args) => ({ code: hotp(args.secret, args.counter, args.digits || 6) }),
  }));
}

export { apply, inject, name };
