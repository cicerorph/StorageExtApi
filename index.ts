import { Hono } from "hono";
import { cors } from "hono/cors";
import { MongoClient, Db } from "mongodb";
import { configure, getConsoleSink, getLogger } from "@logtape/logtape";
import { prettyFormatter } from "@logtape/pretty";
import { honoLogger } from "@logtape/hono";
import { S3Client } from "bun";

await configure({
  sinks: { 
    console: getConsoleSink({ formatter: prettyFormatter }),
    file: getFileSink("app.log"),
  },
  loggers: [
    { category: ["hono"], sinks: ["console", "file"], lowestLevel: "info" },
    { category: ["logtape", "meta"], sinks: ["console", "file"], lowestLevel: "warning" }
  ],
});

const logger = getLogger("hono");

const app = new Hono();
app.use(honoLogger());

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017";
const DB_NAME = process.env.DB_NAME || "kv_store";
const MAX_VALUE_SIZE = 256 * 1024; // 256KB

let db: Db;
let s3Client: S3Client;

let totalRequests = 0;
const timedOutIPs = new Map<string, number>();

// file headers for detection inside base64 strings 
// I copied these from the original project hehehe
const fileHeaders = [
  [0x42, 0x4d], // .bmp
  [0x53, 0x49, 0x4d, 0x50, 0x4c, 0x45], // .fits
  [0x47, 0x49, 0x46, 0x38], // .gif
  [0x47, 0x4b, 0x53, 0x4d], // .gks
  [0x01, 0xda], // .rgb
  [0xf1, 0x00, 0x40, 0xbb], // .itc
  [0xff, 0xd8, 0xff, 0xe0], // .jpg
  [0x49, 0x49, 0x4e, 0x31], // .nif
  [0x56, 0x49, 0x45, 0x57], // .pm
  [0x89, 0x50, 0x4e, 0x47], // .png
  [0x25, 0x21], // .[e]ps
  [0x59, 0xa6, 0x6a, 0x95], // .ras
  [0x4d, 0x4d, 0x00, 0x2a], // .tif (Motorola)
  [0x49, 0x49, 0x2a, 0x00], // .tif (Intel)
  [0x67, 0x69, 0x6d, 0x70, 0x20, 0x78, 0x63, 0x66, 0x20, 0x76], // .xcf
  [0x23, 0x46, 0x49, 0x47], // .fig
  [0x2f, 0x2a, 0x20, 0x58, 0x50, 0x4d, 0x20, 0x2a, 0x2f], // .xpm
  [0x42, 0x5a], // .bz
  [0x1f, 0x9d], // .Z
  [0x1f, 0x8b], // .gz
  [0x50, 0x4b, 0x03, 0x04], // .zip
  [0x75, 0x73, 0x74, 0x61, 0x72], // .tar
  [0x4d, 0x5a], // .exe
  [0x7f, 0x45, 0x4c, 0x46], // .elf
  [0xca, 0xfe, 0xba, 0xbe], // .class
  [0x00, 0x00, 0x01, 0x00], // .ico
  [0x52, 0x49, 0x46, 0x46], // .avi
  [0x46, 0x57, 0x53], // .swf
  [0x46, 0x4c, 0x56], // .flv
  [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x6d, 0x70, 0x34, 0x32], // .mp4
  [0x6d, 0x6f, 0x6f, 0x76], // .mov
  [0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf], // .wmv/.wma
  [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], // .msi/.doc/.msg
  [0x4c, 0x01], // .obj
  [0x4d, 0x5a], // .dll
  [0x4d, 0x53, 0x43, 0x46], // .cab
  [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00], // .rar
  [0x25, 0x50, 0x44, 0x46], // .pdf
  [0x50, 0x4b, 0x03, 0x04], // .docx
  [0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x08, 0x00, 0x08, 0x00], // .jar
  [0x78, 0x9c], // .zlib
];

const b64DataRegex = /^data:.+;base64,/;

function includesFile(input: string): boolean {
  // Remove the data URI prefix if present
  const b64String = input.replace(b64DataRegex, "");

  try {
    // Attempt to base64 decode string
    const decoded = Buffer.from(b64String, "base64");

    // Check against file headers
    for (const header of fileHeaders) {
      if (decoded.length >= header.length) {
        const matches = header.every((byte, i) => decoded[i] === byte);
        if (matches) {
          logger.warn(`file detected with header: ${header.map(b => b.toString(16)).join(" ")}`);
          return true;
        }
      }
    }
  } catch (err) {
    return false;
  }

  return false;
}

function getClientIP(c: any): string {
  // check cloudflare (used when its deployed on CF or behind a CF proxy)
  const cfIP = c.req.header("cf-connecting-ip");
  if (cfIP) return cfIP;

  const xForwardedFor = c.req.header("x-forwarded-for");
  if (xForwardedFor) {
    return xForwardedFor.split(",")[0].trim();
  }

  const xRealIP = c.req.header("x-real-ip");
  if (xRealIP) return xRealIP;

  return "unknown";
}

function generateS3Key(project: string, key: string): string {
  if (!project) {
    return `global/${key}`;
  }
  return `${project}/${key}`;
}

async function uploadToS3(key: string, value: string): Promise<void> {
  await s3Client.write(key, value);
}

async function downloadFromS3(key: string): Promise<string> {
  const s3file = s3Client.file(key);
  return await s3file.text();
}

async function deleteFromS3(key: string): Promise<void> {
  await s3Client.delete(key);
}

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowHeaders: ["*"],
  credentials: true,
  maxAge: 300,
}));

app.use("*", async (c, next) => {
  totalRequests++;
  await next();
});

app.get("/", (c) => {
  return c.json({
    online: true,
    reqCount: totalRequests,
  });
});

app.get("/get", async (c) => {
  const key = c.req.query("key");
  if (!key) {
    return c.json({ error: "NoKeySpecified" }, 400);
  }

  const project = c.req.query("project") || "";

  try {
    const collection = db.collection("kv");
    const doc = await collection.findOne({ project, key });

    if (!doc) {
      return c.json({ error: "KeyFileNonExistent" }, 400);
    }

    const s3Key = generateS3Key(project, key);
    const value = await downloadFromS3(s3Key);

    return c.text(value);
  } catch (err) {
    logger.error(err?.toString() || "unknown error");
    return c.json({ error: "InternalServerError" }, 500);
  }
});

app.post("/set", async (c) => {
  const ip = getClientIP(c);

  const timedOutUntil = timedOutIPs.get(ip);
  if (timedOutUntil && timedOutUntil > Date.now()) {
    return c.json({ error: "TimedOut" }, 403);
  }

  const key = c.req.query("key");
  if (!key) {
    return c.json({ error: "NoKeySpecified" }, 400);
  }

  const project = c.req.query("project") || "";

  try {
    const body = await c.req.json();
    const val = body.value;

    if (!val) {
      return c.json({ error: "InvalidBody" }, 400);
    }

    const valueSize = Buffer.byteLength(val, "utf8");
    if (valueSize > MAX_VALUE_SIZE) {
      return c.json({ error: "ValueTooLarge", maxSize: MAX_VALUE_SIZE }, 413);
    }

    if (includesFile(val)) {
      timedOutIPs.set(ip, Date.now() + 10000); // 10s
      return c.json({ error: "IncludesFile" }, 403);
    }

    const s3Key = generateS3Key(project, key);
    await uploadToS3(s3Key, val);

    const collection = db.collection("kv");
    await collection.updateOne(
      { project, key },
      { 
        $set: { 
          project, 
          key, 
          s3_key: s3Key,
          size: valueSize,
          set_by: ip,
          updated_at: new Date()
        },
        $setOnInsert: {
          created_at: new Date()
        }
      },
      { upsert: true }
    );

    return c.json({ success: true });
  } catch (err) {
    logger.error(err?.toString() || "unknown error");
    return c.json({ error: "InternalServerError" }, 500);
  }
});

app.delete("/delete", async (c) => {
  const key = c.req.query("key");
  if (!key) {
    return c.json({ error: "NoKeySpecified" }, 400);
  }

  const project = c.req.query("project") || "";

  try {
    const collection = db.collection("kv");
    const doc = await collection.findOne({ project, key });

    if (doc) {
      const s3Key = generateS3Key(project, key);
      await deleteFromS3(s3Key);
    }

    await collection.deleteOne({ project, key });

    return c.json({ success: true });
  } catch (err) {
    logger.error(err?.toString() || "unknown error");
    return c.json({ error: "InternalServerError" }, 500);
  }
});

async function init() {
  try {
    s3Client = new S3Client({
      accessKeyId: process.env.S3_ACCESS_KEY_ID,
      secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
      bucket: process.env.S3_BUCKET,
      region: process.env.S3_REGION,
      endpoint: process.env.S3_ENDPOINT,
    });
    logger.info("initialized the s3 client");

    const client = new MongoClient(MONGO_URI);
    await client.connect();
    logger.info("connected to db");

    db = client.db(DB_NAME);

    await db.collection("kv").createIndex({ project: 1, key: 1 }, { unique: true });

    const port = parseInt(process.env.PORT || "3000");
    logger.info(`server starting on port ${port}`);

    Bun.serve({
      port,
      fetch: app.fetch,
    });

    logger.info(`serving server on :${port}`);
  } catch (err) {
    logger.error(`failed to init: ${err?.toString() || "unknown error"}`);
    process.exit(1);
  }
}

init();
