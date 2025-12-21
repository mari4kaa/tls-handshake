import { NestFactory } from "@nestjs/core";
import { CaServerModule } from "./ca-server.module";
import { Logger } from "@nestjs/common";

async function bootstrapCAServer() {
  const logger = new Logger("Bootstrap");

  console.log(
    "\n╔════════════════════════════════════════════════════════════╗"
  );
  console.log("║        Certificate Authority Server Starting              ║");
  console.log(
    "╚════════════════════════════════════════════════════════════╝\n"
  );

  const app = await NestFactory.create(CaServerModule, {
    logger: ["log", "error", "warn", "debug"],
  });

  app.enableCors({
    origin: "*",
    methods: "GET,POST",
    credentials: true,
  });

  const CA_PORT = parseInt(process.env.CA_PORT || "9000", 10);

  await app.listen(CA_PORT);

  console.log("\n═══════════════════════════════════════════════════════════");
  logger.log("✓ Certificate Authority Server is RUNNING");
  console.log("═══════════════════════════════════════════════════════════");
  logger.log(`  Port: ${CA_PORT}`);
  logger.log(`  URL: http://localhost:${CA_PORT}`);
  logger.log(`  Role: ROOT CERTIFICATE AUTHORITY`);
  logger.log("");
  logger.log("  Capabilities:");
  logger.log("    ✓ Issue certificates to network nodes");
  logger.log("    ✓ Verify certificate signatures");
  logger.log("    ✓ Revoke compromised certificates");
  logger.log("    ✓ Maintain certificate registry");
  console.log("═══════════════════════════════════════════════════════════");
  logger.log("");
  logger.log("Waiting for certificate requests from network nodes...");
  logger.log("");
}

bootstrapCAServer().catch((err) => {
  console.error("❌ Failed to start CA Server:", err);
  process.exit(1);
});
