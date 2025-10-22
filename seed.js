// prisma/seed.js
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  const email = process.env.ADMIN_EMAIL || "admin@tijeras.ar";
  const password = process.env.ADMIN_PASS || "TJ123456";

  const passwordHash = await bcrypt.hash(password, 10);

  const admin = await prisma.user.upsert({
    where: { email },
    update: { role: "ADMIN" },
    create: { email, passwordHash, role: "ADMIN" },
  });

  console.log("✅ Usuario admin creado o actualizado:");
  console.log(`📧 Email: ${admin.email}`);
  console.log(`🔑 Password: ${password}`);
  console.log("⚠️ Recordá cambiar la contraseña al primer inicio de sesión.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
