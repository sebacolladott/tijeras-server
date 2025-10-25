import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import nodemailer from "nodemailer";

const app = express();
const prisma = new PrismaClient();

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const COOKIE = process.env.COOKIE_NAME || "token";

// ---------- Middlewares ----------
app.use(
  cors({ origin: ORIGIN.split(",").map((o) => o.trim()), credentials: true })
);
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.disable("x-powered-by");

// ---------- Helpers ----------
const signToken = (payload) =>
  jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

const setCookie = (res, token) =>
  res.cookie(COOKIE, token, {
    httpOnly: true,
    path: "/",
    sameSite: "none",
    secure: true,
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

const requireAuth = (req, res, next) => {
  try {
    const token = req.cookies[COOKIE];
    if (!token) throw new Error();
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "No autenticado" });
  }
};

// 🔒 Solo admin
const requireAdmin = (req, res, next) => {
  if (req.user?.role !== "ADMIN")
    return res.status(403).json({ error: "Acceso denegado" });
  next();
};

// 🔢 Helper para paginado
const getPagination = (req) => {
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const limit = Math.min(parseInt(req.query.limit) || 10, 100);
  const skip = (page - 1) * limit;
  return { skip, take: limit, page, limit };
};

// ---------- Auth ----------
app.post("/api/auth/register", requireAuth, requireAdmin, async (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "Datos inválidos" });

  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) return res.status(409).json({ error: "Email ya registrado" });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      role: role === "ADMIN" ? "ADMIN" : "USER",
    },
  });

  res.status(201).json({ id: user.id, email: user.email, role: user.role });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "Datos inválidos" });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "Credenciales inválidas" });

  setCookie(res, signToken({ id: user.id, email, role: user.role }));
  res.json({ id: user.id, email, role: user.role });
});

app.post("/api/auth/logout", requireAuth, (req, res) => {
  res.clearCookie(COOKIE);
  res.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    select: { id: true, email: true, role: true },
  });
  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
  res.json(user);
});

// ---------- Cambio de contraseña ----------
app.post("/api/auth/change-password", requireAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword)
    return res.status(400).json({ error: "Datos inválidos" });

  const user = await prisma.user.findUnique({ where: { id: req.user.id } });
  if (!user || !(await bcrypt.compare(oldPassword, user.passwordHash)))
    return res.status(401).json({ error: "Contraseña actual incorrecta" });

  const passwordHash = await bcrypt.hash(newPassword, 10);
  await prisma.user.update({ where: { id: user.id }, data: { passwordHash } });
  res.json({ ok: true });
});

// ---------- Recuperación de contraseña ----------
const transporter = nodemailer.createTransport({
  service: "smtp.office365.com",
  port: 587,
  secure: false,
  auth: {
    user: "sebastiancolladott@outlook.com",
    pass: "xhvycclyxgfrfyhl",
  },
});

async function sendResetEmail(to, token) {
  const resetLink = `https://tijeras.imeatara.com/reset-password?token=${token}`;

  await transporter.sendMail({
    from: "Tijeras <tu_correo@outlook.com>",
    to,
    subject: "Recuperación de contraseña",
    html: `
      <div style="font-family: sans-serif; max-width: 400px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 8px;">
        <h2 style="text-align:center; margin-bottom: 20px;">Restablecer contraseña</h2>
        
        <p>Haz clic en el botón para crear una nueva contraseña:</p>

        <a href="${resetLink}" 
           style="display:inline-block; background:#000; color:#fff; padding:10px 16px; border-radius:6px; text-decoration:none; margin:16px 0; text-align:center;">
           Restablecer contraseña
        </a>

        <p>Si no solicitaste esto, simplemente ignora este mensaje.</p>

        <small style="opacity:0.6;">Si el botón no funciona, copia y pega este enlace:</small>
        <br />
        <a href="${resetLink}" style="opacity:0.8; font-size: 13px;">${resetLink}</a>
      </div>
    `,
  });
}

const resetTokens = new Map();

app.post("/api/auth/request-reset", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "Email requerido" });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(404).json({ error: "No encontrado" });

  const token = crypto.randomBytes(20).toString("hex");
  resetTokens.set(token, user.id);

  // ⬇️ ENVÍA EL MAIL
  try {
    await sendResetEmail(email, token);
  } catch (err) {
    console.log("Error enviando mail:", err);
    return res.status(500).json({ error: "No se pudo enviar el correo" });
  }

  res.json({ ok: true });
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { token, newPassword } = req.body || {};
  const userId = resetTokens.get(token);
  if (!userId)
    return res.status(400).json({ error: "Token inválido o expirado" });

  const passwordHash = await bcrypt.hash(newPassword, 10);
  await prisma.user.update({ where: { id: userId }, data: { passwordHash } });
  resetTokens.delete(token);
  res.json({ ok: true });
});

// ---------- Usuarios ----------
app.get("/api/users", requireAuth, requireAdmin, async (req, res) => {
  const { skip, take, page, limit } = getPagination(req);

  const [users, total] = await Promise.all([
    prisma.user.findMany({
      skip,
      take,
      orderBy: { createdAt: "desc" },
      select: { id: true, email: true, role: true, createdAt: true },
    }),
    prisma.user.count(),
  ]);

  res.json({
    data: users,
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  });
});

app.put("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
  const { email, role } = req.body || {};
  if (!email?.trim()) return res.status(400).json({ error: "Email requerido" });

  try {
    const exists = await prisma.user.findFirst({
      where: { email: email.trim(), NOT: { id: req.params.id } },
    });
    if (exists)
      return res
        .status(409)
        .json({ error: "Email ya registrado por otro usuario" });

    const updated = await prisma.user.update({
      where: { id: req.params.id },
      data: {
        email: email.trim(),
        role: role === "ADMIN" ? "ADMIN" : "USER",
      },
      select: { id: true, email: true, role: true, createdAt: true },
    });
    res.json(updated);
  } catch {
    res.status(404).json({ error: "Usuario no encontrado" });
  }
});

app.delete("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    if (id === req.user.id)
      return res.status(400).json({ error: "No podés eliminarte a vos mismo" });

    await prisma.user.delete({ where: { id } });
    res.json({ ok: true });
  } catch {
    res.status(404).json({ error: "Usuario no encontrado" });
  }
});

// ---------- Barbers ----------
app.get("/api/barbers", requireAuth, async (req, res) => {
  const q = (req.query.q || "").trim();
  const { skip, take, page, limit } = getPagination(req);

  const [barbers, total] = await Promise.all([
    prisma.barber.findMany({
      where: q ? { name: { contains: q, mode: "insensitive" } } : undefined,
      skip,
      take,
      orderBy: { name: "asc" },
      include: { _count: { select: { cuts: true } } },
    }),
    prisma.barber.count({
      where: q ? { name: { contains: q, mode: "insensitive" } } : undefined,
    }),
  ]);

  res.json({
    data: barbers,
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  });
});

app.get("/api/barbers/:id", requireAuth, async (req, res) => {
  try {
    const barber = await prisma.barber.findUnique({
      where: { id: req.params.id },
      include: {
        cuts: {
          include: { client: true, photos: true },
          orderBy: { date: "desc" },
        },
      },
    });

    if (!barber)
      return res.status(404).json({ error: "Barbero no encontrado" });
    res.json(barber);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al obtener el barbero" });
  }
});

app.post("/api/barbers", requireAuth, async (req, res) => {
  const { name, bio } = req.body || {};
  if (!name) return res.status(400).json({ error: "Nombre requerido" });
  const barber = await prisma.barber.create({ data: { name, bio } });
  res.status(201).json(barber);
});

app.put("/api/barbers/:id", requireAuth, async (req, res) => {
  const { name, bio } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "Nombre requerido" });
  try {
    const updated = await prisma.barber.update({
      where: { id: req.params.id },
      data: { name: name.trim(), bio: bio || null },
    });
    res.json(updated);
  } catch {
    res.status(404).json({ error: "No encontrado" });
  }
});

app.delete("/api/barbers/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const cuts = await prisma.cut.findMany({ where: { barberId: id } });
    const cutIds = cuts.map((c) => c.id);

    if (cutIds.length) {
      await prisma.cutPhoto.deleteMany({ where: { cutId: { in: cutIds } } });
      await prisma.cut.deleteMany({ where: { id: { in: cutIds } } });
    }

    await prisma.barber.delete({ where: { id } });
    res.json({ ok: true });
  } catch {
    res.status(404).json({ error: "No encontrado" });
  }
});

// ---------- Clients ----------
app.get("/api/clients", requireAuth, async (req, res) => {
  const q = (req.query.q || "").trim();
  const { skip, take, page, limit } = getPagination(req);

  const where = q
    ? {
        OR: [
          { name: { contains: q, mode: "insensitive" } },
          { phone: { contains: q, mode: "insensitive" } },
          { notes: { contains: q, mode: "insensitive" } },
        ],
      }
    : undefined;

  const [clients, total] = await Promise.all([
    prisma.client.findMany({
      where,
      skip,
      take,
      orderBy: { createdAt: "desc" },
    }),
    prisma.client.count({ where }),
  ]);

  res.json({
    data: clients,
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  });
});

app.get("/api/clients/:id", requireAuth, async (req, res) => {
  try {
    const client = await prisma.client.findUnique({
      where: { id: req.params.id },
      include: { cuts: { include: { barber: true, photos: true } } },
    });

    if (!client)
      return res.status(404).json({ error: "Cliente no encontrado" });
    res.json(client);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al obtener el cliente" });
  }
});

app.post("/api/clients", requireAuth, async (req, res) => {
  const { name, phone, notes } = req.body || {};
  if (!name) return res.status(400).json({ error: "Nombre requerido" });
  const client = await prisma.client.create({ data: { name, phone, notes } });
  res.status(201).json(client);
});

app.put("/api/clients/:id", requireAuth, async (req, res) => {
  const { name, phone, notes } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "Nombre requerido" });
  try {
    const updated = await prisma.client.update({
      where: { id: req.params.id },
      data: { name: name.trim(), phone: phone || null, notes: notes || null },
    });
    res.json(updated);
  } catch {
    res.status(404).json({ error: "No encontrado" });
  }
});

app.delete("/api/clients/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const cuts = await prisma.cut.findMany({ where: { clientId: id } });
    const cutIds = cuts.map((c) => c.id);

    if (cutIds.length) {
      await prisma.cutPhoto.deleteMany({ where: { cutId: { in: cutIds } } });
      await prisma.cut.deleteMany({ where: { id: { in: cutIds } } });
    }

    await prisma.client.delete({ where: { id } });
    res.json({ ok: true });
  } catch {
    res.status(404).json({ error: "No encontrado" });
  }
});

// ---------- Cuts ----------
const normalizeBase64 = (s) =>
  s?.includes(",") ? s.split(",").pop() : s || "";

const toPhotoCreates = (arr = []) =>
  arr
    .map((p, i) => {
      const data = normalizeBase64(p.base64 || p.data);
      return data
        ? {
            data: Buffer.from(data, "base64"),
            mimeType: p.mimeType || "image/webp",
            position: p.position ?? i,
          }
        : null;
    })
    .filter(Boolean)
    .slice(0, 10);

app.post("/api/cuts", requireAuth, async (req, res) => {
  try {
    const {
      clientId,
      barberId,
      date,
      style,
      notes,
      photos = [],
    } = req.body || {};
    if (!clientId || !barberId)
      return res.status(400).json({ error: "IDs requeridos" });

    const cut = await prisma.cut.create({
      data: {
        style,
        notes,
        date: date ? new Date(date) : undefined,
        client: { connect: { id: String(clientId).trim() } },
        barber: { connect: { id: String(barberId).trim() } },
        photos: { create: toPhotoCreates(photos) },
      },
      include: { client: true, barber: true, photos: true },
    });
    res.status(201).json(cut);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error creando corte" });
  }
});

app.get("/api/cuts", requireAuth, async (req, res) => {
  const { skip, take, page, limit } = getPagination(req);

  const q = (req.query.q || "").trim();
  const clientId = req.query.clientId
    ? String(req.query.clientId).trim()
    : null;
  const barberId = req.query.barberId
    ? String(req.query.barberId).trim()
    : null;

  // 🧭 Nuevo: campos para ordenar
  const sortBy = req.query.sortBy || "date"; // ej: date | createdAt | style
  const order = req.query.order === "asc" ? "asc" : "desc";

  const where = {
    ...(clientId ? { clientId } : {}),
    ...(barberId ? { barberId } : {}),
    ...(q
      ? {
          OR: [
            { style: { contains: q } },
            { notes: { contains: q } },
            { client: { name: { contains: q } } },
            { barber: { name: { contains: q } } },
          ],
        }
      : {}),
  };

  try {
    const [cuts, total] = await Promise.all([
      prisma.cut.findMany({
        where,
        skip,
        take,
        orderBy: { [sortBy]: order }, // ← dinámico
        include: { client: true, barber: true, photos: true },
      }),
      prisma.cut.count({ where }),
    ]);

    res.json({
      data: cuts,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    console.error("Error al obtener cortes:", err);
    res.status(500).json({ error: "Error al obtener cortes" });
  }
});

app.get("/api/cuts/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const cut = await prisma.cut.findUnique({
      where: { id },
      include: { client: true, barber: true, photos: true },
    });

    if (!cut) return res.status(404).json({ error: "Corte no encontrado" });

    res.json(cut);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al obtener el corte" });
  }
});

app.put("/api/cuts/:id", requireAuth, async (req, res) => {
  try {
    const {
      clientId,
      barberId,
      style,
      notes,
      photos = [],
      keep = [],
    } = req.body || {};
    const id = req.params.id;

    const existing = await prisma.cut.findUnique({
      where: { id },
      include: { photos: true },
    });

    if (!existing) return res.status(404).json({ error: "No encontrado" });

    await prisma.cut.update({
      where: { id },
      data: { clientId, barberId, style, notes },
    });

    const toDelete = existing.photos.filter((p) => !keep.includes(p.id));
    if (toDelete.length) {
      await prisma.cutPhoto.deleteMany({
        where: { id: { in: toDelete.map((p) => p.id) } },
      });
    }

    if (photos.length) {
      await prisma.cutPhoto.createMany({
        data: photos.map((p, i) => ({
          cutId: id,
          mimeType: p.mimeType || "image/webp",
          data: Buffer.from(p.base64, "base64"),
          position: existing.photos.length + i,
        })),
      });
    }

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al actualizar" });
  }
});

app.get("/api/cuts/:id/photos/:photoId/data", requireAuth, async (req, res) => {
  const photo = await prisma.cutPhoto.findUnique({
    where: { id: req.params.photoId },
  });
  if (!photo) return res.sendStatus(404);
  res.set("Content-Type", photo.mimeType).send(Buffer.from(photo.data));
});

app.delete("/api/cuts/:id", requireAuth, async (req, res) => {
  await prisma.cut.delete({ where: { id: req.params.id } }).catch(() => {});
  res.json({ ok: true });
});

// ---------- Root ----------
app.get("/", (req, res) => {
  res.send("🚀 API activa y funcionando correctamente");
});

// ---------- Start ----------
app.listen(PORT, () => console.log(`✅ API lista en http://localhost:${PORT}`));
