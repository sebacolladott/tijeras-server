import "dotenv/config";

// ---------- Core ----------
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

// ---------- Database ----------
import { PrismaClient } from "@prisma/client";

// ---------- Auth / Seguridad ----------
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";

// ---------- Email ----------
import nodemailer from "nodemailer";

// ---------- Archivos ----------
import fs from "fs";
import path from "path";
import multer from "multer";

const app = express();
const prisma = new PrismaClient();

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const COOKIE = process.env.COOKIE_NAME || "token";

// ---------- Static uploads ----------
const uploadDir = path.join(process.cwd(), "uploads");

// 🧩 crea la carpeta si no existe
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log("📁 Carpeta 'uploads' creada automáticamente");
}

// ✅ Servir archivos solo a usuarios autenticados
app.use(
  "/uploads",
  requireAuth, // 🔒 exige JWT válido (cookie)
  express.static(uploadDir)
);

// ---------- Middlewares ----------
app.use(
  cors({ origin: ORIGIN.split(",").map((o) => o.trim()), credentials: true })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.disable("x-powered-by");
app.use((req, res, next) => {
  console.log(req.method, req.url, req.headers["content-type"]);
  next();
});

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
  service: "gmail",
  auth: {
    user: "sebastiancolladott@gmail.com",
    pass: "xlduralhusiuvorn",
  },
});

async function sendResetEmail(to, token) {
  const resetLink = `https://tijeras.imeatara.com/reset?token=${token}`;

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

// ---------- Estadísticas ----------
app.get("/api/stats", requireAuth, async (req, res) => {
  try {
    const [
      totalCuts,
      totalClients,
      totalBarbers,
      totalPhotos,
      latestCuts,
      cutsByBarber,
      cutsByClient,
      cutsRawDates,
      topStyles,
      activeClients,
      activeBarbers,
      recentUsers,
    ] = await Promise.all([
      prisma.cut.count().catch(() => 0),
      prisma.client.count().catch(() => 0),
      prisma.barber.count().catch(() => 0),
      prisma.cutPhoto.count().catch(() => 0),

      prisma.cut
        .findMany({
          orderBy: { createdAt: "desc" },
          take: 5,
          include: {
            client: { select: { name: true } },
            barber: { select: { name: true } },
          },
        })
        .catch(() => []),

      prisma.barber
        .findMany({
          select: { id: true, name: true, _count: { select: { cuts: true } } },
          orderBy: { name: "asc" },
        })
        .catch(() => []),

      prisma.client
        .findMany({
          select: { id: true, name: true, _count: { select: { cuts: true } } },
          orderBy: { cuts: { _count: "desc" } },
          take: 5,
        })
        .catch(() => []),

      prisma.cut
        .findMany({
          select: { createdAt: true },
        })
        .then((rows) => rows.filter((r) => !!r.createdAt))
        .catch(() => []),

      prisma.cut
        .findMany({
          select: { style: true },
        })
        .then((rows) => {
          const counter = {};
          for (const r of rows) {
            if (!r.style) continue;
            const key = r.style.trim().toLowerCase();
            counter[key] = (counter[key] || 0) + 1;
          }
          return Object.entries(counter)
            .map(([style, total]) => ({
              style: style.charAt(0).toUpperCase() + style.slice(1),
              total,
            }))
            .sort((a, b) => b.total - a.total)
            .slice(0, 5);
        })
        .catch(() => []),

      prisma.cut
        .groupBy({
          by: ["clientId"],
          _count: { _all: true },
          where: {
            createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
          },
        })
        .catch(() => []),

      prisma.cut
        .groupBy({
          by: ["barberId"],
          _count: { _all: true },
          where: {
            createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
          },
        })
        .catch(() => []),

      prisma.user
        .findMany({
          orderBy: { createdAt: "desc" },
          take: 5,
          select: { id: true, email: true, role: true, createdAt: true },
        })
        .catch(() => []),
    ]);

    // 📊 Agrupar cortes por mes (usando createdAt)
    const monthly = {};
    for (const c of cutsRawDates) {
      if (!c.createdAt) continue;
      const key = new Date(c.createdAt).toISOString().slice(0, 7);
      monthly[key] = (monthly[key] || 0) + 1;
    }

    const activeClientsData = await Promise.all(
      activeClients.map(async (c) => {
        const client = await prisma.client
          .findUnique({
            where: { id: c.clientId },
            select: { name: true },
          })
          .catch(() => null);
        return {
          client: client?.name || "Desconocido",
          total: c._count._all,
        };
      })
    );

    const activeBarbersData = await Promise.all(
      activeBarbers.map(async (b) => {
        const barber = await prisma.barber
          .findUnique({
            where: { id: b.barberId },
            select: { name: true },
          })
          .catch(() => null);
        return {
          barber: barber?.name || "Desconocido",
          total: b._count._all,
        };
      })
    );

    res.json({
      totals: {
        cuts: totalCuts,
        clients: totalClients,
        barbers: totalBarbers,
        photos: totalPhotos,
      },
      latestCuts,
      ranking: {
        byBarber: cutsByBarber.map((b) => ({
          barber: b.name,
          totalCuts: b._count.cuts,
        })),
        byClient: cutsByClient.map((c) => ({
          client: c.name,
          totalCuts: c._count.cuts,
        })),
        topStyles: topStyles.map((s) => ({
          style: s.style || "Sin estilo",
          total: s.total || 0,
        })),
      },
      activity: {
        monthlyCuts: Object.entries(monthly).map(([month, total]) => ({
          month,
          total,
        })),
        activeClients: activeClientsData,
        activeBarbers: activeBarbersData,
      },
      recent: { users: recentUsers },
    });
  } catch (e) {
    console.error("Error en /api/stats:", e);
    res.status(500).json({ error: "Error al obtener estadísticas" });
  }
});

// ---------- Barbers ----------
app.get("/api/barbers", requireAuth, async (req, res) => {
  const { skip, take, page, limit } = getPagination(req);

  const q = (req.query.q || "").trim();

  // 🧭 Campos válidos para ordenar
  const sortBy = ["name", "bio", "createdAt", "updatedAt"].includes(
    req.query.sortBy
  )
    ? req.query.sortBy
    : "name";

  const order = req.query.order === "desc" ? "desc" : "asc";

  // 🎯 Filtros dinámicos
  const where = q
    ? {
        OR: [{ name: { contains: q } }, { bio: { contains: q } }],
      }
    : {};

  try {
    const [barbers, total] = await Promise.all([
      prisma.barber.findMany({
        where,
        skip,
        take,
        orderBy: { [sortBy]: order },
        include: {
          _count: { select: { cuts: true } }, // 💈 total de cortes por barbero
        },
      }),
      prisma.barber.count({ where }),
    ]);

    res.json({
      data: barbers,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    console.error("Error al obtener barberos:", err);
    res.status(500).json({ error: "Error al obtener barberos" });
  }
});

app.get("/api/barbers/:id", requireAuth, async (req, res) => {
  try {
    const barber = await prisma.barber.findUnique({
      where: { id: req.params.id },
      include: {
        cuts: {
          include: { client: true, photos: true },
          orderBy: { createdAt: "desc" },
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
  const { skip, take, page, limit } = getPagination(req);

  const q = (req.query.q || "").trim();
  const barberId = req.query.barberId
    ? String(req.query.barberId).trim()
    : null;

  // 🧭 Campos válidos para ordenar
  const sortBy = ["name", "phone", "notes", "createdAt", "updatedAt"].includes(
    req.query.sortBy
  )
    ? req.query.sortBy
    : "createdAt";

  const order = req.query.order === "asc" ? "asc" : "desc";

  // 🎯 Filtros dinámicos
  const where = {
    ...(barberId ? { cuts: { some: { barberId } } } : {}),
    ...(q
      ? {
          OR: [
            { name: { contains: q } },
            { phone: { contains: q } },
            { notes: { contains: q } },
          ],
        }
      : {}),
  };

  try {
    const [clients, total] = await Promise.all([
      prisma.client.findMany({
        where,
        skip,
        take,
        orderBy: { [sortBy]: order },
        include: { cuts: true }, // 🧩 opcional, coherente con /cuts
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
  } catch (err) {
    console.error("Error al obtener clientes:", err);
    res.status(500).json({ error: "Error al obtener clientes" });
  }
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

// 📂 Carpeta donde se guardan las fotos
const cutsDir = path.join(uploadDir, "cuts");
fs.mkdirSync(cutsDir, { recursive: true });

// 🧩 Configuración de almacenamiento físico con multer
const storage = multer.diskStorage({
  destination: cutsDir,
  filename: (_, file, cb) => {
    const unique = `${Date.now()}-${file.originalname.replace(/\s+/g, "_")}`;
    cb(null, unique);
  },
});

// Filtro para aceptar solo imágenes
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Solo se permiten imágenes"), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB por archivo
    files: 3,
  },
});

// 📋 Listar cortes con búsqueda, orden y paginación
app.get("/api/cuts", requireAuth, async (req, res) => {
  try {
    const { skip, take, page, limit } = getPagination(req);
    const q = (req.query.q || "").trim();
    const sortBy = ["createdAt", "date", "style"].includes(req.query.sortBy)
      ? req.query.sortBy
      : "createdAt";
    const order = req.query.order === "asc" ? "asc" : "desc";

    const where = q
      ? {
          OR: [
            { style: { contains: q } },
            { notes: { contains: q } },
            { client: { name: { contains: q } } },
            { barber: { name: { contains: q } } },
          ],
        }
      : {};

    const [cuts, total] = await Promise.all([
      prisma.cut.findMany({
        where,
        skip,
        take,
        orderBy: { [sortBy]: order },
        include: {
          client: { select: { id: true, name: true } },
          barber: { select: { id: true, name: true } },
          photos: true,
        },
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
  } catch (e) {
    console.error("Error obteniendo cortes:", e);
    res.status(500).json({ error: "Error al obtener cortes" });
  }
});

// 📍 Obtener detalle de un corte
app.get("/api/cuts/:id", requireAuth, async (req, res) => {
  try {
    const cut = await prisma.cut.findUnique({
      where: { id: req.params.id },
      include: {
        client: { select: { id: true, name: true, phone: true } },
        barber: { select: { id: true, name: true, bio: true } },
        photos: true,
      },
    });

    if (!cut) return res.status(404).json({ error: "Corte no encontrado" });
    res.json(cut);
  } catch (e) {
    console.error("Error obteniendo corte:", e);
    res.status(500).json({ error: "Error al obtener corte" });
  }
});

// 📍 Crear corte con fotos
app.post(
  "/api/cuts",
  requireAuth,
  upload.array("photos", 10),
  async (req, res) => {
    try {
      const { clientId, barberId, style, notes } = req.body;
      if (!clientId || !barberId)
        return res.status(400).json({ error: "IDs requeridos" });

      const photos = (req.files || []).map((file, i) => ({
        path: `/uploads/cuts/${file.filename}`,
        mimeType: file.mimetype || "image/webp",
        position: i,
      }));

      const cut = await prisma.cut.create({
        data: {
          style,
          notes,
          client: { connect: { id: String(clientId).trim() } },
          barber: { connect: { id: String(barberId).trim() } },
          photos: { create: photos },
        },
        include: { client: true, barber: true, photos: true },
      });

      res.status(201).json(cut);
    } catch (e) {
      console.error("Error creando corte:", e);
      res.status(500).json({ error: "Error creando corte" });
    }
  }
);

// 📍 Actualizar corte y fotos
app.put(
  "/api/cuts/:id",
  requireAuth,
  upload.array("photos", 3),
  async (req, res) => {
    try {
      const id = req.params.id;
      const { clientId, barberId, style, notes, keep = [] } = req.body;

      const existing = await prisma.cut.findUnique({
        where: { id },
        include: { photos: true },
      });

      if (!existing) return res.status(404).json({ error: "No encontrado" });

      // 1️⃣ Actualiza datos básicos
      await prisma.cut.update({
        where: { id },
        data: { clientId, barberId, style, notes },
      });

      // 2️⃣ Elimina fotos que no se mantienen
      const toDelete = existing.photos.filter((p) => !keep.includes(p.id));
      if (toDelete.length) {
        for (const photo of toDelete) {
          const filePath = path.join(
            process.cwd(),
            photo.path.replace(/^\//, "")
          );

          if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        }
        await prisma.cutPhoto.deleteMany({
          where: { id: { in: toDelete.map((p) => p.id) } },
        });
      }

      // 3️⃣ Agrega nuevas fotos
      const photos = (req.files || []).map((file, i) => ({
        cutId: id,
        path: `/uploads/cuts/${file.filename}`,
        mimeType: file.mimetype || "image/webp",
        position: existing.photos.length + i,
      }));

      if (photos.length) await prisma.cutPhoto.createMany({ data: photos });

      res.json({ ok: true });
    } catch (e) {
      console.error("Error al actualizar corte:", e);
      res.status(500).json({ error: "Error al actualizar corte" });
    }
  }
);

// 📍 Eliminar corte (y sus fotos físicas)
app.delete("/api/cuts/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const photos = await prisma.cutPhoto.findMany({ where: { cutId: id } });
    for (const p of photos) {
      const filePath = path.join(process.cwd(), p.path);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }

    await prisma.cutPhoto.deleteMany({ where: { cutId: id } });
    await prisma.cut.delete({ where: { id } });

    res.json({ ok: true });
  } catch (e) {
    console.error("Error al eliminar corte:", e);
    res.status(500).json({ error: "Error al eliminar corte" });
  }
});

// 📍 Eliminar una foto individual
app.delete("/api/cuts/:id/photos/:photoId", requireAuth, async (req, res) => {
  try {
    const { id, photoId } = req.params;

    const photo = await prisma.cutPhoto.findUnique({ where: { id: photoId } });
    if (!photo) return res.status(404).json({ error: "Foto no encontrada" });
    if (photo.cutId !== id)
      return res.status(400).json({ error: "Foto no pertenece al corte" });

    const filePath = path.join(process.cwd(), photo.path);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    await prisma.cutPhoto.delete({ where: { id: photoId } });
    res.json({ ok: true });
  } catch (e) {
    console.error("Error al eliminar foto:", e);
    res.status(500).json({ error: "Error al eliminar foto" });
  }
});

// 📸 Servir foto directamente desde disco
app.get("/api/cuts/:id/photos/:photoId/data", requireAuth, async (req, res) => {
  try {
    const { id, photoId } = req.params;

    const photo = await prisma.cutPhoto.findUnique({
      where: { id: photoId },
    });

    if (!photo) return res.status(404).json({ error: "Foto no encontrada" });
    if (photo.cutId !== id)
      return res.status(400).json({ error: "Foto no pertenece al corte" });

    const filePath = path.join(process.cwd(), photo.path);
    if (!fs.existsSync(filePath))
      return res.status(404).json({ error: "Archivo físico no encontrado" });

    res.type(photo.mimeType || "image/webp");
    fs.createReadStream(filePath).pipe(res);
  } catch (e) {
    console.error("Error al servir foto:", e);
    res.status(500).json({ error: "Error al cargar la foto" });
  }
});

// ---------- Root ----------
app.get("/", (req, res) => {
  res.send("🚀 API activa y funcionando correctamente");
});

// ---------- Start ----------
app.listen(PORT, () => console.log(`✅ API lista en http://localhost:${PORT}`));
