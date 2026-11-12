
require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.use(express.static(path.join(__dirname, "public")));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: false }
    : false
});

const sessions = new Map();

function safeEqual(a, b) {
  const first = Buffer.from(String(a || ""));
  const second = Buffer.from(String(b || ""));

  return first.length === second.length &&
    crypto.timingSafeEqual(first, second);
}

function authenticate(req, res, next) {
  const authorization = req.headers.authorization || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : req.headers["x-session-token"];

  if (!token || !sessions.has(token)) {
    return res.status(401).json({
      error: "Sessão inválida ou expirada."
    });
  }

  next();
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS contacts (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT DEFAULT '',
      email TEXT DEFAULT '',
      status TEXT DEFAULT 'Novo',
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sales (
      id BIGSERIAL PRIMARY KEY,
      customer_name TEXT NOT NULL,
      product TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'Pendente',
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  console.log("Banco de dados inicializado.");
}

// Saúde do sistema
app.get("/health", async (req, res) => {
  let database = false;

  try {
    await pool.query("SELECT 1");
    database = true;
  } catch (error) {
    console.error("Erro no banco:", error.message);
  }

  res.json({
    status: "online",
    database
  });
});

// Login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};

  const validUser = safeEqual(
    username,
    process.env.ADMIN_USER || "admin"
  );

  const validPassword = safeEqual(
    password,
    process.env.ADMIN_PASSWORD
  );

  if (!validUser || !validPassword) {
    return res.status(401).json({
      error: "Usuário ou senha incorretos."
    });
  }

  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, true);

  res.json({
    success: true,
    token
  });
});

// Logout
app.post("/api/logout", authenticate, (req, res) => {
  const authorization = req.headers.authorization || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : req.headers["x-session-token"];

  sessions.delete(token);

  res.json({ success: true });
});

// LISTAR CLIENTES
app.get("/api/contacts", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM contacts ORDER BY created_at DESC"
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Erro ao buscar contatos."
    });
  }
});

// CRIAR CLIENTE
app.post("/api/contacts", authenticate, async (req, res) => {
  try {
    const { name, phone, email, status, notes } = req.body || {};

    if (!name || !String(name).trim()) {
      return res.status(400).json({
        error: "O nome é obrigatório."
      });
    }

    const result = await pool.query(
      `INSERT INTO contacts
       (name, phone, email, status, notes)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        String(name).trim(),
        phone || "",
        email || "",
        status || "Novo",
        notes || ""
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Erro ao criar contato."
    });
  }
});

// ATUALIZAR CLIENTE
app.put("/api/contacts/:id", authenticate, async (req, res) => {
  try {
    const { name, phone, email, status, notes } = req.body || {};

    const result = await pool.query(
      `UPDATE contacts
       SET name = $1,
           phone = $2,
           email = $3,
           status = $4,
           notes = $5,
           updated_at = NOW()
       WHERE id = $6
       RETURNING *`,
      [
        name,
        phone || "",
        email || "",
        status || "Novo",
        notes || "",
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Contato não encontrado."
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Erro ao atualizar contato."
    });
  }
});

// EXCLUIR CLIENTE
app.delete("/api/contacts/:id", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM contacts WHERE id = $1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Contato não encontrado."
      });
    }

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Erro ao excluir contato."
    });
  }
});

// EXPORTAR CLIENTES
app.get("/api/contacts/export", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT name, phone, email, status, notes, created_at
       FROM contacts ORDER BY created_at DESC`
    );

    const escapeCSV = (value) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;

    const header = [
      "Nome",
      "Telefone",
      "Email",
      "Status",
      "Observações",
      "Criado em"
    ];

    const lines = result.rows.map(contact =>
      [
        contact.name,
        contact.phone,
        contact.email,
        contact.status,
        contact.notes,
        contact.created_at
      ].map(escapeCSV).join(";")
    );

    const csv = [
      header.map(escapeCSV).join(";"),
      ...lines
    ].join("\n");

    res.setHeader(
      "Content-Type",
      "text/csv; charset=utf-8"
    );

    res.setHeader(
      "Content-Disposition",
      'attachment; filename="contatos.csv"'
    );

    res.send("\uFEFF" + csv);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Erro ao exportar contatos."
    });
  }
});

// ===================================
// MÓDULO DE VENDAS E PEDIDOS
// ===================================

// LISTAR VENDAS
app.get("/api/sales", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM sales ORDER BY created_at DESC"
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Erro ao buscar vendas."
    });
  }
});

// CADASTRAR VENDA
app.post("/api/sales", authenticate, async (req, res) => {
  try {
    const {
      customer_name,
      product,
      amount,
      status,
      notes
    } = req.body || {};

    const value = Number(amount);

    if (!customer_name || !String(customer_name).trim()) {
      return res.status(400).json({
        error: "Informe o nome do cliente."
      });
    }

    if (!product || !String(product).trim()) {
      return res.status(400).json({
        error: "Informe o produto ou serviço."
      });
    }

    if (!Number.isFinite(value) || value < 0) {
      return res.status(400).json({
        error: "Informe um valor válido."
      });
    }

    const result = await pool.query(
      `INSERT INTO sales
       (customer_name, product, amount, status, notes)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        String(customer_name).trim(),
        String(product).trim(),
        value,
        status || "Pendente",
        notes || ""
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Erro ao cadastrar venda."
    });
  }
});

// ATUALIZAR VENDA
app.put("/api/sales/:id", authenticate, async (req, res) => {
  try {
    const {
      customer_name,
      product,
      amount,
      status,
      notes
    } = req.body || {};

    const value = Number(amount);

    if (!customer_name || !String(customer_name).trim()) {
      return res.status(400).json({
        error: "Informe o nome do cliente."
      });
    }

    if (!product || !String(product).trim()) {
      return res.status(400).json({
        error: "Informe o produto ou serviço."
      });
    }

    if (!Number.isFinite(value) || value < 0) {
      return res.status(400).json({
        error: "Informe um valor válido."
      });
    }

    const result = await pool.query(
      `UPDATE sales
       SET customer_name = $1,
           product = $2,
           amount = $3,
           status = $4,
           notes = $5,
           updated_at = NOW()
       WHERE id = $6
       RETURNING *`,
      [
        String(customer_name).trim(),
        String(product).trim(),
        value,
        status || "Pendente",
        notes || "",
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Venda não encontrada."
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Erro ao atualizar venda."
    });
  }
});

// EXCLUIR VENDA
app.delete("/api/sales/:id", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM sales WHERE id = $1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Venda não encontrada."
      });
    }

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Erro ao excluir venda."
    });
  }
});

// EXPORTAR VENDAS
app.get("/api/sales/export", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT customer_name, product, amount, status, notes, created_at
       FROM sales ORDER BY created_at DESC`
    );

    const escapeCSV = (value) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;

    const header = [
      "Cliente",
      "Produto",
      "Valor",
      "Status",
      "Observações",
      "Criado em"
    ];

    const lines = result.rows.map(sale =>
      [
        sale.customer_name,
        sale.product,
        sale.amount,
        sale.status,
        sale.notes,
        sale.created_at
      ].map(escapeCSV).join(";")
    );

    const csv = [
      header.map(escapeCSV).join(";"),
      ...lines
    ].join("\n");

    res.setHeader(
      "Content-Type",
      "text/csv; charset=utf-8"
    );

    res.setHeader(
      "Content-Disposition",
      'attachment; filename="vendas.csv"'
    );

    res.send("\uFEFF" + csv);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Erro ao exportar vendas."
    });
  }
});

// WEBHOOK DO WHATSAPP
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (
    mode === "subscribe" &&
    safeEqual(token, process.env.META_VERIFY_TOKEN)
  ) {
    return res.status(200).send(challenge);
  }

  res.sendStatus(403);
});

app.post("/webhook", (req, res) => {
  const appSecret = process.env.META_APP_SECRET;

  if (appSecret) {
    const signature = req.headers["x-hub-signature-256"];

    const expected =
      "sha256=" +
      crypto
        .createHmac("sha256", appSecret)
        .update(req.rawBody || Buffer.from(""))
        .digest("hex");

    if (!safeEqual(signature, expected)) {
      return res.sendStatus(401);
    }
  }

  console.log(
    "Evento recebido do WhatsApp:",
    JSON.stringify(req.body)
  );

  res.sendStatus(200);
});

// ROTA NÃO ENCONTRADA
app.use((req, res) => {
  res.status(404).json({
    error: "Rota não encontrada."
  });
});

// INICIALIZAÇÃO
app.listen(PORT, async () => {
  console.log(`Central de Vendas rodando na porta ${PORT}`);

  try {
    await initDatabase();
  } catch (error) {
    console.error(
      "Não foi possível inicializar o banco:",
      error.message
    );
  }
});
