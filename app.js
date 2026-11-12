
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

function csvEscape(value) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

function validMoney(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0;
}

function validMonth(value) {
  return /^\d{4}-\d{2}$/.test(String(value || ""));
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

  // Novos campos adicionados sem apagar vendas existentes.
  await pool.query(`
    ALTER TABLE sales
    ADD COLUMN IF NOT EXISTS consultant_name TEXT DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE sales
    ADD COLUMN IF NOT EXISTS commission_rate NUMERIC(5,2) NOT NULL DEFAULT 0
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS expenses (
      id BIGSERIAL PRIMARY KEY,
      description TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      category TEXT DEFAULT 'Geral',
      expense_date DATE NOT NULL DEFAULT CURRENT_DATE,
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS consultants (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      commission_rate NUMERIC(5,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS monthly_goals (
      id BIGSERIAL PRIMARY KEY,
      month_start DATE NOT NULL UNIQUE,
      target_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  console.log("Banco de dados inicializado.");
}

// SAÚDE
app.get("/health", async (req, res) => {
  let database = false;

  try {
    await pool.query("SELECT 1");
    database = true;
  } catch (error) {
    console.error("Erro no banco:", error.message);
  }

  res.json({ status: "online", database });
});

// LOGIN
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

  res.json({ success: true, token });
});

// LOGOUT
app.post("/api/logout", authenticate, (req, res) => {
  const authorization = req.headers.authorization || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : req.headers["x-session-token"];

  sessions.delete(token);
  res.json({ success: true });
});

// CLIENTES
app.get("/api/contacts", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM contacts ORDER BY created_at DESC"
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao buscar contatos." });
  }
});

app.post("/api/contacts", authenticate, async (req, res) => {
  try {
    const { name, phone, email, status, notes } = req.body || {};

    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: "O nome é obrigatório." });
    }

    const result = await pool.query(
      `INSERT INTO contacts
       (name, phone, email, status, notes)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
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
    res.status(500).json({ error: "Erro ao criar contato." });
  }
});

app.put("/api/contacts/:id", authenticate, async (req, res) => {
  try {
    const { name, phone, email, status, notes } = req.body || {};

    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: "O nome é obrigatório." });
    }

    const result = await pool.query(
      `UPDATE contacts
       SET name=$1, phone=$2, email=$3, status=$4,
           notes=$5, updated_at=NOW()
       WHERE id=$6 RETURNING *`,
      [
        String(name).trim(),
        phone || "",
        email || "",
        status || "Novo",
        notes || "",
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Contato não encontrado." });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao atualizar contato." });
  }
});

app.delete("/api/contacts/:id", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM contacts WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Contato não encontrado." });
    }

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao excluir contato." });
  }
});

app.get("/api/contacts/export", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT name, phone, email, status, notes, created_at
       FROM contacts ORDER BY created_at DESC`
    );

    const header = [
      "Nome", "Telefone", "Email", "Status", "Observações", "Criado em"
    ];

    const lines = result.rows.map(c =>
      [
        c.name, c.phone, c.email, c.status, c.notes, c.created_at
      ].map(csvEscape).join(";")
    );

    const csv = [
      header.map(csvEscape).join(";"),
      ...lines
    ].join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="contatos.csv"');
    res.send("\uFEFF" + csv);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao exportar contatos." });
  }
});

// CONSULTORES
app.get("/api/consultants", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM consultants ORDER BY name ASC"
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao buscar consultores." });
  }
});

app.post("/api/consultants", authenticate, async (req, res) => {
  try {
    const { name, commission_rate } = req.body || {};
    const rate = Number(commission_rate || 0);

    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: "Informe o nome do consultor." });
    }

    if (!Number.isFinite(rate) || rate < 0 || rate > 100) {
      return res.status(400).json({ error: "Comissão deve estar entre 0 e 100%." });
    }

    const result = await pool.query(
      `INSERT INTO consultants (name, commission_rate)
       VALUES ($1, $2) RETURNING *`,
      [String(name).trim(), rate]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Esse consultor já existe." });
    }
    console.error(error);
    res.status(500).json({ error: "Erro ao cadastrar consultor." });
  }
});

app.put("/api/consultants/:id", authenticate, async (req, res) => {
  try {
    const { name, commission_rate } = req.body || {};
    const rate = Number(commission_rate || 0);

    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: "Informe o nome do consultor." });
    }

    if (!Number.isFinite(rate) || rate < 0 || rate > 100) {
      return res.status(400).json({ error: "Comissão deve estar entre 0 e 100%." });
    }

    const result = await pool.query(
      `UPDATE consultants SET name=$1, commission_rate=$2
       WHERE id=$3 RETURNING *`,
      [String(name).trim(), rate, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Consultor não encontrado." });
    }

    res.json(result.rows[0]);
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Esse consultor já existe." });
    }
    console.error(error);
    res.status(500).json({ error: "Erro ao atualizar consultor." });
  }
});

app.delete("/api/consultants/:id", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM consultants WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Consultor não encontrado." });
    }

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao excluir consultor." });
  }
});

// VENDAS
app.get("/api/sales", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM sales ORDER BY created_at DESC"
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao buscar vendas." });
  }
});

app.post("/api/sales", authenticate, async (req, res) => {
  try {
    const {
      customer_name, product, amount, status, notes,
      consultant_name, commission_rate
    } = req.body || {};

    const value = Number(amount);
    const rate = Number(commission_rate || 0);

    if (!customer_name || !String(customer_name).trim()) {
      return res.status(400).json({ error: "Informe o nome do cliente." });
    }

    if (!product || !String(product).trim()) {
      return res.status(400).json({ error: "Informe o produto ou serviço." });
    }

    if (!validMoney(value)) {
      return res.status(400).json({ error: "Informe um valor válido." });
    }

    if (!Number.isFinite(rate) || rate < 0 || rate > 100) {
      return res.status(400).json({ error: "Comissão inválida." });
    }

    const result = await pool.query(
      `INSERT INTO sales
       (customer_name, product, amount, status, notes,
        consultant_name, commission_rate)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [
        String(customer_name).trim(),
        String(product).trim(),
        value,
        status || "Pendente",
        notes || "",
        consultant_name || "",
        rate
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao cadastrar venda." });
  }
});

app.put("/api/sales/:id", authenticate, async (req, res) => {
  try {
    const {
      customer_name, product, amount, status, notes,
      consultant_name, commission_rate
    } = req.body || {};

    const value = Number(amount);
    const rate = Number(commission_rate || 0);

    if (!customer_name || !String(customer_name).trim()) {
      return res.status(400).json({ error: "Informe o nome do cliente." });
    }

    if (!product || !String(product).trim()) {
      return res.status(400).json({ error: "Informe o produto ou serviço." });
    }

    if (!validMoney(value)) {
      return res.status(400).json({ error: "Informe um valor válido." });
    }

    if (!Number.isFinite(rate) || rate < 0 || rate > 100) {
      return res.status(400).json({ error: "Comissão inválida." });
    }

    const result = await pool.query(
      `UPDATE sales
       SET customer_name=$1, product=$2, amount=$3, status=$4,
           notes=$5, consultant_name=$6, commission_rate=$7,
           updated_at=NOW()
       WHERE id=$8 RETURNING *`,
      [
        String(customer_name).trim(),
        String(product).trim(),
        value,
        status || "Pendente",
        notes || "",
        consultant_name || "",
        rate,
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Venda não encontrada." });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao atualizar venda." });
  }
});

app.delete("/api/sales/:id", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM sales WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Venda não encontrada." });
    }

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao excluir venda." });
  }
});

app.get("/api/sales/export", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT customer_name, product, amount, status, notes,
              consultant_name, commission_rate, created_at
       FROM sales ORDER BY created_at DESC`
    );

    const header = [
      "Cliente", "Produto", "Valor", "Status", "Observações",
      "Consultor", "Comissão (%)", "Criado em"
    ];

    const lines = result.rows.map(s =>
      [
        s.customer_name, s.product, s.amount, s.status, s.notes,
        s.consultant_name, s.commission_rate, s.created_at
      ].map(csvEscape).join(";")
    );

    const csv = [
      header.map(csvEscape).join(";"),
      ...lines
    ].join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="vendas.csv"');
    res.send("\uFEFF" + csv);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao exportar vendas." });
  }
});

// DESPESAS
app.get("/api/expenses", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM expenses ORDER BY expense_date DESC, id DESC"
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao buscar despesas." });
  }
});

app.post("/api/expenses", authenticate, async (req, res) => {
  try {
    const { description, amount, category, expense_date, notes } = req.body || {};
    const value = Number(amount);

    if (!description || !String(description).trim()) {
      return res.status(400).json({ error: "Informe a descrição da despesa." });
    }

    if (!validMoney(value) || value === 0) {
      return res.status(400).json({ error: "Informe um valor válido." });
    }

    const result = await pool.query(
      `INSERT INTO expenses
       (description, amount, category, expense_date, notes)
       VALUES ($1,$2,$3,COALESCE($4::date,CURRENT_DATE),$5)
       RETURNING *`,
      [
        String(description).trim(),
        value,
        category || "Geral",
        expense_date || null,
        notes || ""
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao cadastrar despesa." });
  }
});

app.put("/api/expenses/:id", authenticate, async (req, res) => {
  try {
    const { description, amount, category, expense_date, notes } = req.body || {};
    const value = Number(amount);

    if (!description || !String(description).trim()) {
      return res.status(400).json({ error: "Informe a descrição da despesa." });
    }

    if (!validMoney(value) || value === 0) {
      return res.status(400).json({ error: "Informe um valor válido." });
    }

    const result = await pool.query(
      `UPDATE expenses
       SET description=$1, amount=$2, category=$3,
           expense_date=COALESCE($4::date,expense_date), notes=$5
       WHERE id=$6 RETURNING *`,
      [
        String(description).trim(),
        value,
        category || "Geral",
        expense_date || null,
        notes || "",
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Despesa não encontrada." });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao atualizar despesa." });
  }
});

app.delete("/api/expenses/:id", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM expenses WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Despesa não encontrada." });
    }

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao excluir despesa." });
  }
});

// META MENSAL
app.get("/api/goals", authenticate, async (req, res) => {
  try {
    const month = req.query.month;

    if (!validMonth(month)) {
      return res.status(400).json({ error: "Informe o mês no formato AAAA-MM." });
    }

    const result = await pool.query(
      `SELECT * FROM monthly_goals
       WHERE month_start=$1::date`,
      [month + "-01"]
    );

    res.json(result.rows[0] || {
      month_start: month + "-01",
      target_amount: 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao buscar meta." });
  }
});

app.put("/api/goals", authenticate, async (req, res) => {
  try {
    const { month, target_amount } = req.body || {};
    const target = Number(target_amount);

    if (!validMonth(month)) {
      return res.status(400).json({ error: "Mês inválido." });
    }

    if (!validMoney(target)) {
      return res.status(400).json({ error: "Informe uma meta válida." });
    }

    const result = await pool.query(
      `INSERT INTO monthly_goals (month_start,target_amount)
       VALUES ($1::date,$2)
       ON CONFLICT (month_start)
       DO UPDATE SET target_amount=EXCLUDED.target_amount,
                     updated_at=NOW()
       RETURNING *`,
      [month + "-01", target]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao salvar meta." });
  }
});

// RESUMO FINANCEIRO
app.get("/api/finance/summary", authenticate, async (req, res) => {
  try {
    const month = req.query.month;

    if (!validMonth(month)) {
      return res.status(400).json({ error: "Mês inválido." });
    }

    const start = month + "-01";

    const salesResult = await pool.query(
      `SELECT
         COALESCE(SUM(amount) FILTER (WHERE status='Pago'),0) AS revenue,
         COALESCE(SUM(amount) FILTER (WHERE status='Pendente'),0) AS pending,
         COUNT(*) FILTER (WHERE status='Pago') AS paid_count,
         COALESCE(SUM(amount * commission_rate / 100)
           FILTER (WHERE status='Pago'),0) AS commissions
       FROM sales
       WHERE created_at >= $1::date
         AND created_at < ($1::date + INTERVAL '1 month')`,
      [start]
    );

    const expensesResult = await pool.query(
      `SELECT COALESCE(SUM(amount),0) AS expenses
       FROM expenses
       WHERE expense_date >= $1::date
         AND expense_date < ($1::date + INTERVAL '1 month')`,
      [start]
    );

    const goalResult = await pool.query(
      `SELECT target_amount FROM monthly_goals WHERE month_start=$1::date`,
      [start]
    );

    const salesData = salesResult.rows[0];
    const revenue = Number(salesData.revenue);
    const expenses = Number(expensesResult.rows[0].expenses);
    const commissions = Number(salesData.commissions);
    const target = Number(goalResult.rows[0]?.target_amount || 0);

    res.json({
      revenue,
      pending: Number(salesData.pending),
      expenses,
      commissions,
      profit: revenue - expenses - commissions,
      paid_count: Number(salesData.paid_count),
      target,
      progress: target > 0 ? Math.min(100, revenue / target * 100) : 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao gerar resumo financeiro." });
  }
});

// WEBHOOK WHATSAPP
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
    const expected = "sha256=" + crypto
      .createHmac("sha256", appSecret)
      .update(req.rawBody || Buffer.from(""))
      .digest("hex");

    if (!safeEqual(signature, expected)) {
      return res.sendStatus(401);
    }
  }

  console.log("Evento recebido do WhatsApp:", JSON.stringify(req.body));
  res.sendStatus(200);
});

// ROTA NÃO ENCONTRADA
app.use((req, res) => {
  res.status(404).json({ error: "Rota não encontrada." });
});

// INICIALIZAÇÃO
app.listen(PORT, async () => {
  console.log(`Central de Vendas rodando na porta ${PORT}`);

  try {
    await initDatabase();
  } catch (error) {
    console.error("Não foi possível inicializar o banco:", error.message);
  }
});
