require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");
const bcrypt = require("bcryptjs");

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
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function tokenFrom(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ")
    ? h.slice(7)
    : req.headers["x-session-token"];
}

function authenticate(req, res, next) {
  const token = tokenFrom(req);
  const user = token && sessions.get(token);

  if (!user) {
    return res.status(401).json({
      error: "Sessão inválida ou expirada."
    });
  }

  req.user = user;
  req.sessionToken = token;
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Acesso permitido somente ao administrador."
    });
  }

  next();
}

function csvEscape(v) {
  return `"${String(v ?? "").replace(/"/g, '""')}"`;
}

function validMoney(v) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0;
}

function validMonth(v) {
  return /^\d{4}-(0[1-9]|1[0-2])$/.test(String(v || ""));
}

function validRate(v) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 && n <= 100;
}

async function getConsultant(req) {
  const r = await pool.query(
    "SELECT id,name,commission_rate FROM consultants WHERE id=$1",
    [req.user.consultantId]
  );

  return r.rows[0] || null;
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

  await pool.query(`
    ALTER TABLE sales
    ADD COLUMN IF NOT EXISTS consultant_name TEXT DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE sales
    ADD COLUMN IF NOT EXISTS commission_rate
    NUMERIC(5,2) NOT NULL DEFAULT 0
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS consultant_monthly_goals (
      id BIGSERIAL PRIMARY KEY,
      consultant_id BIGINT NOT NULL
        REFERENCES consultants(id) ON DELETE CASCADE,
      month_start DATE NOT NULL,
      target_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(consultant_id, month_start)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS consultant_accounts (
      id BIGSERIAL PRIMARY KEY,
      consultant_id BIGINT NOT NULL UNIQUE
        REFERENCES consultants(id) ON DELETE CASCADE,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  console.log("Banco de dados inicializado.");
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "online", database: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ status: "offline", database: false });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (
      safeEqual(username, process.env.ADMIN_USER || "admin") &&
      safeEqual(password, process.env.ADMIN_PASSWORD)
    ) {
      const token = crypto.randomBytes(32).toString("hex");

      sessions.set(token, { role: "admin" });

      return res.json({
        success: true,
        token,
        role: "admin"
      });
    }

    const r = await pool.query(`
      SELECT
        a.consultant_id,
        a.username,
        a.password_hash,
        c.name,
        c.commission_rate
      FROM consultant_accounts a
      JOIN consultants c ON c.id = a.consultant_id
      WHERE LOWER(a.username) = LOWER($1)
    `, [String(username || "").trim()]);

    if (
      !r.rowCount ||
      !await bcrypt.compare(
        String(password || ""),
        r.rows[0].password_hash
      )
    ) {
      return res.status(401).json({
        error: "Usuário ou senha incorretos."
      });
    }

    const c = r.rows[0];
    const token = crypto.randomBytes(32).toString("hex");

    sessions.set(token, {
      role: "consultant",
      consultantId: Number(c.consultant_id),
      consultantName: c.name
    });

    res.json({
      success: true,
      token,
      role: "consultant",
      consultantId: Number(c.consultant_id),
      consultantName: c.name
    });

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao entrar no sistema."
    });
  }
});

app.post("/api/logout", authenticate, (req, res) => {
  sessions.delete(req.sessionToken);
  res.json({ success: true });
});

app.get("/api/me", authenticate, (req, res) => {
  res.json(req.user);
});

// CLIENTES: SOMENTE ADMINISTRADOR
app.get("/api/contacts", authenticate, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM contacts ORDER BY created_at DESC"
    );
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar contatos." });
  }
});

app.post("/api/contacts", authenticate, adminOnly, async (req, res) => {
  try {
    const { name, phone, email, status, notes } = req.body || {};

    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: "O nome é obrigatório." });
    }

    const r = await pool.query(`
      INSERT INTO contacts(name,phone,email,status,notes)
      VALUES($1,$2,$3,$4,$5)
      RETURNING *
    `, [
      String(name).trim(),
      phone || "",
      email || "",
      status || "Novo",
      notes || ""
    ]);

    res.status(201).json(r.rows[0]);

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar contato." });
  }
});

app.put("/api/contacts/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const { name, phone, email, status, notes } = req.body || {};

    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: "O nome é obrigatório." });
    }

    const r = await pool.query(`
      UPDATE contacts
      SET name=$1,phone=$2,email=$3,status=$4,notes=$5,updated_at=NOW()
      WHERE id=$6
      RETURNING *
    `, [
      String(name).trim(),
      phone || "",
      email || "",
      status || "Novo",
      notes || "",
      req.params.id
    ]);

    if (!r.rowCount) {
      return res.status(404).json({ error: "Contato não encontrado." });
    }

    res.json(r.rows[0]);

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao atualizar contato." });
  }
});

app.delete("/api/contacts/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      "DELETE FROM contacts WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!r.rowCount) {
      return res.status(404).json({ error: "Contato não encontrado." });
    }

    res.json({ success: true });

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir contato." });
  }
});

app.get("/api/contacts/export", authenticate, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT name,phone,email,status,notes,created_at
      FROM contacts
      ORDER BY created_at DESC
    `);

    const h = [
      "Nome", "Telefone", "Email", "Status",
      "Observações", "Criado em"
    ];

    const lines = r.rows.map(c =>
      [c.name,c.phone,c.email,c.status,c.notes,c.created_at]
        .map(csvEscape).join(";")
    );

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="contatos.csv"'
    );

    res.send("\uFEFF" + [
      h.map(csvEscape).join(";"),
      ...lines
    ].join("\n"));

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao exportar contatos." });
  }
});

// CONSULTORES
app.get("/api/consultants", authenticate, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT
        c.*,
        a.username,
        CASE WHEN a.id IS NULL THEN false ELSE true END AS has_access
      FROM consultants c
      LEFT JOIN consultant_accounts a ON a.consultant_id=c.id
      ORDER BY c.name
    `);

    res.json(r.rows);

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar consultores." });
  }
});

app.post("/api/consultants", authenticate, adminOnly, async (req, res) => {
  try {
    const { name, commission_rate } = req.body || {};
    const rate = Number(commission_rate || 0);

    if (!name || !String(name).trim()) {
      return res.status(400).json({
        error: "Informe o nome do consultor."
      });
    }

    if (!validRate(rate)) {
      return res.status(400).json({
        error: "Comissão deve estar entre 0 e 100%."
      });
    }

    const r = await pool.query(`
      INSERT INTO consultants(name,commission_rate)
      VALUES($1,$2)
      RETURNING *
    `, [String(name).trim(), rate]);

    res.status(201).json(r.rows[0]);

  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({
        error: "Esse consultor já existe."
      });
    }

    console.error(e);
    res.status(500).json({
      error: "Erro ao cadastrar consultor."
    });
  }
});

app.put("/api/consultants/:id", authenticate, adminOnly, async (req, res) => {
  const client = await pool.connect();

  try {
    const name = String(req.body?.name || "").trim();
    const rate = Number(req.body?.commission_rate || 0);

    if (!name) {
      return res.status(400).json({
        error: "Informe o nome do consultor."
      });
    }

    if (!validRate(rate)) {
      return res.status(400).json({
        error: "Comissão deve estar entre 0 e 100%."
      });
    }

    await client.query("BEGIN");

    const old = await client.query(
      "SELECT name FROM consultants WHERE id=$1",
      [req.params.id]
    );

    if (!old.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        error: "Consultor não encontrado."
      });
    }

    const oldName = old.rows[0].name;

    const updated = await client.query(`
      UPDATE consultants
      SET name=$1,commission_rate=$2
      WHERE id=$3
      RETURNING *
    `, [name, rate, req.params.id]);

    await client.query(`
      UPDATE sales
      SET consultant_name=$1
      WHERE LOWER(TRIM(consultant_name))=LOWER(TRIM($2))
    `, [name, oldName]);

    await client.query("COMMIT");
    res.json(updated.rows[0]);

  } catch (e) {
    await client.query("ROLLBACK");

    if (e.code === "23505") {
      return res.status(409).json({
        error: "Esse consultor já existe."
      });
    }

    console.error(e);
    res.status(500).json({
      error: "Erro ao atualizar consultor."
    });

  } finally {
    client.release();
  }
});

app.delete("/api/consultants/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      "DELETE FROM consultants WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!r.rowCount) {
      return res.status(404).json({
        error: "Consultor não encontrado."
      });
    }

    res.json({ success: true });

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao excluir consultor."
    });
  }
});

// CRIAR OU ATUALIZAR ACESSO DO CONSULTOR
app.put("/api/consultants/:id/access", authenticate, adminOnly, async (req, res) => {
  try {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");

    if (!username) {
      return res.status(400).json({
        error: "Informe o usuário de acesso."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "A senha precisa ter pelo menos 8 caracteres."
      });
    }

    const c = await pool.query(
      "SELECT id FROM consultants WHERE id=$1",
      [req.params.id]
    );

    if (!c.rowCount) {
      return res.status(404).json({
        error: "Consultor não encontrado."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const r = await pool.query(`
      INSERT INTO consultant_accounts(consultant_id,username,password_hash)
      VALUES($1,$2,$3)
      ON CONFLICT(consultant_id)
      DO UPDATE SET
        username=EXCLUDED.username,
        password_hash=EXCLUDED.password_hash,
        updated_at=NOW()
      RETURNING consultant_id,username
    `, [req.params.id, username, hash]);

    res.json({
      success: true,
      account: r.rows[0]
    });

  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({
        error: "Esse nome de usuário já está em uso."
      });
    }

    console.error(e);
    res.status(500).json({
      error: "Erro ao salvar acesso do consultor."
    });
  }
});

app.delete("/api/consultants/:id/access", authenticate, adminOnly, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM consultant_accounts WHERE consultant_id=$1",
      [req.params.id]
    );

    res.json({ success: true });

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao remover acesso."
    });
  }
});

// VENDAS
app.get("/api/sales", authenticate, async (req, res) => {
  try {
    const r = req.user.role === "admin"
      ? await pool.query(
          "SELECT * FROM sales ORDER BY created_at DESC"
        )
      : await pool.query(`
          SELECT *
          FROM sales
          WHERE LOWER(TRIM(consultant_name))=LOWER(TRIM($1))
          ORDER BY created_at DESC
        `, [req.user.consultantName]);

    res.json(r.rows);

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar vendas." });
  }
});

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

    if (!validMoney(value)) {
      return res.status(400).json({
        error: "Informe um valor válido."
      });
    }

    let consultantName = "";
    let rate = 0;

    if (req.user.role === "consultant") {
      const c = await getConsultant(req);

      if (!c) {
        return res.status(403).json({
          error: "Conta de consultor não está mais ativa."
        });
      }

      consultantName = c.name;
      rate = Number(c.commission_rate || 0);

    } else {
      consultantName = String(req.body?.consultant_name || "");
      rate = Number(req.body?.commission_rate || 0);

      if (!validRate(rate)) {
        return res.status(400).json({
          error: "Comissão inválida."
        });
      }
    }

    const r = await pool.query(`
      INSERT INTO sales(
        customer_name,product,amount,status,notes,
        consultant_name,commission_rate
      )
      VALUES($1,$2,$3,$4,$5,$6,$7)
      RETURNING *
    `, [
      String(customer_name).trim(),
      String(product).trim(),
      value,
      status || "Pendente",
      notes || "",
      consultantName,
      rate
    ]);

    res.status(201).json(r.rows[0]);

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao cadastrar venda."
    });
  }
});

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

    if (!validMoney(value)) {
      return res.status(400).json({
        error: "Informe um valor válido."
      });
    }

    let r;

    if (req.user.role === "consultant") {
      const c = await getConsultant(req);

      if (!c) {
        return res.status(403).json({
          error: "Conta de consultor não está mais ativa."
        });
      }

      r = await pool.query(`
        UPDATE sales
        SET
          customer_name=$1,
          product=$2,
          amount=$3,
          status=$4,
          notes=$5,
          updated_at=NOW()
        WHERE id=$6
          AND LOWER(TRIM(consultant_name))=LOWER(TRIM($7))
        RETURNING *
      `, [
        String(customer_name).trim(),
        String(product).trim(),
        value,
        status || "Pendente",
        notes || "",
        req.params.id,
        c.name
      ]);

    } else {
      const rate = Number(req.body?.commission_rate || 0);

      if (!validRate(rate)) {
        return res.status(400).json({
          error: "Comissão inválida."
        });
      }

      r = await pool.query(`
        UPDATE sales
        SET
          customer_name=$1,
          product=$2,
          amount=$3,
          status=$4,
          notes=$5,
          consultant_name=$6,
          commission_rate=$7,
          updated_at=NOW()
        WHERE id=$8
        RETURNING *
      `, [
        String(customer_name).trim(),
        String(product).trim(),
        value,
        status || "Pendente",
        notes || "",
        req.body?.consultant_name || "",
        rate,
        req.params.id
      ]);
    }

    if (!r.rowCount) {
      return res.status(404).json({
        error: "Venda não encontrada ou sem permissão."
      });
    }

    res.json(r.rows[0]);

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao atualizar venda."
    });
  }
});

app.delete("/api/sales/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      "DELETE FROM sales WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!r.rowCount) {
      return res.status(404).json({
        error: "Venda não encontrada."
      });
    }

    res.json({ success: true });

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao excluir venda."
    });
  }
});

app.get("/api/sales/export", authenticate, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT
        customer_name,product,amount,status,notes,
        consultant_name,commission_rate,created_at
      FROM sales
      ORDER BY created_at DESC
    `);

    const h = [
      "Cliente", "Produto", "Valor", "Status",
      "Observações", "Consultor", "Comissão (%)", "Criado em"
    ];

    const lines = r.rows.map(s =>
      [
        s.customer_name,s.product,s.amount,s.status,s.notes,
        s.consultant_name,s.commission_rate,s.created_at
      ].map(csvEscape).join(";")
    );

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="vendas.csv"'
    );

    res.send("\uFEFF" + [
      h.map(csvEscape).join(";"),
      ...lines
    ].join("\n"));

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao exportar vendas."
    });
  }
});

// DESPESAS: SOMENTE ADMINISTRADOR
app.get("/api/expenses", authenticate, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM expenses ORDER BY expense_date DESC,id DESC"
    );

    res.json(r.rows);

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao buscar despesas."
    });
  }
});

app.post("/api/expenses", authenticate, adminOnly, async (req, res) => {
  try {
    const {
      description,
      amount,
      category,
      expense_date,
      notes
    } = req.body || {};

    const value = Number(amount);

    if (!description || !String(description).trim()) {
      return res.status(400).json({
        error: "Informe a descrição da despesa."
      });
    }

    if (!validMoney(value) || value === 0) {
      return res.status(400).json({
        error: "Informe um valor válido."
      });
    }

    const r = await pool.query(`
      INSERT INTO expenses(
        description,amount,category,expense_date,notes
      )
      VALUES($1,$2,$3,COALESCE($4::date,CURRENT_DATE),$5)
      RETURNING *
    `, [
      String(description).trim(),
      value,
      category || "Geral",
      expense_date || null,
      notes || ""
    ]);

    res.status(201).json(r.rows[0]);

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao cadastrar despesa."
    });
  }
});

app.put("/api/expenses/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const {
      description,
      amount,
      category,
      expense_date,
      notes
    } = req.body || {};

    const value = Number(amount);

    if (!description || !String(description).trim()) {
      return res.status(400).json({
        error: "Informe a descrição da despesa."
      });
    }

    if (!validMoney(value) || value === 0) {
      return res.status(400).json({
        error: "Informe um valor válido."
      });
    }

    const r = await pool.query(`
      UPDATE expenses
      SET
        description=$1,
        amount=$2,
        category=$3,
        expense_date=COALESCE($4::date,expense_date),
        notes=$5
      WHERE id=$6
      RETURNING *
    `, [
      String(description).trim(),
      value,
      category || "Geral",
      expense_date || null,
      notes || "",
      req.params.id
    ]);

    if (!r.rowCount) {
      return res.status(404).json({
        error: "Despesa não encontrada."
      });
    }

    res.json(r.rows[0]);

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao atualizar despesa."
    });
  }
});

app.delete("/api/expenses/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      "DELETE FROM expenses WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!r.rowCount) {
      return res.status(404).json({
        error: "Despesa não encontrada."
      });
    }

    res.json({ success: true });

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao excluir despesa."
    });
  }
});

// METAS GERAIS
app.get("/api/goals", authenticate, adminOnly, async (req, res) => {
  try {
    const m = req.query.month;

    if (!validMonth(m)) {
      return res.status(400).json({
        error: "Informe o mês no formato AAAA-MM."
      });
    }

    const r = await pool.query(
      "SELECT * FROM monthly_goals WHERE month_start=$1::date",
      [m + "-01"]
    );

    res.json(r.rows[0] || {
      month_start: m + "-01",
      target_amount: 0
    });

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao buscar meta."
    });
  }
});

app.put("/api/goals", authenticate, adminOnly, async (req, res) => {
  try {
    const { month, target_amount } = req.body || {};
    const target = Number(target_amount);

    if (!validMonth(month)) {
      return res.status(400).json({ error: "Mês inválido." });
    }

    if (!validMoney(target)) {
      return res.status(400).json({
        error: "Informe uma meta válida."
      });
    }

    const r = await pool.query(`
      INSERT INTO monthly_goals(month_start,target_amount)
      VALUES($1::date,$2)
      ON CONFLICT(month_start)
      DO UPDATE SET
        target_amount=EXCLUDED.target_amount,
        updated_at=NOW()
      RETURNING *
    `, [month + "-01", target]);

    res.json(r.rows[0]);

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao salvar meta."
    });
  }
});

// DESEMPENHO INDIVIDUAL
app.get("/api/consultant-goals/performance", authenticate, async (req, res) => {
  try {
    const month = req.query.month;

    if (!validMonth(month)) {
      return res.status(400).json({ error: "Mês inválido." });
    }

    const params = [month + "-01"];
    let where = "";

    if (req.user.role === "consultant") {
      where = "WHERE c.id=$2";
      params.push(req.user.consultantId);
    }

    const r = await pool.query(`
      SELECT
        c.id AS consultant_id,
        c.name AS consultant_name,
        c.commission_rate,
        COALESCE(g.target_amount,0) AS target_amount,
        COALESCE(
          SUM(s.amount) FILTER(WHERE s.status='Pago'),
          0
        ) AS sales_amount,
        COALESCE(
          SUM(s.amount*s.commission_rate/100)
          FILTER(WHERE s.status='Pago'),
          0
        ) AS commissions,
        COUNT(s.id) FILTER(WHERE s.status='Pago') AS paid_count
      FROM consultants c
      LEFT JOIN consultant_monthly_goals g
        ON g.consultant_id=c.id
        AND g.month_start=$1::date
      LEFT JOIN sales s
        ON LOWER(TRIM(s.consultant_name))=LOWER(TRIM(c.name))
        AND s.created_at >= $1::date
        AND s.created_at < ($1::date+INTERVAL '1 month')
      ${where}
      GROUP BY c.id,c.name,c.commission_rate,g.target_amount
      ORDER BY sales_amount DESC,c.name
    `, params);

    res.json(r.rows.map(x => {
      const target = Number(x.target_amount || 0);
      const sold = Number(x.sales_amount || 0);

      return {
        ...x,
        target_amount: target,
        sales_amount: sold,
        commissions: Number(x.commissions || 0),
        paid_count: Number(x.paid_count || 0),
        remaining: Math.max(0, target - sold),
        progress: target > 0
          ? Math.min(100, sold / target * 100)
          : 0
      };
    }));

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao calcular desempenho."
    });
  }
});

app.put("/api/consultant-goals", authenticate, adminOnly, async (req, res) => {
  try {
    const {
      consultant_id,
      month,
      target_amount
    } = req.body || {};

    const target = Number(target_amount);

    if (!validMonth(month)) {
      return res.status(400).json({ error: "Mês inválido." });
    }

    if (
      !Number.isInteger(Number(consultant_id)) ||
      Number(consultant_id) < 1
    ) {
      return res.status(400).json({
        error: "Consultor inválido."
      });
    }

    if (!validMoney(target)) {
      return res.status(400).json({
        error: "Informe uma meta válida."
      });
    }

    const c = await pool.query(
      "SELECT id FROM consultants WHERE id=$1",
      [consultant_id]
    );

    if (!c.rowCount) {
      return res.status(404).json({
        error: "Consultor não encontrado."
      });
    }

    const r = await pool.query(`
      INSERT INTO consultant_monthly_goals(
        consultant_id,month_start,target_amount
      )
      VALUES($1,$2::date,$3)
      ON CONFLICT(consultant_id,month_start)
      DO UPDATE SET
        target_amount=EXCLUDED.target_amount,
        updated_at=NOW()
      RETURNING *
    `, [consultant_id, month + "-01", target]);

    res.json(r.rows[0]);

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao salvar meta individual."
    });
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
    let sr;

    if (req.user.role === "admin") {
      sr = await pool.query(`
        SELECT
          COALESCE(
            SUM(amount) FILTER(WHERE status='Pago'),0
          ) revenue,
          COALESCE(
            SUM(amount) FILTER(WHERE status='Pendente'),0
          ) pending,
          COUNT(*) FILTER(WHERE status='Pago') paid_count,
          COALESCE(
            SUM(amount*commission_rate/100)
            FILTER(WHERE status='Pago'),0
          ) commissions
        FROM sales
        WHERE created_at >= $1::date
          AND created_at < ($1::date+INTERVAL '1 month')
      `, [start]);

    } else {
      sr = await pool.query(`
        SELECT
          COALESCE(
            SUM(amount) FILTER(WHERE status='Pago'),0
          ) revenue,
          COALESCE(
            SUM(amount) FILTER(WHERE status='Pendente'),0
          ) pending,
          COUNT(*) FILTER(WHERE status='Pago') paid_count,
          COALESCE(
            SUM(amount*commission_rate/100)
            FILTER(WHERE status='Pago'),0
          ) commissions
        FROM sales
        WHERE LOWER(TRIM(consultant_name))=LOWER(TRIM($2))
          AND created_at >= $1::date
          AND created_at < ($1::date+INTERVAL '1 month')
      `, [start, req.user.consultantName]);
    }

    const s = sr.rows[0];

    if (req.user.role === "consultant") {
      const g = await pool.query(`
        SELECT target_amount
        FROM consultant_monthly_goals
        WHERE consultant_id=$1
          AND month_start=$2::date
      `, [req.user.consultantId, start]);

      const target = Number(g.rows[0]?.target_amount || 0);
      const revenue = Number(s.revenue);

      return res.json({
        revenue,
        pending: Number(s.pending),
        expenses: 0,
        commissions: Number(s.commissions),
        profit: Number(s.commissions),
        paid_count: Number(s.paid_count),
        target,
        progress: target > 0
          ? Math.min(100, revenue / target * 100)
          : 0
      });
    }

    const er = await pool.query(`
      SELECT COALESCE(SUM(amount),0) expenses
      FROM expenses
      WHERE expense_date >= $1::date
        AND expense_date < ($1::date+INTERVAL '1 month')
    `, [start]);

    const gr = await pool.query(
      "SELECT target_amount FROM monthly_goals WHERE month_start=$1::date",
      [start]
    );

    const revenue = Number(s.revenue);
    const expenses = Number(er.rows[0].expenses);
    const commissions = Number(s.commissions);
    const target = Number(gr.rows[0]?.target_amount || 0);

    res.json({
      revenue,
      pending: Number(s.pending),
      expenses,
      commissions,
      profit: revenue - expenses - commissions,
      paid_count: Number(s.paid_count),
      target,
      progress: target > 0
        ? Math.min(100, revenue / target * 100)
        : 0
    });

  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "Erro ao gerar resumo financeiro."
    });
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
  const secret = process.env.META_APP_SECRET;

  if (secret) {
    const signature = req.headers["x-hub-signature-256"];

    const expected = "sha256=" + crypto
      .createHmac("sha256", secret)
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

app.use((req, res) => {
  res.status(404).json({
    error: "Rota não encontrada."
  });
});

app.listen(PORT, async () => {
  console.log(`Central de Vendas rodando na porta ${PORT}`);

  try {
    await initDatabase();
  } catch (e) {
    console.error(
      "Não foi possível inicializar o banco:",
      e.message
    );
  }
});
