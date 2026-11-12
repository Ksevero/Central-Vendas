
# Central de Vendas

Painel inicial para gerenciamento de clientes e oportunidades de venda.

## Tecnologias
- Node.js
- Express
- PostgreSQL
- Supabase
- Render

## Instalação
1. Instale Node.js 20 ou superior.
2. Execute `npm install`.
3. Configure as variáveis de ambiente.
4. Execute `npm start`.

## Variáveis necessárias
- DATABASE_URL
- DATABASE_SSL
- ADMIN_USER
- ADMIN_PASSWORD

## Endpoints
- `/health` — verifica o servidor.
- `/api/login` — login.
- `/api/contacts` — gerenciamento de contatos.
- `/api/contacts/export` — exportação CSV.
- `/webhook` — integração inicial com WhatsApp.

## Observação
Esta é uma versão inicial. Antes de usar com clientes reais, é necessário testar, revisar a segurança e configurar o banco de dados e a integração oficial do WhatsApp.
