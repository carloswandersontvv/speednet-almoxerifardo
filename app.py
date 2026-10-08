from flask import Flask, request, redirect, url_for, render_template_string, flash, send_file, session, jsonify
import sqlite3
from datetime import date, datetime
from pathlib import Path
import re
import unicodedata
import shutil
from functools import wraps

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

# =========================================================
# CONFIGURAÇÃO
# =========================================================

app = Flask(__name__)
app.secret_key = "speednet_chave_local_2026"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Faça login para acessar o sistema."
login_manager.login_message_category = "danger"
password_hasher = PasswordHasher()


class Usuario(UserMixin):
    def __init__(self, row):
        self.id = str(row["id"])
        self.nome = row["nome"]
        self.usuario = row["usuario"]
        self.perfil = row["perfil"]
        self.ativo = row["ativo"]
        self.perfis = set()
        try:
            conn = conectar()
            roles = conn.execute("SELECT perfil FROM usuario_perfis WHERE usuario_id = ?", (int(self.id),)).fetchall()
            conn.close()
            self.perfis = {r["perfil"] for r in roles}
        except Exception:
            pass
        if self.perfil:
            self.perfis.add(self.perfil)

    def tem_perfil(self, *perfis):
        return any(p in self.perfis for p in perfis)


@login_manager.user_loader
def carregar_usuario(user_id):
    try:
        conn = conectar()
        row = conn.execute(
            "SELECT * FROM usuarios WHERE id = ? AND ativo = 1",
            (int(user_id),)
        ).fetchone()
        conn.close()
        return Usuario(row) if row else None
    except Exception:
        return None


PERFIS = {
    "admin": "Administrador",
    "almoxarifado": "Almoxarifado",
    "tecnico": "Técnico",
    "consulta": "Consulta"
}


ROTAS_POR_PERFIL = {
    "admin": None,
    "almoxarifado": None,
    "tecnico": {"/", "/equipamentos", "/movimentacoes", "/agendamentos", "/defeitos", "/relatorios"},
    "consulta": {"/", "/equipamentos", "/movimentacoes", "/agendamentos", "/defeitos", "/relatorios"},
}


def registrar_auditoria(acao, detalhes=""):
    if not current_user.is_authenticated:
        return
    try:
        conn = conectar()
        conn.execute(
            "INSERT INTO auditoria (usuario_id, acao, detalhes, data_hora) VALUES (?, ?, ?, ?)",
            (int(current_user.id), acao, detalhes[:500], datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def exigir_perfis(*perfis):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if not current_user.tem_perfil(*perfis):
                flash("Você não tem permissão para realizar esta ação.", "danger")
                return redirect(url_for("index"))
            return func(*args, **kwargs)
        return wrapper
    return decorator


@app.before_request
def proteger_sistema():
    caminho = request.path.rstrip("/") or "/"
    if caminho in {"/login", "/configurar", "/logout", "/favicon.ico"} or caminho.startswith("/static/"):
        return None

    try:
        conn = conectar()
        total_usuarios = conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
        conn.close()
    except Exception:
        total_usuarios = 0

    if total_usuarios == 0:
        return redirect(url_for("configurar"))

    if not current_user.is_authenticated:
        return login_manager.unauthorized()

    # Todos os usuários autenticados podem alterar a própria senha.
    # Esta rota também precisa aceitar POST para perfis restritos.
    if caminho == "/minha-senha":
        return None

    # Administrador e Almoxarifado possuem acesso amplo; as rotas sensíveis
    # continuam protegidas individualmente pelos decoradores @exigir_perfis.
    if current_user.tem_perfil("admin", "almoxarifado"):
        return None

    # Técnico: o conjunto abaixo é deliberadamente limitado. Qualquer rota
    # administrativa ou de configuração que não esteja aqui deve ser bloqueada
    # também pelo decorador da própria rota.
    if current_user.tem_perfil("tecnico"):
        permitidas_tecnico = (
            caminho == "/"
            or caminho == "/buscar"
            or caminho == "/equipamentos"
            or caminho == "/tecnicos"
            or caminho == "/movimentacoes"
            or caminho in {"/movimentacao/entrada", "/movimentacao/saida", "/movimentacao/macs-disponiveis"}
            or caminho == "/agendamentos"
            or caminho.startswith("/agendamentos/")
            or caminho == "/defeitos"
            or caminho.startswith("/defeitos/")
            or caminho == "/kits-preventivos"
            or caminho.startswith("/kits-preventivos/")
            or caminho.startswith("/equipamentos/")
            or caminho.startswith("/mac/")
        )
        if permitidas_tecnico:
            return None
        flash("Você não tem permissão para acessar esta área.", "danger")
        return redirect(url_for("index"))

    # Consulta: somente leitura nas áreas permitidas.
    if current_user.tem_perfil("consulta"):
        permitidas_consulta = {"/", "/buscar", "/equipamentos", "/movimentacoes", "/agendamentos", "/defeitos", "/relatorios"}
        if caminho in permitidas_consulta or caminho.startswith("/mac/") or caminho.startswith("/equipamentos/"):
            if request.method == "POST":
                flash("Seu perfil é somente para consulta.", "danger")
                return redirect(url_for("index"))
            return None
        flash("Você não tem permissão para acessar esta área.", "danger")
        return redirect(url_for("index"))

    return None


@app.after_request
def auditar_requisicao(response):
    if current_user.is_authenticated and response.status_code < 400:
        caminho = request.path.rstrip("/") or "/"
        rotas_mutacao = {
            "/tecnicos/novo", "/equipamentos/novo", "/movimentacao/entrada",
            "/movimentacao/saida", "/agendamentos", "/defeitos", "/kits-preventivos", "/backup"
        }
        if request.method == "POST" or any(caminho.startswith(r) for r in rotas_mutacao if r != "/backup"):
            if caminho != "/login" and caminho != "/configurar":
                registrar_auditoria(request.method + " " + caminho, "Operação concluída")
    return response


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "almoxarifado.db"
BACKUP_DIR = BASE_DIR / "backups"

BACKUP_DIR.mkdir(exist_ok=True)


# =========================================================
# BANCO DE DADOS
# =========================================================

def conectar():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def inicializar_banco():
    conn = conectar()

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tecnicos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL UNIQUE,
            ativo INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS equipamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            categoria TEXT,
            fabricante TEXT,
            modelo TEXT,
            possui_mac INTEGER NOT NULL DEFAULT 0,
            estoque_minimo INTEGER NOT NULL DEFAULT 0,
            estoque_inicial INTEGER NOT NULL DEFAULT 0,
            criado_em TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS unidades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            equipamento_id INTEGER NOT NULL,
            mac TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'estoque',
            tecnico_id INTEGER,
            FOREIGN KEY (equipamento_id) REFERENCES equipamentos(id),
            FOREIGN KEY (tecnico_id) REFERENCES tecnicos(id)
        );

        CREATE TABLE IF NOT EXISTS movimentacoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            equipamento_id INTEGER NOT NULL,
            tipo TEXT NOT NULL,
            quantidade INTEGER NOT NULL DEFAULT 1,
            mac TEXT,
            tecnico_id INTEGER,
            observacao TEXT,
            data TEXT NOT NULL,
            FOREIGN KEY (equipamento_id) REFERENCES equipamentos(id),
            FOREIGN KEY (tecnico_id) REFERENCES tecnicos(id)
        );

        CREATE TABLE IF NOT EXISTS agendamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tecnico_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            observacao TEXT,
            status TEXT NOT NULL DEFAULT 'aberto',
            criado_em TEXT NOT NULL,
            FOREIGN KEY (tecnico_id) REFERENCES tecnicos(id)
        );

        CREATE TABLE IF NOT EXISTS agendamento_itens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agendamento_id INTEGER NOT NULL,
            equipamento_id INTEGER NOT NULL,
            quantidade INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (agendamento_id) REFERENCES agendamentos(id) ON DELETE CASCADE,
            FOREIGN KEY (equipamento_id) REFERENCES equipamentos(id)
        );

        CREATE TABLE IF NOT EXISTS defeitos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            equipamento_id INTEGER NOT NULL,
            mac TEXT,
            descricao TEXT NOT NULL,
            data TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'aberto',
            tecnico_id INTEGER,
            FOREIGN KEY (equipamento_id) REFERENCES equipamentos(id),
            FOREIGN KEY (tecnico_id) REFERENCES tecnicos(id)
        );

        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            usuario TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            perfil TEXT NOT NULL DEFAULT 'consulta',
            ativo INTEGER NOT NULL DEFAULT 1,
            criado_em TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            acao TEXT NOT NULL,
            detalhes TEXT,
            data_hora TEXT NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        );
    """)

    # Migrações seguras para bancos já existentes.
    colunas_usuarios = {row[1] for row in conn.execute("PRAGMA table_info(usuarios)").fetchall()}
    if "tecnico_id" not in colunas_usuarios:
        conn.execute("ALTER TABLE usuarios ADD COLUMN tecnico_id INTEGER")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS fechamentos_semanais (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tecnico_id INTEGER NOT NULL,
            semana_inicio TEXT NOT NULL,
            semana_fim TEXT NOT NULL,
            fechado_por INTEGER,
            fechado_em TEXT NOT NULL,
            UNIQUE(tecnico_id, semana_inicio),
            FOREIGN KEY (tecnico_id) REFERENCES tecnicos(id),
            FOREIGN KEY (fechado_por) REFERENCES usuarios(id)
        )
    """)

    colunas_fech = {row[1] for row in conn.execute("PRAGMA table_info(fechamentos_semanais)").fetchall()}
    if "ultimo_movimento_id" not in colunas_fech:
        conn.execute("ALTER TABLE fechamentos_semanais ADD COLUMN ultimo_movimento_id INTEGER")
    if "ultimo_kit_movimento_id" not in colunas_fech:
        conn.execute("ALTER TABLE fechamentos_semanais ADD COLUMN ultimo_kit_movimento_id INTEGER")

    # Histórico detalhado: data + hora exatas de cada movimentação.
    colunas_mov = {row[1] for row in conn.execute("PRAGMA table_info(movimentacoes)").fetchall()}
    if "data_hora" not in colunas_mov:
        conn.execute("ALTER TABLE movimentacoes ADD COLUMN data_hora TEXT")
    conn.execute("UPDATE movimentacoes SET data_hora = COALESCE(data_hora, data || ' 00:00:00') WHERE data_hora IS NULL OR data_hora = ''")

    conn.executescript("""
        CREATE TRIGGER IF NOT EXISTS trg_movimentacoes_data_hora
        AFTER INSERT ON movimentacoes
        WHEN NEW.data_hora IS NULL OR NEW.data_hora = ''
        BEGIN
            UPDATE movimentacoes
               SET data_hora = datetime('now','localtime')
             WHERE id = NEW.id;
        END;
    """)

    # Kits preventivos: cada técnico possui um kit próprio, com quantidade padrão
    # e quantidade atual. A movimentação de renovação é registrada separadamente.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kits_preventivos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tecnico_id INTEGER NOT NULL UNIQUE,
            criado_em TEXT NOT NULL,
            FOREIGN KEY (tecnico_id) REFERENCES tecnicos(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS kit_preventivo_itens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kit_id INTEGER NOT NULL,
            equipamento_id INTEGER NOT NULL,
            quantidade_padrao INTEGER NOT NULL DEFAULT 0,
            quantidade_atual INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (kit_id) REFERENCES kits_preventivos(id) ON DELETE CASCADE,
            FOREIGN KEY (equipamento_id) REFERENCES equipamentos(id),
            UNIQUE(kit_id, equipamento_id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS kit_preventivo_movimentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kit_id INTEGER NOT NULL,
            equipamento_id INTEGER NOT NULL,
            tipo TEXT NOT NULL,
            quantidade INTEGER NOT NULL DEFAULT 0,
            mac TEXT,
            usuario_id INTEGER,
            data TEXT NOT NULL,
            observacao TEXT,
            FOREIGN KEY (kit_id) REFERENCES kits_preventivos(id) ON DELETE CASCADE,
            FOREIGN KEY (equipamento_id) REFERENCES equipamentos(id),
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    """)

    # Migração segura para bancos já existentes: adiciona o MAC ao histórico do kit.
    colunas_kit_mov = {row[1] for row in conn.execute("PRAGMA table_info(kit_preventivo_movimentos)").fetchall()}
    if "mac" not in colunas_kit_mov:
        conn.execute("ALTER TABLE kit_preventivo_movimentos ADD COLUMN mac TEXT")

    # Histórico detalhado do kit preventivo também guarda data/hora.
    if "data_hora" not in colunas_kit_mov:
        conn.execute("ALTER TABLE kit_preventivo_movimentos ADD COLUMN data_hora TEXT")
    conn.execute("UPDATE kit_preventivo_movimentos SET data_hora = COALESCE(data_hora, data || ' 00:00:00') WHERE data_hora IS NULL OR data_hora = ''")

    conn.executescript("""
        CREATE TRIGGER IF NOT EXISTS trg_kit_movimentos_data_hora
        AFTER INSERT ON kit_preventivo_movimentos
        WHEN NEW.data_hora IS NULL OR NEW.data_hora = ''
        BEGIN
            UPDATE kit_preventivo_movimentos
               SET data_hora = datetime('now','localtime')
             WHERE id = NEW.id;
        END;
    """)

    conn.commit()
    conn.close()

inicializar_banco()


def semana_atual():
    """Retorna a semana corrente (segunda a domingo)."""
    hoje_date = date.today()
    inicio = hoje_date.fromordinal(hoje_date.toordinal() - hoje_date.weekday())
    fim = inicio.fromordinal(inicio.toordinal() + 6)
    return inicio.isoformat(), fim.isoformat()


def semana_anterior():
    hoje_date = date.today()
    inicio_atual = hoje_date.fromordinal(hoje_date.toordinal() - hoje_date.weekday())
    inicio = inicio_atual.fromordinal(inicio_atual.toordinal() - 7)
    fim = inicio.fromordinal(inicio.toordinal() + 6)
    return inicio.isoformat(), fim.isoformat()


def periodo_semana(inicio_param=None):
    """Valida uma segunda-feira informada e retorna o período completo."""
    inicio_atual, fim_atual = semana_atual()
    valor = (inicio_param or inicio_atual).strip()
    try:
        inicio_date = date.fromisoformat(valor)
    except ValueError:
        return inicio_atual, fim_atual
    # A semana do sistema sempre começa na segunda-feira.
    inicio_date = inicio_date.fromordinal(inicio_date.toordinal() - inicio_date.weekday())
    fim_date = inicio_date.fromordinal(inicio_date.toordinal() + 6)
    return inicio_date.isoformat(), fim_date.isoformat()


def formatar_data_hora(valor):
    """Converte YYYY-MM-DD HH:MM:SS para uma apresentação brasileira."""
    if not valor:
        return "-"
    texto = str(valor).replace("T", " ")
    try:
        dt = datetime.fromisoformat(texto)
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    except ValueError:
        return texto


def tecnico_do_usuario():
    if not current_user.is_authenticated:
        return None
    conn = conectar()
    row = conn.execute("""
        SELECT t.*
        FROM usuarios u
        JOIN tecnicos t ON t.id = u.tecnico_id
        WHERE u.id = ?
    """, (int(current_user.id),)).fetchone()
    conn.close()
    return row


def inicializar_autenticacao():
    conn = conectar()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            usuario TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            perfil TEXT NOT NULL DEFAULT 'consulta',
            ativo INTEGER NOT NULL DEFAULT 1,
            criado_em TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            acao TEXT NOT NULL,
            detalhes TEXT,
            data_hora TEXT NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS usuario_perfis (
            usuario_id INTEGER NOT NULL,
            perfil TEXT NOT NULL,
            PRIMARY KEY (usuario_id, perfil),
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
        )
    """)

    # Migração: usuários antigos passam a ter o perfil atual também na nova tabela.
    usuarios_existentes = conn.execute("SELECT id, perfil FROM usuarios").fetchall()
    for u in usuarios_existentes:
        if u["perfil"] in PERFIS:
            conn.execute("INSERT OR IGNORE INTO usuario_perfis (usuario_id, perfil) VALUES (?, ?)", (u["id"], u["perfil"]))
    conn.commit()
    conn.close()


inicializar_autenticacao()


# =========================================================
# FUNÇÕES AUXILIARES
# =========================================================

def hoje():
    return date.today().isoformat()


def estoque_equipamento(conn, equipamento_id):
    equipamento = conn.execute(
        "SELECT * FROM equipamentos WHERE id = ?",
        (equipamento_id,)
    ).fetchone()

    if not equipamento:
        return 0

    if equipamento["possui_mac"]:
        return conn.execute("""
            SELECT COUNT(*)
            FROM unidades
            WHERE equipamento_id = ?
              AND status = 'estoque'
        """, (equipamento_id,)).fetchone()[0]

    entrada = conn.execute("""
        SELECT COALESCE(SUM(quantidade), 0)
        FROM movimentacoes
        WHERE equipamento_id = ?
          AND tipo = 'entrada'
    """, (equipamento_id,)).fetchone()[0]

    saida = conn.execute("""
        SELECT COALESCE(SUM(quantidade), 0)
        FROM movimentacoes
        WHERE equipamento_id = ?
          AND tipo = 'saida'
    """, (equipamento_id,)).fetchone()[0]

    return entrada - saida


def reservado_equipamento(conn, equipamento_id):
    """Quantidade já comprometida e que não deve ser entregue novamente.

    Além de agendamentos, itens sem MAC que estão fisicamente reservados em
    kits preventivos entram aqui. A baixa definitiva do estoque acontece
    somente quando o item do kit é consumido.
    """
    agendado = conn.execute("""
        SELECT COALESCE(SUM(ai.quantidade), 0)
        FROM agendamento_itens ai
        JOIN agendamentos a ON a.id = ai.agendamento_id
        WHERE ai.equipamento_id = ?
          AND a.status = 'aberto'
          AND a.data >= ?
    """, (equipamento_id, hoje())).fetchone()[0]
    kit = conn.execute("""
        SELECT COALESCE(SUM(i.quantidade_atual), 0)
        FROM kit_preventivo_itens i
        JOIN kits_preventivos k ON k.id = i.kit_id
        WHERE i.equipamento_id = ?
    """, (equipamento_id,)).fetchone()[0]
    return int(agendado or 0) + int(kit or 0)


def nome_tecnico(conn, tecnico_id):
    if not tecnico_id:
        return "-"
    tecnico = conn.execute(
        "SELECT nome FROM tecnicos WHERE id = ?",
        (tecnico_id,)
    ).fetchone()
    return tecnico["nome"] if tecnico else "-"


# =========================================================
# ESTILO / HTML BASE
# =========================================================

CSS = """
<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #0b1220;
    color: #e5e7eb;
}

a {
    color: inherit;
    text-decoration: none;
}

.topbar {
    background: #111827;
    border-bottom: 1px solid #263244;
    padding: 15px 25px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 20;
}

.logo {
    font-size: 21px;
    font-weight: bold;
    color: #f97316;
}

.logo span {
    color: #fff;
}

.menu {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
}

.menu a {
    padding: 9px 12px;
    border-radius: 8px;
    color: #cbd5e1;
    font-size: 14px;
}

.menu a:hover {
    background: #1f2937;
    color: #fff;
}

.menu-group {
    position: relative;
}

.menu-group summary {
    list-style: none;
    cursor: pointer;
    padding: 9px 12px;
    border-radius: 8px;
    color: #cbd5e1;
    font-size: 14px;
    user-select: none;
}

.menu-group summary::-webkit-details-marker {
    display: none;
}

.menu-group summary::after {
    content: ' ▾';
    font-size: 11px;
    color: #94a3b8;
}

.menu-group summary:hover,
.menu-group[open] summary {
    background: #1f2937;
    color: #fff;
}

.menu-dropdown {
    position: absolute;
    top: calc(100% + 6px);
    left: 0;
    min-width: 190px;
    padding: 6px;
    background: #111827;
    border: 1px solid #334155;
    border-radius: 10px;
    box-shadow: 0 14px 35px rgba(0,0,0,.35);
    z-index: 50;
}

.menu-dropdown a {
    display: block;
    width: 100%;
}

.menu-divider {
    height: 1px;
    background: #263244;
    margin: 5px 0;
}

.mobile-section {
    grid-column: 1 / -1;
    margin-top: 6px;
    padding: 7px 8px 4px;
    color: #f97316;
    font-size: 12px;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: .05em;
}

.mobile-user {
    grid-column: 1 / -1;
    padding: 10px 8px;
    color: #93c5fd;
    font-size: 13px;
    border-top: 1px solid #263244;
    margin-top: 6px;
}

.container {
    max-width: 1400px;
    margin: auto;
    padding: 25px;
}

h1 {
    margin-top: 0;
}

h2 {
    margin-top: 0;
}

.grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
}

.card {
    background: #111827;
    border: 1px solid #263244;
    border-radius: 12px;
    padding: 20px;
}

.card .number {
    font-size: 32px;
    font-weight: bold;
    margin-top: 8px;
}

.muted {
    color: #94a3b8;
}

.orange {
    color: #f97316;
}

.green {
    color: #22c55e;
}

.red {
    color: #ef4444;
}

.yellow {
    color: #eab308;
}

.blue {
    color: #38bdf8;
}

.toolbar {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 20px;
}

input,
select,
textarea {
    width: 100%;
    background: #0f172a;
    border: 1px solid #334155;
    color: #fff;
    padding: 11px;
    border-radius: 8px;
}

textarea {
    min-height: 100px;
    resize: vertical;
}

button,
.btn {
    border: 0;
    background: #f97316;
    color: white;
    padding: 10px 15px;
    border-radius: 8px;
    cursor: pointer;
    display: inline-block;
}

button:hover,
.btn:hover {
    opacity: .9;
}

.btn-secondary {
    background: #334155;
}

.btn-green {
    background: #16a34a;
}

.btn-red {
    background: #dc2626;
}

.btn-blue {
    background: #0284c7;
}

.btn-yellow {
    background: #ca8a04;
}

.form-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 15px;
}

.form-group {
    margin-bottom: 12px;
}

.form-group label {
    display: block;
    margin-bottom: 6px;
    color: #cbd5e1;
}

.full {
    grid-column: 1 / -1;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    border-bottom: 1px solid #263244;
    padding: 12px 9px;
    text-align: left;
    vertical-align: middle;
}

th {
    color: #94a3b8;
    font-size: 13px;
}

tr:hover {
    background: #151f31;
}

.badge {
    display: inline-block;
    padding: 5px 9px;
    border-radius: 20px;
    font-size: 12px;
    background: #334155;
}

.badge-green {
    background: #14532d;
    color: #86efac;
}

.badge-red {
    background: #7f1d1d;
    color: #fecaca;
}

.badge-yellow {
    background: #713f12;
    color: #fde68a;
}

.badge-blue {
    background: #164e63;
    color: #a5f3fc;
}

.alert {
    padding: 13px;
    border-radius: 8px;
    margin-bottom: 15px;
    background: #172033;
    border: 1px solid #334155;
}

.alert-danger {
    border-color: #7f1d1d;
    background: #2a1115;
}

.alert-success {
    border-color: #166534;
    background: #0d2616;
}

.actions {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
}

.section {
    margin-top: 25px;
}

.search {
    max-width: 500px;
}

.empty {
    text-align: center;
    padding: 30px;
    color: #64748b;
}

.small {
    font-size: 13px;
}

.stat-row {
    display: flex;
    justify-content: space-between;
    gap: 15px;
}

@media (max-width: 900px) {
    .grid {
        grid-template-columns: repeat(2, 1fr);
    }

    .form-grid {
        grid-template-columns: 1fr;
    }

    .full {
        grid-column: auto;
    }

    .topbar {
        align-items: flex-start;
        gap: 15px;
        flex-direction: column;
    }
}

@media (max-width: 600px) {
    .topbar {
        padding: 12px 14px;
        position: sticky;
    }

    .logo {
        font-size: 17px;
    }

    .menu {
        display: none;
    }

    .mobile-menu {
        display: block;
        width: 100%;
    }

    .mobile-menu summary {
        list-style: none;
        cursor: pointer;
        background: #1f2937;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 10px 12px;
        color: #fff;
        text-align: center;
    }

    .mobile-menu summary::-webkit-details-marker {
        display: none;
    }

    .mobile-links {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 7px;
        margin-top: 8px;
    }

    .mobile-links a {
        background: #172033;
        border: 1px solid #263244;
        border-radius: 8px;
        padding: 10px 8px;
        text-align: center;
        font-size: 13px;
    }

    .mobile-user {
        grid-column: 1 / -1;
        color: #a5f3fc;
        font-size: 12px;
        padding: 4px;
        text-align: center;
    }

    .container {
        padding: 12px;
    }

    .grid {
        grid-template-columns: 1fr;
        gap: 10px;
    }

    .card {
        padding: 15px;
        border-radius: 10px;
    }

    .card .number {
        font-size: 27px;
    }

    h1 {
        font-size: 24px;
    }

    h2 {
        font-size: 19px;
    }

    .stat-row {
        align-items: center;
        flex-wrap: wrap;
    }

    .toolbar {
        flex-direction: column;
    }

    .toolbar > * {
        width: 100%;
    }

    .actions {
        flex-direction: column;
        align-items: stretch;
    }

    .actions .btn,
    .actions button {
        width: 100%;
        text-align: center;
    }

    button,
    .btn {
        min-height: 42px;
    }

    input,
    select,
    textarea {
        font-size: 16px;
    }

    table {
        font-size: 13px;
        min-width: 650px;
    }

    th,
    td {
        padding: 8px 7px;
        white-space: nowrap;
    }

    .table-wrap {
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        border-radius: 8px;
    }
}

@media (min-width: 601px) {
    .mobile-menu {
        display: none;
    }
}
.mac-check-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;margin-top:8px;max-height:260px;overflow:auto;padding:8px;border:1px solid #d7dce2;border-radius:10px;background:#fafafa}.mac-check-item{display:flex;align-items:center;gap:8px;padding:9px 10px;border:1px solid #e1e5ea;border-radius:8px;background:#fff;cursor:pointer}.mac-check-item input{width:auto;margin:0}.mac-check-item span{font-family:monospace;letter-spacing:.3px}
</style>
"""


BASE_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ titulo }} - Speednet</title>
""" + CSS + """
</head>
<body>

<div class="topbar">
    <div class="logo">SPEEDNET <span>ALMOXARIFADO</span></div>

    <div class="menu">
        <details class="menu-group">
            <summary>Início</summary>
            <div class="menu-dropdown">
                <a href="{{ url_for('index') }}">🏠 Dashboard</a>
                <a href="{{ url_for('buscar') }}">🔎 Busca geral</a>
            </div>
        </details>

        <details class="menu-group">
            <summary>Estoque</summary>
            <div class="menu-dropdown">
                <a href="{{ url_for('equipamentos') }}">📦 Equipamentos</a>
                {% if current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
                    <a href="{{ url_for('entrada') }}">📥 Entrada</a>
                    <a href="{{ url_for('saida') }}">📤 Saída</a>
                {% endif %}
                <a href="{{ url_for('movimentacoes') }}">📋 Movimentações</a>
               
            </div>
        </details>

        <details class="menu-group">
            <summary>Operação</summary>
            <div class="menu-dropdown">
                {% if current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
                    <a href="{{ url_for('tecnicos') }}">👨‍🔧 Técnicos</a>
                {% endif %}
                <a href="{{ url_for('agendamentos') }}">📅 Agendamentos</a>
                {% if current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
                    <a href="{{ url_for('kits_preventivos') }}">🧰 Meu kit preventivo{% if current_user.tem_perfil('admin', 'almoxarifado') %} / Kits{% endif %}</a>
                {% endif %}
                {% if current_user.tem_perfil('admin', 'almoxarifado') %}
                    <a href="{{ url_for('fechamento_semanal') }}">🗓️ Fechamento semanal</a>
                {% endif %}
            </div>
        </details>

        <details class="menu-group">
            <summary>Manutenção</summary>
            <div class="menu-dropdown">
                <a href="{{ url_for('defeitos') }}">🔧 Equipamentos com defeito</a>
            </div>
        </details>

        {% if current_user.tem_perfil('admin', 'almoxarifado', 'consulta') %}
        <details class="menu-group">
            <summary>Relatórios</summary>
            <div class="menu-dropdown">
                <a href="{{ url_for('relatorios') }}">📊 Relatórios</a>
            </div>
        </details>
        {% endif %}

        {% if current_user.is_authenticated and current_user.tem_perfil('admin') %}
        <details class="menu-group">
            <summary>Administração</summary>
            <div class="menu-dropdown">
                <a href="{{ url_for('usuarios') }}">👥 Usuários</a>
                <a href="{{ url_for('auditoria') }}">🧾 Auditoria</a>
                <a href="{{ url_for('backup') }}">💾 Backup</a>
            </div>
        </details>
        {% elif current_user.tem_perfil('almoxarifado') %}
        <details class="menu-group">
            <summary>Administração</summary>
            <div class="menu-dropdown">
                <a href="{{ url_for('backup') }}">💾 Backup</a>
            </div>
        </details>
        {% endif %}

        {% if current_user.is_authenticated %}
        <details class="menu-group">
            <summary>👤 {{ current_user.nome }}</summary>
            <div class="menu-dropdown">
                <a href="{{ url_for('minha_senha') }}">🔐 Minha senha</a>
                <div class="menu-divider"></div>
                <a href="{{ url_for('logout') }}">↪ Sair</a>
            </div>
        </details>
        {% endif %}
    </div>

    <details class="mobile-menu">
        <summary>☰ Menu</summary>
        <div class="mobile-links">
            <div class="mobile-section">Início</div>
            <a href="{{ url_for('index') }}">🏠 Dashboard</a>
            <a href="{{ url_for('buscar') }}">🔎 Busca geral</a>

            <div class="mobile-section">Estoque</div>
            <a href="{{ url_for('equipamentos') }}">📦 Equipamentos</a>
            {% if current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
                <a href="{{ url_for('entrada') }}">📥 Entrada</a>
                <a href="{{ url_for('saida') }}">📤 Saída</a>
            {% endif %}
            <a href="{{ url_for('movimentacoes') }}">📋 Movimentações</a>
            <a href="{{ url_for('equipamentos') }}#macs">🔢 MACs</a>

            <div class="mobile-section">Operação</div>
            {% if current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
                <a href="{{ url_for('tecnicos') }}">👨‍🔧 Técnicos</a>
            {% endif %}
            <a href="{{ url_for('agendamentos') }}">📅 Agendamentos</a>
            {% if current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
                <a href="{{ url_for('kits_preventivos') }}">🧰 Meu kit preventivo{% if current_user.tem_perfil('admin', 'almoxarifado') %} / Kits{% endif %}</a>
            {% endif %}
            {% if current_user.tem_perfil('admin', 'almoxarifado') %}
                <a href="{{ url_for('fechamento_semanal') }}">🗓️ Fechamento semanal</a>
            {% endif %}

            <div class="mobile-section">Manutenção</div>
            <a href="{{ url_for('defeitos') }}">🔧 Equipamentos com defeito</a>

            {% if current_user.tem_perfil('admin', 'almoxarifado', 'consulta') %}
                <div class="mobile-section">Relatórios</div>
                <a href="{{ url_for('relatorios') }}">📊 Relatórios</a>
            {% endif %}
            {% if current_user.is_authenticated and current_user.tem_perfil('admin') %}
                <a href="{{ url_for('auditoria') }}">🧾 Auditoria</a>
            {% endif %}

            {% if current_user.is_authenticated and current_user.tem_perfil('admin') %}
                <div class="mobile-section">Administração</div>
                <a href="{{ url_for('usuarios') }}">👥 Usuários</a>
                <a href="{{ url_for('auditoria') }}">🧾 Auditoria</a>
                <a href="{{ url_for('backup') }}">💾 Backup</a>
            {% elif current_user.tem_perfil('almoxarifado') %}
                <div class="mobile-section">Administração</div>
                <a href="{{ url_for('backup') }}">💾 Backup</a>
            {% endif %}

            {% if current_user.is_authenticated %}
                <div class="mobile-user">{{ current_user.nome }} · {{ PERFIS[current_user.perfil] if current_user.perfil in PERFIS else current_user.perfil }}</div>
                <a href="{{ url_for('minha_senha') }}">🔐 Minha senha</a>
                <a href="{{ url_for('logout') }}">↪ Sair</a>
            {% endif %}
        </div>
    </details>
</div>

<div class="container">

{% with messages = get_flashed_messages(with_categories=true) %}
    {% for categoria, mensagem in messages %}
        <div class="alert {% if categoria == 'danger' %}alert-danger{% elif categoria == 'success' %}alert-success{% endif %}">
            {{ mensagem }}
        </div>
    {% endfor %}
{% endwith %}

{{ conteudo|safe }}

</div>

</body>
</html>
"""


def pagina(titulo, conteudo, **contexto):
    # O PERFIS é usado tanto no conteúdo da página quanto no menu/base.
    # Colocamos a variável uma única vez no contexto para evitar o erro
    # de argumento duplicado do render_template_string.
    contexto = dict(contexto)
    contexto["PERFIS"] = PERFIS

    conteudo_renderizado = render_template_string(
        conteudo,
        **contexto
    )

    contexto_base = dict(contexto)
    contexto_base["titulo"] = titulo
    contexto_base["conteudo"] = conteudo_renderizado

    return render_template_string(
        BASE_HTML,
        **contexto_base
    )


# =========================================================
# AUTENTICAÇÃO / USUÁRIOS
# =========================================================

AUTH_CSS = """
<style>
body { margin:0; font-family:Arial,Helvetica,sans-serif; background:#0b1220; color:#e5e7eb; }
.auth-wrap { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }
.auth-card { width:100%; max-width:430px; background:#111827; border:1px solid #263244; border-radius:16px; padding:30px; box-shadow:0 20px 50px rgba(0,0,0,.35); }
.auth-logo { text-align:center; font-size:26px; font-weight:bold; color:#f97316; margin-bottom:6px; }
.auth-logo span { color:#fff; }
.auth-sub { text-align:center; color:#94a3b8; margin-bottom:25px; }
.auth-card label { display:block; margin:12px 0 6px; color:#cbd5e1; }
.auth-card input, .auth-card select { width:100%; box-sizing:border-box; background:#0f172a; border:1px solid #334155; color:#fff; padding:12px; border-radius:8px; }
.auth-card button { width:100%; border:0; background:#f97316; color:#fff; padding:12px; border-radius:8px; cursor:pointer; margin-top:18px; font-weight:bold; }
.auth-alert { padding:12px; border-radius:8px; margin-bottom:12px; background:#2a1115; border:1px solid #7f1d1d; color:#fecaca; }
</style>
"""


def auth_page(titulo, conteudo):
    return render_template_string("""
    <!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ titulo }} - Speednet</title>""" + AUTH_CSS + """</head><body>
    <div class="auth-wrap"><div class="auth-card">{{ conteudo|safe }}</div></div>
    </body></html>""", titulo=titulo, conteudo=render_template_string(conteudo))


@app.route("/configurar", methods=["GET", "POST"])
def configurar():
    conn = conectar()
    total = conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
    conn.close()
    if total > 0:
        return redirect(url_for("login"))

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        usuario = request.form.get("usuario", "").strip().lower()
        senha = request.form.get("senha", "")
        confirmar = request.form.get("confirmar", "")
        if not nome or not usuario or not senha:
            flash("Preencha todos os campos.", "danger")
        elif len(senha) < 6:
            flash("A senha precisa ter pelo menos 6 caracteres.", "danger")
        elif senha != confirmar:
            flash("As senhas não conferem.", "danger")
        else:
            conn = conectar()
            conn.execute("INSERT INTO usuarios (nome, usuario, senha_hash, perfil, ativo, criado_em) VALUES (?, ?, ?, 'admin', 1, ?)",
                         (nome, usuario, password_hasher.hash(senha), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()
            flash("Administrador criado. Agora faça login.", "success")
            return redirect(url_for("login"))

    html = """
    <div class="auth-logo">SPEEDNET <span>ALMOXARIFADO</span></div>
    <div class="auth-sub">Configuração inicial do sistema</div>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for categoria, mensagem in messages %}<div class="auth-alert">{{ mensagem }}</div>{% endfor %}
    {% endwith %}
    <form method="post">
      <label>Nome</label><input name="nome" required autofocus>
      <label>Usuário</label><input name="usuario" required autocomplete="username">
      <label>Senha</label><input type="password" name="senha" required autocomplete="new-password">
      <label>Confirmar senha</label><input type="password" name="confirmar" required autocomplete="new-password">
      <button type="submit">Criar administrador</button>
    </form>
    """
    return auth_page("Configuração inicial", html)


@app.route("/login", methods=["GET", "POST"])
def login():
    conn = conectar()
    total = conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
    conn.close()
    if total == 0:
        return redirect(url_for("configurar"))

    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip().lower()
        senha = request.form.get("senha", "")
        conn = conectar()
        row = conn.execute("SELECT * FROM usuarios WHERE usuario = ? AND ativo = 1", (usuario,)).fetchone()
        conn.close()
        valido = False
        if row:
            try:
                password_hasher.verify(row["senha_hash"], senha)
                valido = True
            except (VerifyMismatchError, VerificationError):
                valido = False
        if valido:
            user = Usuario(row)
            login_user(user)
            registrar_auditoria("LOGIN", "Login realizado")
            destino = request.args.get("next")
            if not destino or not destino.startswith("/"):
                destino = url_for("index")
            return redirect(destino)
        flash("Usuário ou senha inválidos.", "danger")

    html = """
    <div class="auth-logo">SPEEDNET <span>ALMOXARIFADO</span></div>
    <div class="auth-sub">Acesso ao sistema</div>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for categoria, mensagem in messages %}<div class="auth-alert">{{ mensagem }}</div>{% endfor %}
    {% endwith %}
    <form method="post">
      <label>Usuário</label><input name="usuario" required autofocus autocomplete="username">
      <label>Senha</label><input type="password" name="senha" required autocomplete="current-password">
      <button type="submit">Entrar</button>
    </form>
    """
    return auth_page("Login", html)


@app.route("/logout")
@login_required
def logout():
    registrar_auditoria("LOGOUT", "Logout realizado")
    logout_user()
    return redirect(url_for("login"))


@app.route("/usuarios")
@login_required
@exigir_perfis("admin")
def usuarios():
    conn = conectar()
    lista = conn.execute("""
        SELECT u.*, t.nome AS tecnico_nome,
               (SELECT GROUP_CONCAT(up.perfil) FROM usuario_perfis up WHERE up.usuario_id = u.id) AS perfis
        FROM usuarios u
        LEFT JOIN tecnicos t ON t.id = u.tecnico_id
        ORDER BY u.ativo DESC, u.nome
    """).fetchall()
    conn.close()
    html = """
    <div class="stat-row"><h1>Usuários</h1><div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;"><a class="btn" href="{{ url_for('novo_usuario') }}">+ Novo usuário</a><form method="post" action="{{ url_for('limpar_dados_sistema') }}" style="display:inline;" onsubmit="return confirm('ATENÇÃO: isso apagará equipamentos, estoque, movimentações, agendamentos, defeitos, kits, fechamentos e técnicos não vinculados a usuários. Os usuários cadastrados e seus cargos/perfis serão mantidos. Deseja continuar?');"><button class="btn btn-red" type="submit">Limpar dados do sistema</button></form></div></div>
    <div class="card"><div class="table-wrap"><table>
    <tr><th>Nome</th><th>Usuário</th><th>Perfil</th><th>Técnico</th><th>Status</th><th>Ação</th></tr>
    {% for u in lista %}<tr>
      <td>{{ u.nome }}</td><td>{{ u.usuario }}</td>
      <td>
        {% if u.perfis %}{% for p in u.perfis.split(',') %}<span class="badge">{{ PERFIS.get(p, p) }}</span>{% endfor %}{% else %}<span class="muted">-</span>{% endif %}
      </td><td>{{ u.tecnico_nome or '-' }}</td>
      <td>{% if u.ativo %}<span class="badge badge-green">Ativo</span>{% else %}<span class="badge badge-red">Inativo</span>{% endif %}</td>
      <td>
        <a class="btn" href="{{ url_for('editar_usuario', id=u.id) }}">Editar</a>
        <a class="btn" href="{{ url_for('alterar_senha_usuario', id=u.id) }}">Alterar senha</a>
        {% if u.id != current_user.id|int %}
          <a class="btn {% if u.ativo %}btn-red{% else %}btn-green{% endif %}" href="{{ url_for('alternar_usuario', id=u.id) }}">{% if u.ativo %}Desativar{% else %}Ativar{% endif %}</a>
        {% else %}
          <span class="muted small">Usuário atual</span>
        {% endif %}
      </td>
    </tr>{% endfor %}
    </table></div></div>
    """
    return pagina("Usuários", html, lista=lista)


@app.route("/usuarios/limpar-dados", methods=["POST"])
@login_required
@exigir_perfis("admin")
def limpar_dados_sistema():
    """Limpa os dados operacionais, preservando usuários e seus perfis/cargos.

    Usuários e a tabela usuario_perfis nunca são apagados. Técnicos vinculados
    diretamente a usuários também são preservados para não quebrar o vínculo
    de quem possui o cargo de técnico.
    """
    conn = conectar()
    try:
        # Apaga primeiro as tabelas filhas para respeitar as chaves estrangeiras.
        tabelas = [
            "kit_preventivo_movimentos",
            "kit_preventivo_itens",
            "kits_preventivos",
            "agendamento_itens",
            "agendamentos",
            "defeitos",
            "unidades",
            "movimentacoes",
            "fechamentos_semanais",
            "equipamentos",
            # Auditoria também faz parte dos dados operacionais/históricos.
            "auditoria",
        ]

        for tabela in tabelas:
            conn.execute(f"DELETE FROM {tabela}")

        # Mantém somente os técnicos que continuam vinculados a algum usuário.
        conn.execute("DELETE FROM tecnicos WHERE id NOT IN (SELECT tecnico_id FROM usuarios WHERE tecnico_id IS NOT NULL)")

        # Zera os contadores das tabelas limpas quando o SQLite tiver sqlite_sequence.
        for tabela in tabelas:
            conn.execute("DELETE FROM sqlite_sequence WHERE name = ?", (tabela,))
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'tecnicos'")

        conn.commit()
        registrar_auditoria("LIMPEZA_SISTEMA", "Dados operacionais limpos; usuários e cargos/perfis preservados.")
        flash("Dados do sistema limpos. Usuários e seus cargos/perfis foram preservados.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Não foi possível limpar os dados: {e}", "danger")
    finally:
        conn.close()

    return redirect(url_for("usuarios"))


@app.route("/usuarios/novo", methods=["GET", "POST"])
@login_required
@exigir_perfis("admin")
def novo_usuario():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        usuario = request.form.get("usuario", "").strip().lower()
        senha = request.form.get("senha", "")
        perfis = [p for p in request.form.getlist("perfis") if p in PERFIS]
        if not perfis:
            perfis = ["consulta"]

        if not nome or not usuario or not senha:
            flash("Preencha todos os campos.", "danger")
            return redirect(url_for("novo_usuario"))

        if len(senha) < 6:
            flash("A senha precisa ter pelo menos 6 caracteres.", "danger")
            return redirect(url_for("novo_usuario"))

        conn = conectar()
        try:
            tecnico_id = None

            # Usuário com perfil Técnico vira técnico automaticamente.
            # Não é necessário criar/vincular um técnico separadamente.
            if "tecnico" in perfis:
                tecnico = conn.execute(
                    "SELECT id FROM tecnicos WHERE LOWER(TRIM(nome)) = LOWER(TRIM(?)) LIMIT 1",
                    (nome,)
                ).fetchone()

                if tecnico:
                    tecnico_id = tecnico["id"]
                    conn.execute(
                        "UPDATE tecnicos SET ativo = 1 WHERE id = ?",
                        (tecnico_id,)
                    )
                else:
                    cursor = conn.execute(
                        "INSERT INTO tecnicos (nome, ativo) VALUES (?, 1)",
                        (nome,)
                    )
                    tecnico_id = cursor.lastrowid

            conn.execute(
                """
                INSERT INTO usuarios
                    (nome, usuario, senha_hash, perfil, tecnico_id, ativo, criado_em)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    nome,
                    usuario,
                    password_hasher.hash(senha),
                    perfis[0],
                    tecnico_id,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
            )

            novo_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.executemany("INSERT INTO usuario_perfis (usuario_id, perfil) VALUES (?, ?)", [(novo_id, p) for p in perfis])

            conn.commit()
            flash("Usuário criado com sucesso.", "success")
            registrar_auditoria(
                "CRIAR_USUARIO",
                f"Usuário: {usuario}; perfis: {", ".join(perfis)}"
            )

        except sqlite3.IntegrityError:
            conn.rollback()
            flash("Esse nome de usuário já existe.", "danger")
        finally:
            conn.close()

        return redirect(url_for("usuarios"))

    html = """
    <h1>Novo usuário</h1>
    <div class="card">
      <form method="post">
        <div class="form-grid">
          <div class="form-group">
            <label>Nome</label>
            <input name="nome" required>
          </div>
          <div class="form-group">
            <label>Usuário</label>
            <input name="usuario" required>
          </div>
          <div class="form-group">
            <label>Senha</label>
            <input type="password" name="senha" required>
          </div>
          <div class="form-group full">
            <label>Cargos / Perfis</label>
            <div style="display:flex;flex-wrap:wrap;gap:12px;margin-top:8px;">
              {% for chave,nome_perfil in PERFIS.items() %}
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" name="perfis" value="{{ chave }}" {% if chave == 'consulta' %}checked{% endif %}> {{ nome_perfil }}</label>
              {% endfor %}
            </div>
          </div>
        </div>

        <div class="muted small" style="margin-bottom:14px;">
          O usuário pode ter <strong>mais de um cargo</strong>. Se houver o cargo <strong>Técnico</strong>, o sistema cria ou reutiliza automaticamente o cadastro do técnico.
        </div>

        <button type="submit">Criar usuário</button>
        <a class="btn btn-secondary" href="{{ url_for('usuarios') }}">Cancelar</a>
      </form>
    </div>
    """
    return pagina("Novo usuário", html)


@app.route("/minha-senha", methods=["GET", "POST"])
@login_required
def minha_senha():
    if request.method == "POST":
        atual = request.form.get("senha_atual", "")
        nova = request.form.get("nova_senha", "")
        confirmar = request.form.get("confirmar", "")

        if not atual or not nova or not confirmar:
            flash("Preencha todos os campos.", "danger")
            return redirect(url_for("minha_senha"))

        if len(nova) < 6:
            flash("A nova senha precisa ter pelo menos 6 caracteres.", "danger")
            return redirect(url_for("minha_senha"))

        if nova != confirmar:
            flash("As novas senhas não conferem.", "danger")
            return redirect(url_for("minha_senha"))

        conn = conectar()
        row = conn.execute("SELECT senha_hash, usuario FROM usuarios WHERE id = ?", (int(current_user.id),)).fetchone()

        valido = False
        if row:
            try:
                password_hasher.verify(row["senha_hash"], atual)
                valido = True
            except (VerifyMismatchError, VerificationError):
                valido = False

        if not valido:
            conn.close()
            flash("A senha atual está incorreta.", "danger")
            return redirect(url_for("minha_senha"))

        conn.execute("UPDATE usuarios SET senha_hash = ? WHERE id = ?",
                     (password_hasher.hash(nova), int(current_user.id)))
        conn.commit()
        conn.close()
        registrar_auditoria("ALTERAR_PROPRIA_SENHA", f"Usuário: {current_user.usuario}")
        flash("Sua senha foi alterada com sucesso.", "success")
        return redirect(url_for("index"))

    html = """
    <h1>Minha senha</h1>
    <div class="card">
      <p class="muted">Usuário: <strong>{{ current_user.usuario }}</strong></p>
      <form method="post">
        <div class="form-grid">
          <div class="form-group full"><label>Senha atual</label><input type="password" name="senha_atual" required autocomplete="current-password"></div>
          <div class="form-group"><label>Nova senha</label><input type="password" name="nova_senha" minlength="6" required autocomplete="new-password"></div>
          <div class="form-group"><label>Confirmar nova senha</label><input type="password" name="confirmar" minlength="6" required autocomplete="new-password"></div>
        </div>
        <button type="submit">Alterar senha</button>
      </form>
    </div>
    """
    return pagina("Minha senha", html)


@app.route("/usuarios/<int:id>/senha", methods=["GET", "POST"])
@login_required
@exigir_perfis("admin")
def alterar_senha_usuario(id):
    conn = conectar()
    row = conn.execute("SELECT id, nome, usuario FROM usuarios WHERE id = ?", (id,)).fetchone()
    conn.close()

    if not row:
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for("usuarios"))

    if request.method == "POST":
        nova = request.form.get("nova_senha", "")
        confirmar = request.form.get("confirmar", "")

        if len(nova) < 6:
            flash("A nova senha precisa ter pelo menos 6 caracteres.", "danger")
            return redirect(url_for("alterar_senha_usuario", id=id))

        if nova != confirmar:
            flash("As senhas não conferem.", "danger")
            return redirect(url_for("alterar_senha_usuario", id=id))

        conn = conectar()
        conn.execute("UPDATE usuarios SET senha_hash = ? WHERE id = ?",
                     (password_hasher.hash(nova), id))
        conn.commit()
        conn.close()
        registrar_auditoria("REDEFINIR_SENHA", f"Usuário: {row['usuario']}")
        flash(f"Senha de {row['nome']} alterada com sucesso.", "success")
        return redirect(url_for("usuarios"))

    html = """
    <h1>Alterar senha</h1>
    <div class="card">
      <p><strong>{{ row.nome }}</strong> · {{ row.usuario }}</p>
      <form method="post">
        <div class="form-grid">
          <div class="form-group"><label>Nova senha</label><input type="password" name="nova_senha" minlength="6" required autocomplete="new-password"></div>
          <div class="form-group"><label>Confirmar nova senha</label><input type="password" name="confirmar" minlength="6" required autocomplete="new-password"></div>
        </div>
        <button type="submit">Salvar nova senha</button>
        <a class="btn btn-secondary" href="{{ url_for('usuarios') }}">Cancelar</a>
      </form>
    </div>
    """
    return pagina("Alterar senha", html, row=row)


@app.route("/usuarios/<int:id>/editar", methods=["GET", "POST"])
@login_required
@exigir_perfis("admin")
def editar_usuario(id):
    conn = conectar()
    row = conn.execute("SELECT * FROM usuarios WHERE id = ?", (id,)).fetchone()
    if not row:
        conn.close()
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for("usuarios"))

    perfis_atuais = {r["perfil"] for r in conn.execute("SELECT perfil FROM usuario_perfis WHERE usuario_id = ?", (id,)).fetchall()}
    if not perfis_atuais and row["perfil"] in PERFIS:
        perfis_atuais = {row["perfil"]}

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        usuario = request.form.get("usuario", "").strip().lower()
        perfis = [p for p in request.form.getlist("perfis") if p in PERFIS]
        tecnico_id = row["tecnico_id"]

        if not nome or not usuario or not perfis:
            conn.close()
            flash("Informe nome, usuário e pelo menos um cargo.", "danger")
            return redirect(url_for("editar_usuario", id=id))

        if id == int(current_user.id) and "admin" not in perfis:
            conn.close()
            flash("Você não pode remover o próprio cargo de Administrador.", "danger")
            return redirect(url_for("editar_usuario", id=id))

        try:
            existe = conn.execute("SELECT id FROM usuarios WHERE LOWER(usuario) = LOWER(?) AND id <> ?", (usuario, id)).fetchone()
            if existe:
                raise ValueError("Esse nome de usuário já existe.")

            if "tecnico" in perfis:
                tecnico = conn.execute("SELECT id FROM tecnicos WHERE LOWER(TRIM(nome)) = LOWER(TRIM(?)) LIMIT 1", (nome,)).fetchone()
                if tecnico:
                    tecnico_id = tecnico["id"]
                    conn.execute("UPDATE tecnicos SET nome = ?, ativo = 1 WHERE id = ?", (nome, tecnico_id))
                elif tecnico_id:
                    conn.execute("UPDATE tecnicos SET nome = ?, ativo = 1 WHERE id = ?", (nome, tecnico_id))
                else:
                    tecnico_id = conn.execute("INSERT INTO tecnicos (nome, ativo) VALUES (?, 1)", (nome,)).lastrowid
            else:
                if tecnico_id:
                    conn.execute("UPDATE tecnicos SET ativo = 0 WHERE id = ?", (tecnico_id,))
                tecnico_id = None

            conn.execute("UPDATE usuarios SET nome = ?, usuario = ?, perfil = ?, tecnico_id = ? WHERE id = ?", (nome, usuario, perfis[0], tecnico_id, id))
            conn.execute("DELETE FROM usuario_perfis WHERE usuario_id = ?", (id,))
            conn.executemany("INSERT INTO usuario_perfis (usuario_id, perfil) VALUES (?, ?)", [(id, p) for p in perfis])
            conn.commit()
            registrar_auditoria("EDITAR_USUARIO", f"Usuário: {usuario}; perfis: {', '.join(perfis)}")
            flash("Dados do usuário atualizados com sucesso.", "success")
            conn.close()
            return redirect(url_for("usuarios"))
        except ValueError as e:
            conn.rollback()
            flash(str(e), "danger")
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("Não foi possível atualizar os dados do usuário.", "danger")
        finally:
            conn.close()
        return redirect(url_for("editar_usuario", id=id))

    conn.close()
    html = """
    <h1>Editar usuário</h1>
    <div class="card">
      <form method="post">
        <div class="form-grid">
          <div class="form-group"><label>Nome</label><input name="nome" value="{{ row.nome }}" required></div>
          <div class="form-group"><label>Usuário</label><input name="usuario" value="{{ row.usuario }}" required></div>
          <div class="form-group full">
            <label>Cargos / Perfis</label>
            <div style="display:flex;flex-wrap:wrap;gap:12px;margin-top:8px;">
              {% for chave,nome_perfil in PERFIS.items() %}
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" name="perfis" value="{{ chave }}" {% if chave in perfis_atuais %}checked{% endif %}> {{ nome_perfil }}</label>
              {% endfor %}
            </div>
          </div>
        </div>
        <button type="submit">Salvar alterações</button>
        <a class="btn btn-secondary" href="{{ url_for('usuarios') }}">Cancelar</a>
      </form>
    </div>
    """
    return pagina("Editar usuário", html, row=row, perfis_atuais=perfis_atuais)


@app.route("/usuarios/<int:id>/excluir", methods=["POST"])
@login_required
@exigir_perfis("admin")
def excluir_usuario(id):
    if id == int(current_user.id):
        flash("Você não pode excluir o próprio usuário.", "danger")
        return redirect(url_for("usuarios"))

    conn = conectar()
    row = conn.execute("SELECT id, nome, usuario, tecnico_id FROM usuarios WHERE id = ?", (id,)).fetchone()
    if not row:
        conn.close()
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for("usuarios"))

    try:
        # Não apaga o técnico para preservar histórico de movimentações.
        conn.execute("DELETE FROM usuario_perfis WHERE usuario_id = ?", (id,))
        conn.execute("DELETE FROM usuarios WHERE id = ?", (id,))
        conn.commit()
        registrar_auditoria("EXCLUIR_USUARIO", f"Usuário excluído: {row['usuario']}")
        flash(f"Usuário {row['nome']} excluído com sucesso.", "success")
    except sqlite3.IntegrityError:
        conn.rollback()
        # Se houver registros históricos ligados ao usuário, desativa em vez de apagar.
        conn.execute("UPDATE usuarios SET ativo = 0 WHERE id = ?", (id,))
        conn.commit()
        registrar_auditoria("DESATIVAR_USUARIO", f"Usuário não pôde ser excluído e foi desativado: {row['usuario']}")
        flash("O usuário possui registros históricos e não pode ser apagado. Ele foi desativado para preservar o histórico.", "warning")
    finally:
        conn.close()
    return redirect(url_for("usuarios"))


@app.route("/usuarios/<int:id>/alternar")
@login_required
@exigir_perfis("admin")
def alternar_usuario(id):
    if id == int(current_user.id):
        flash("Você não pode desativar o próprio usuário.", "danger")
        return redirect(url_for("usuarios"))
    conn = conectar()
    row = conn.execute("SELECT ativo, usuario FROM usuarios WHERE id = ?", (id,)).fetchone()
    if row:
        novo = 0 if row["ativo"] else 1
        conn.execute("UPDATE usuarios SET ativo = ? WHERE id = ?", (novo, id))
        conn.commit()
        flash("Usuário atualizado.", "success")
        registrar_auditoria("ALTERAR_USUARIO", f"Usuário: {row['usuario']}; ativo: {novo}")
    conn.close()
    return redirect(url_for("usuarios"))


@app.route("/auditoria")
@login_required
@exigir_perfis("admin")
def auditoria():
    conn = conectar()
    lista = conn.execute("""
        SELECT a.*, u.nome, u.usuario FROM auditoria a
        LEFT JOIN usuarios u ON u.id = a.usuario_id
        ORDER BY a.id DESC LIMIT 300
    """).fetchall()
    conn.close()
    html = """
    <h1>Auditoria</h1><div class="card"><div class="table-wrap"><table>
    <tr><th>Data/Hora</th><th>Usuário</th><th>Ação</th><th>Detalhes</th></tr>
    {% for a in lista %}<tr><td>{{ a.data_hora }}</td><td>{{ a.nome or '-' }} ({{ a.usuario or '-' }})</td><td>{{ a.acao }}</td><td>{{ a.detalhes or '-' }}</td></tr>{% endfor %}
    </table></div></div>
    """
    return pagina("Auditoria", html, lista=lista)


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def index():
    conn = conectar()

    equipamentos = conn.execute(
        "SELECT COUNT(*) FROM equipamentos"
    ).fetchone()[0]

    tecnicos = conn.execute(
        "SELECT COUNT(*) FROM tecnicos WHERE ativo = 1"
    ).fetchone()[0]

    defeitos = conn.execute(
        "SELECT COUNT(*) FROM defeitos WHERE status = 'aberto'"
    ).fetchone()[0]

    agendamentos = conn.execute("""
        SELECT COUNT(*)
        FROM agendamentos
        WHERE status = 'aberto'
          AND data >= ?
    """, (hoje(),)).fetchone()[0]

    lista = conn.execute("""
        SELECT *
        FROM equipamentos
        ORDER BY nome
    """).fetchall()

    estoque_baixo = []

    for equipamento in lista:
        estoque = estoque_equipamento(conn, equipamento["id"])
        reservado = reservado_equipamento(conn, equipamento["id"])

        if estoque - reservado <= equipamento["estoque_minimo"]:
            estoque_baixo.append({
                "nome": equipamento["nome"],
                "estoque": estoque,
                "reservado": reservado,
                "minimo": equipamento["estoque_minimo"]
            })

    movimentos = conn.execute("""
        SELECT
            m.*,
            e.nome AS equipamento,
            t.nome AS tecnico
        FROM movimentacoes m
        JOIN equipamentos e ON e.id = m.equipamento_id
        LEFT JOIN tecnicos t ON t.id = m.tecnico_id
        ORDER BY m.id DESC
        LIMIT 8
    """).fetchall()

    tecnico_pessoal = None
    meus_movimentos = []
    meus_agendamentos = []
    if current_user.is_authenticated and current_user.tem_perfil("tecnico"):
        tecnico_pessoal = conn.execute("""
            SELECT t.* FROM usuarios u JOIN tecnicos t ON t.id = u.tecnico_id WHERE u.id = ?
        """, (int(current_user.id),)).fetchone()
        if tecnico_pessoal:
            meus_movimentos = conn.execute("""
                SELECT m.data, m.tipo, m.quantidade, m.mac, e.nome AS equipamento
                FROM movimentacoes m JOIN equipamentos e ON e.id = m.equipamento_id
                WHERE m.tecnico_id = ? ORDER BY m.id DESC LIMIT 6
            """, (tecnico_pessoal["id"],)).fetchall()
            meus_agendamentos = conn.execute("""
                SELECT a.id, a.data, a.status, a.observacao
                FROM agendamentos a WHERE a.tecnico_id = ? AND a.status = 'aberto'
                ORDER BY a.data, a.id DESC LIMIT 6
            """, (tecnico_pessoal["id"],)).fetchall()

    conn.close()

    html = """
    <h1>Dashboard</h1>

    <div class="grid">
        <div class="card">
            <div class="muted">Equipamentos</div>
            <div class="number blue">{{ equipamentos }}</div>
        </div>

        <div class="card">
            <div class="muted">Técnicos ativos</div>
            <div class="number green">{{ tecnicos }}</div>
        </div>

        <div class="card">
            <div class="muted">Defeitos abertos</div>
            <div class="number red">{{ defeitos }}</div>
        </div>

        <div class="card">
            <div class="muted">Agendamentos</div>
            <div class="number orange">{{ agendamentos }}</div>
        </div>
    </div>

    {% if current_user.tem_perfil('tecnico') %}
    <div class="section card">
        <div class="stat-row"><h2>Meu painel</h2><a class="btn" href="{{ url_for('agendamentos') }}">Novo agendamento</a></div>
        {% if tecnico_pessoal %}
            <p class="muted">Técnico vinculado: <strong>{{ tecnico_pessoal.nome }}</strong></p>
            <div class="grid">
                <div class="card"><div class="muted">Agendamentos abertos</div><div class="number orange">{{ meus_agendamentos|length }}</div></div>
                <div class="card"><div class="muted">Últimas movimentações</div><div class="number blue">{{ meus_movimentos|length }}</div></div>
            </div>
        {% else %}
            <div class="alert alert-danger">Seu usuário ainda não está vinculado a um técnico. Peça ao administrador para fazer o vínculo.</div>
        {% endif %}
    </div>
    {% endif %}

    <div class="section card">
        <div class="stat-row">
            <h2>Estoque baixo</h2>
            <a class="btn btn-secondary" href="{{ url_for('equipamentos') }}">Ver estoque</a>
        </div>

        {% if estoque_baixo %}
            <div class="table-wrap">
                <table>
                    <tr>
                        <th>Equipamento</th>
                        <th>Estoque</th>
                        <th>Reservado</th>
                        <th>Mínimo</th>
                    </tr>

                    {% for item in estoque_baixo %}
                    <tr>
                        <td>{{ item.nome }}</td>
                        <td class="red">{{ item.estoque }}</td>
                        <td>{{ item.reservado }}</td>
                        <td>{{ item.minimo }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        {% else %}
            <div class="empty">Nenhum equipamento abaixo do estoque mínimo.</div>
        {% endif %}
    </div>

    <div class="section card">
        <h2>Últimas movimentações</h2>

        {% if movimentos %}
        <div class="table-wrap">
            <table>
                <tr>
                    <th>Data</th>
                    <th>Tipo</th>
                    <th>Equipamento</th>
                    <th>Quantidade</th>
                    <th>MAC</th>
                    <th>Técnico</th>
                </tr>

                {% for m in movimentos %}
                <tr>
                    <td>{{ m.data }}</td>
                    <td>
                        {% if m.tipo == 'entrada' %}
                            <span class="badge badge-green">ENTRADA</span>
                        {% else %}
                            <span class="badge badge-red">SAÍDA</span>
                        {% endif %}
                    </td>
                    <td>{{ m.equipamento }}</td>
                    <td>{{ m.quantidade }}</td>
                    <td>{{ m.mac or '-' }}</td>
                    <td>{{ m.tecnico or '-' }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% else %}
            <div class="empty">Ainda não existem movimentações.</div>
        {% endif %}
    </div>
    """

    return pagina(
        "Dashboard",
        html,
        equipamentos=equipamentos,
        tecnicos=tecnicos,
        defeitos=defeitos,
        agendamentos=agendamentos,
        estoque_baixo=estoque_baixo,
        movimentos=movimentos,
        tecnico_pessoal=tecnico_pessoal,
        meus_movimentos=meus_movimentos,
        meus_agendamentos=meus_agendamentos
    )


# =========================================================
# BUSCA GERAL
# =========================================================

@app.route("/buscar")
def buscar():
    q = request.args.get("q", "").strip()
    resultados = []
    movimentos_tecnicos = []

    def normalizar(texto):
        texto = str(texto or "").lower()
        texto = unicodedata.normalize("NFD", texto)
        return "".join(c for c in texto if unicodedata.category(c) != "Mn")

    def campo_bate(campo, termos):
        """Busca por palavras inteiras, evitando falsos positivos como ONT em FONTE."""
        texto = normalizar(campo)
        for termo in termos:
            termo = normalizar(termo)
            if not termo:
                continue
            if not re.search(r"(?<![a-z0-9])" + re.escape(termo) + r"(?![a-z0-9])", texto):
                return False
        return True

    if q:
        conn = conectar()
        termos = [t for t in re.split(r"\s+", q) if t]

        # Equipamentos: busca por palavras, não por simples substring.
        # Assim "ONT" encontra "ONT V2", mas não encontra "FONTE".
        equipamentos_rows = conn.execute("""
            SELECT id, nome, categoria, fabricante, modelo
            FROM equipamentos
            ORDER BY nome
        """).fetchall()
        for r in equipamentos_rows:
            texto = " ".join([
                r["nome"] or "",
                r["categoria"] or "",
                r["fabricante"] or "",
                r["modelo"] or ""
            ])
            if campo_bate(texto, termos):
                resultados.append({
                    "tipo": "Equipamento",
                    "titulo": r["nome"],
                    "detalhe": f"{r['categoria'] or '-'} · {r['modelo'] or '-'}",
                    "url": url_for("equipamentos", q=r["nome"])
                })
                if len([x for x in resultados if x["tipo"] == "Equipamento"]) >= 20:
                    break

        # Técnicos: ao encontrar o técnico, a busca também mostra as
        # entradas e saídas dele logo abaixo dos resultados.
        tecnicos_encontrados = []
        for r in conn.execute("SELECT id, nome FROM tecnicos WHERE ativo = 1 ORDER BY nome").fetchall():
            if campo_bate(r["nome"], termos):
                tecnicos_encontrados.append(r)
                resultados.append({
                    "tipo": "Técnico",
                    "titulo": r["nome"],
                    "detalhe": "Entradas e saídas do técnico",
                    "url": url_for("movimentacoes", tecnico_id=r["id"])
                })

        # MAC: mantém a busca específica pelo MAC e também aceita parte dele.
        like_mac = f"%{q.upper()}%"
        for r in conn.execute("""
            SELECT u.id, u.mac, u.equipamento_id
            FROM unidades u
            WHERE UPPER(u.mac) LIKE ?
            ORDER BY u.mac
            LIMIT 20
        """, (like_mac,)).fetchall():
            eq = conn.execute("SELECT nome FROM equipamentos WHERE id = ?", (r["equipamento_id"],)).fetchone()
            resultados.append({
                "tipo": "MAC",
                "titulo": r["mac"],
                "detalhe": eq["nome"] if eq else "Equipamento",
                "url": url_for("macs", id=r["equipamento_id"])
            })

        # Histórico completo dos técnicos encontrados.
        for t in tecnicos_encontrados:
            movimentos = conn.execute("""
                SELECT
                    m.data,
                    m.tipo,
                    m.quantidade,
                    m.mac,
                    m.observacao,
                    e.nome AS equipamento
                FROM movimentacoes m
                JOIN equipamentos e ON e.id = m.equipamento_id
                WHERE m.tecnico_id = ?
                ORDER BY m.id DESC
            """, (t["id"],)).fetchall()
            movimentos_tecnicos.append({
                "tecnico": t["nome"],
                "tecnico_id": t["id"],
                "movimentos": movimentos
            })

        conn.close()

    html = """
    <div class="stat-row"><h1>Busca geral</h1></div>
    <div class="card">
        <form method="get" class="toolbar">
            <input class="search" name="q" value="{{ q }}" placeholder="Equipamento, MAC ou técnico...">
            <button type="submit">Pesquisar</button>
        </form>
    </div>

    <div class="section card">
      {% if q and resultados %}
        <div class="table-wrap">
          <table>
            <tr><th>Tipo</th><th>Resultado</th><th>Detalhes</th><th></th></tr>
            {% for r in resultados %}
            <tr>
              <td><span class="badge badge-blue">{{ r.tipo }}</span></td>
              <td><strong>{{ r.titulo }}</strong></td>
              <td>{{ r.detalhe }}</td>
              <td><a class="btn" href="{{ r.url }}">Abrir</a></td>
            </tr>
            {% endfor %}
          </table>
        </div>
      {% elif q %}
        <div class="empty">Nenhum resultado encontrado.</div>
      {% else %}
        <div class="empty">Digite algo para pesquisar.</div>
      {% endif %}
    </div>

    {% if movimentos_tecnicos %}
      {% for grupo in movimentos_tecnicos %}
      <div class="section card">
        <div class="stat-row">
          <h2 style="margin:0">Movimentações — {{ grupo.tecnico }}</h2>
          <a class="btn" href="{{ url_for('movimentacoes', tecnico_id=grupo.tecnico_id) }}">Abrir histórico completo</a>
        </div>

        {% if grupo.movimentos %}
        <div class="table-wrap">
          <table>
            <tr>
              <th>Data</th>
              <th>Tipo</th>
              <th>Equipamento</th>
              <th>Quantidade</th>
              <th>MAC</th>
              <th>Observação</th>
            </tr>
            {% for m in grupo.movimentos %}
            <tr>
              <td>{{ m.data }}</td>
              <td>
                {% if m.tipo == 'entrada' %}
                  <span class="badge badge-green">ENTRADA</span>
                {% else %}
                  <span class="badge badge-red">SAÍDA</span>
                {% endif %}
              </td>
              <td>{{ m.equipamento }}</td>
              <td>{{ m.quantidade }}</td>
              <td>{{ m.mac or '-' }}</td>
              <td>{{ m.observacao or '-' }}</td>
            </tr>
            {% endfor %}
          </table>
        </div>
        {% else %}
          <div class="empty">Esse técnico ainda não possui movimentações registradas.</div>
        {% endif %}
      </div>
      {% endfor %}
    {% endif %}
    """
    return pagina("Busca geral", html, q=q, resultados=resultados, movimentos_tecnicos=movimentos_tecnicos)


# =========================================================
# TÉCNICOS
# =========================================================

@app.route("/tecnicos")
@exigir_perfis("admin", "almoxarifado", "tecnico")
def tecnicos():
    conn = conectar()

    lista = conn.execute("""
        SELECT *
        FROM tecnicos
        ORDER BY ativo DESC, nome
    """).fetchall()

    conn.close()

    html = """
    <div class="stat-row">
        <h1>Técnicos</h1>
        <span class="muted small">Consulte os técnicos disponíveis e seus status.</span>
    </div>

    <div class="card">
        {% if lista %}
        <div class="table-wrap">
            <table>
                <tr>
                    <th>Nome</th>
                    <th>Status</th>
                    {% if current_user.tem_perfil('admin', 'almoxarifado') %}<th>Ação</th>{% endif %}
                </tr>

                {% for tecnico in lista %}
                <tr>
                    <td>{{ tecnico.nome }}</td>
                    <td>
                        {% if tecnico.ativo %}
                            <span class="badge badge-green">Ativo</span>
                        {% else %}
                            <span class="badge badge-red">Inativo</span>
                        {% endif %}
                    </td>
                    {% if current_user.tem_perfil('admin', 'almoxarifado') %}
                    <td>
                        <a class="btn {% if tecnico.ativo %}btn-red{% else %}btn-green{% endif %}"
                           href="{{ url_for('alternar_tecnico', id=tecnico.id) }}">
                            {% if tecnico.ativo %}Desativar{% else %}Ativar{% endif %}
                        </a>
                    </td>
                    {% endif %}
                </tr>
                {% endfor %}
            </table>
        </div>
        {% else %}
            <div class="empty">Nenhum técnico cadastrado.</div>
        {% endif %}
    </div>
    """

    return pagina("Técnicos", html, lista=lista)


@app.route("/tecnicos/novo", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado")
def novo_tecnico():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()

        if not nome:
            flash("Informe o nome do técnico.", "danger")
            return redirect(url_for("novo_tecnico"))

        conn = conectar()

        try:
            conn.execute(
                "INSERT INTO tecnicos (nome) VALUES (?)",
                (nome,)
            )
            conn.commit()
            flash("Técnico cadastrado com sucesso.", "success")
        except sqlite3.IntegrityError:
            flash("Esse técnico já está cadastrado.", "danger")
        finally:
            conn.close()

        return redirect(url_for("tecnicos"))

    html = """
    <h1>Novo técnico</h1>

    <div class="card">
        <form method="post">
            <div class="form-group">
                <label>Nome do técnico</label>
                <input type="text" name="nome" required autofocus>
            </div>

            <button type="submit">Cadastrar técnico</button>
            <a class="btn btn-secondary" href="{{ url_for('tecnicos') }}">Cancelar</a>
        </form>
    </div>
    """

    return pagina("Novo técnico", html)


@app.route("/tecnicos/<int:id>/alternar")
@exigir_perfis("admin", "almoxarifado")
def alternar_tecnico(id):
    conn = conectar()

    tecnico = conn.execute(
        "SELECT ativo FROM tecnicos WHERE id = ?",
        (id,)
    ).fetchone()

    if tecnico:
        novo_status = 0 if tecnico["ativo"] else 1

        conn.execute(
            "UPDATE tecnicos SET ativo = ? WHERE id = ?",
            (novo_status, id)
        )

        conn.commit()

    conn.close()

    return redirect(url_for("tecnicos"))


# =========================================================
# EQUIPAMENTOS
# =========================================================

@app.route("/equipamentos")
@exigir_perfis("admin", "almoxarifado", "tecnico", "consulta")
def equipamentos():
    pesquisa = request.args.get("q", "").strip()

    conn = conectar()

    if pesquisa:
        lista = conn.execute("""
            SELECT *
            FROM equipamentos
            WHERE nome LIKE ?
               OR categoria LIKE ?
               OR fabricante LIKE ?
               OR modelo LIKE ?
            ORDER BY nome
        """, (
            f"%{pesquisa}%",
            f"%{pesquisa}%",
            f"%{pesquisa}%",
            f"%{pesquisa}%"
        )).fetchall()
    else:
        lista = conn.execute("""
            SELECT *
            FROM equipamentos
            ORDER BY nome
        """).fetchall()

    dados = []

    for equipamento in lista:
        estoque = estoque_equipamento(conn, equipamento["id"])
        reservado = reservado_equipamento(conn, equipamento["id"])

        entradas = conn.execute("""
            SELECT COALESCE(SUM(quantidade), 0)
            FROM movimentacoes
            WHERE equipamento_id = ?
              AND tipo = 'entrada'
        """, (equipamento["id"],)).fetchone()[0]

        saidas = conn.execute("""
            SELECT COALESCE(SUM(quantidade), 0)
            FROM movimentacoes
            WHERE equipamento_id = ?
              AND tipo = 'saida'
        """, (equipamento["id"],)).fetchone()[0]

        dados.append({
            "id": equipamento["id"],
            "nome": equipamento["nome"],
            "categoria": equipamento["categoria"] or "-",
            "fabricante": equipamento["fabricante"] or "-",
            "modelo": equipamento["modelo"] or "-",
            "possui_mac": equipamento["possui_mac"],
            "estoque": estoque,
            "reservado": reservado,
            "disponivel": max(0, estoque - reservado),
            "entradas": entradas,
            "saidas": saidas,
            "minimo": equipamento["estoque_minimo"]
        })

    conn.close()

    html = """
    <div class="stat-row">
        <h1>Equipamentos</h1>
        {% if current_user.tem_perfil('admin', 'almoxarifado') %}
            <a class="btn" href="{{ url_for('novo_equipamento') }}">+ Novo equipamento</a>
        {% endif %}
    </div>

    <div class="card">
        <form method="get" class="toolbar">
            <input class="search"
                   type="text"
                   name="q"
                   value="{{ pesquisa }}"
                   placeholder="Pesquisar por nome, fabricante, modelo...">

            <button type="submit">Pesquisar</button>

            {% if pesquisa %}
                <a class="btn btn-secondary" href="{{ url_for('equipamentos') }}">Limpar</a>
            {% endif %}
        </form>
    </div>

    <div class="section card">
        {% if dados %}
        <div class="table-wrap">
            <table>
                <tr>
                    <th>Equipamento</th>
                    <th>Categoria</th>
                    <th>MAC</th>
                    <th>Estoque</th>
                    <th>Reservado</th>
                    <th>Disponível</th>
                    <th>Entradas</th>
                    <th>Saídas</th>
                    <th>Ações</th>
                </tr>

                {% for e in dados %}
                <tr>
                    <td>
                        <strong>{{ e.nome }}</strong>
                        <div class="muted small">
                            {{ e.fabricante }} {{ e.modelo }}
                        </div>
                    </td>

                    <td>{{ e.categoria }}</td>

                    <td>
                        {% if e.possui_mac %}
                            <span class="badge badge-blue">SIM</span>
                        {% else %}
                            <span class="badge">NÃO</span>
                        {% endif %}
                    </td>

                    <td class="{% if e.estoque <= e.minimo %}red{% else %}green{% endif %}">
                        {{ e.estoque }}
                    </td>

                    <td>{{ e.reservado }}</td>

                    <td>
                        <strong>{{ e.disponivel }}</strong>
                    </td>

                    <td>{{ e.entradas }}</td>
                    <td>{{ e.saidas }}</td>

                    <td>
                        <div class="actions">
                            {% if e.possui_mac %}
                                <a class="btn btn-blue"
                                   href="{{ url_for('macs', id=e.id) }}">
                                    MACs
                                </a>
                            {% else %}
                                {% if current_user.tem_perfil('admin', 'almoxarifado') %}
                                    <a class="btn btn-blue"
                                       href="{{ url_for('adicionar_estoque', id=e.id) }}">
                                        + Estoque
                                    </a>
                                {% endif %}
                            {% endif %}

                            {% if current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
                                <a class="btn btn-green"
                                   href="{{ url_for('entrada') }}">
                                    Entrada
                                </a>

                                <a class="btn btn-red"
                                   href="{{ url_for('saida') }}">
                                    Saída
                                </a>
                            {% endif %}
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% else %}
            <div class="empty">Nenhum equipamento encontrado.</div>
        {% endif %}
    </div>
    """

    return pagina(
        "Equipamentos",
        html,
        dados=dados,
        pesquisa=pesquisa
    )


@app.route("/equipamentos/novo", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado")
def novo_equipamento():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        categoria = request.form.get("categoria", "").strip()
        fabricante = request.form.get("fabricante", "").strip()
        modelo = request.form.get("modelo", "").strip()
        possui_mac = 1 if request.form.get("possui_mac") else 0

        try:
            estoque_minimo = max(
                0,
                int(request.form.get("estoque_minimo", 0))
            )
        except ValueError:
            estoque_minimo = 0

        try:
            estoque_inicial = max(
                0,
                int(request.form.get("estoque_inicial", 0))
            )
        except ValueError:
            estoque_inicial = 0

        if not nome:
            flash("Informe o nome do equipamento.", "danger")
            return redirect(url_for("novo_equipamento"))

        if possui_mac and estoque_inicial > 0:
            flash(
                "Equipamentos com MAC devem ser cadastrados individualmente na área de MACs. "
                "Por isso, deixe o estoque inicial como 0.",
                "danger"
            )
            return redirect(url_for("novo_equipamento"))

        conn = conectar()

        cursor = conn.execute("""
            INSERT INTO equipamentos (
                nome,
                categoria,
                fabricante,
                modelo,
                possui_mac,
                estoque_minimo,
                estoque_inicial,
                criado_em
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            nome,
            categoria,
            fabricante,
            modelo,
            possui_mac,
            estoque_minimo,
            estoque_inicial,
            datetime.now().isoformat()
        ))

        equipamento_id = cursor.lastrowid

        if not possui_mac and estoque_inicial > 0:
            conn.execute("""
                INSERT INTO movimentacoes (
                    equipamento_id,
                    tipo,
                    quantidade,
                    observacao,
                    data
                )
                VALUES (?, 'entrada', ?, ?, ?)
            """, (
                equipamento_id,
                estoque_inicial,
                "Estoque inicial",
                hoje()
            ))

        conn.commit()
        conn.close()

        flash("Equipamento cadastrado com sucesso.", "success")
        return redirect(url_for("equipamentos"))

    html = """
    <h1>Novo equipamento</h1>

    <div class="card">
        <form method="post">
            <div class="form-grid">

                <div class="form-group">
                    <label>Nome do equipamento *</label>
                    <input type="text" name="nome" required
                           placeholder="Ex.: ONT Wi-Fi 6">
                </div>

                <div class="form-group">
                    <label>Categoria</label>
                    <input type="text" name="categoria"
                           placeholder="Ex.: ONT, roteador, fonte, fibra">
                </div>

                <div class="form-group">
                    <label>Fabricante</label>
                    <input type="text" name="fabricante"
                           placeholder="Ex.: Intelbras">
                </div>

                <div class="form-group">
                    <label>Modelo</label>
                    <input type="text" name="modelo"
                           placeholder="Ex.: RX 1500">
                </div>

                <div class="form-group">
                    <label>Estoque mínimo</label>
                    <input type="number" name="estoque_minimo"
                           min="0" value="0">
                </div>

                <div class="form-group">
                    <label>Estoque inicial</label>
                    <input type="number" name="estoque_inicial"
                           min="0" value="0">
                    <div class="muted small">
                        Para itens sem MAC, informe aqui a quantidade inicial. Depois você poderá adicionar mais em <strong>+ Estoque</strong>.
                    </div>
                </div>

                <div class="form-group full">
                    <label>
                        <input type="checkbox" name="possui_mac">
                        Este equipamento possui MAC individual
                    </label>

                    <div class="muted small">
                        Marque para equipamentos como ONT, ONU ou roteadores
                        que precisam ser controlados individualmente pelo MAC.
                    </div>
                </div>

            </div>

            <button type="submit">Cadastrar equipamento</button>
            <a class="btn btn-secondary" href="{{ url_for('equipamentos') }}">
                Cancelar
            </a>
        </form>
    </div>
    """

    return pagina("Novo equipamento", html)


# =========================================================
# ADICIONAR ESTOQUE DE ITEM SEM MAC
# =========================================================

@app.route("/equipamentos/<int:id>/estoque", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado")
def adicionar_estoque(id):
    conn = conectar()
    equipamento = conn.execute("SELECT * FROM equipamentos WHERE id = ?", (id,)).fetchone()

    if not equipamento:
        conn.close()
        flash("Equipamento não encontrado.", "danger")
        return redirect(url_for("equipamentos"))

    if equipamento["possui_mac"]:
        conn.close()
        flash("Equipamentos com MAC devem ser adicionados individualmente na área de MACs.", "danger")
        return redirect(url_for("macs", id=id))

    if request.method == "POST":
        try:
            quantidade = int(request.form.get("quantidade", 0))
        except ValueError:
            quantidade = 0

        observacao = request.form.get("observacao", "").strip()
        if quantidade < 1:
            conn.close()
            flash("Informe uma quantidade válida.", "danger")
            return redirect(url_for("adicionar_estoque", id=id))

        conn.execute("""
            INSERT INTO movimentacoes (equipamento_id, tipo, quantidade, observacao, data)
            VALUES (?, 'entrada', ?, ?, ?)
        """, (id, quantidade, observacao or "Reposição de estoque", hoje()))
        conn.commit()
        conn.close()
        registrar_auditoria("ADICIONAR_ESTOQUE", f"Equipamento {id}; quantidade {quantidade}")
        flash(f"{quantidade} unidade(s) adicionada(s) ao estoque.", "success")
        return redirect(url_for("equipamentos"))

    estoque_atual = estoque_equipamento(conn, id)
    conn.close()

    html = """
    <div class="stat-row">
        <h1>Adicionar estoque</h1>
        <a class="btn btn-secondary" href="{{ url_for('equipamentos') }}">Voltar</a>
    </div>
    <div class="card">
        <h2>{{ equipamento.nome }}</h2>
        <p class="muted">Estoque atual: <strong>{{ estoque_atual }}</strong></p>
        <form method="post">
            <div class="form-group">
                <label>Quantidade a adicionar *</label>
                <input type="number" name="quantidade" min="1" value="1" required>
            </div>
            <div class="form-group">
                <label>Observação</label>
                <input type="text" name="observacao" placeholder="Ex.: reposição do fornecedor">
            </div>
            <button type="submit" class="btn-green">Adicionar ao estoque</button>
        </form>
    </div>
    """
    return pagina("Adicionar estoque", html, equipamento=equipamento, estoque_atual=estoque_atual)


# =========================================================
# MACS
# =========================================================

@app.route("/equipamentos/<int:id>/macs", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado", "tecnico", "consulta")
def macs(id):
    conn = conectar()

    equipamento = conn.execute(
        "SELECT * FROM equipamentos WHERE id = ?",
        (id,)
    ).fetchone()

    if not equipamento:
        conn.close()
        flash("Equipamento não encontrado.", "danger")
        return redirect(url_for("equipamentos"))

    if not equipamento["possui_mac"]:
        conn.close()
        flash("Esse equipamento não utiliza controle por MAC.", "danger")
        return redirect(url_for("equipamentos"))

    if request.method == "POST":
        if not current_user.tem_perfil("admin", "almoxarifado"):
            conn.close()
            flash("Você não tem permissão para cadastrar MACs.", "danger")
            return redirect(url_for("macs", id=id))

        mac = request.form.get("mac", "").strip().upper()

        mac = mac.replace("-", ":").replace(".", ":")

        if not mac:
            flash("Informe o MAC.", "danger")
        else:
            try:
                conn.execute("""
                    INSERT INTO unidades (
                        equipamento_id,
                        mac,
                        status
                    )
                    VALUES (?, ?, 'estoque')
                """, (id, mac))

                conn.execute("""
                    INSERT INTO movimentacoes (
                        equipamento_id,
                        tipo,
                        quantidade,
                        mac,
                        observacao,
                        data
                    )
                    VALUES (?, 'entrada', 1, ?, ?, ?)
                """, (
                    id,
                    mac,
                    "Entrada de equipamento com MAC",
                    hoje()
                ))

                conn.commit()
                flash("MAC cadastrado e adicionado ao estoque.", "success")

            except sqlite3.IntegrityError:
                flash("Esse MAC já está cadastrado.", "danger")

        conn.close()
        return redirect(url_for("macs", id=id))

    unidades = conn.execute("""
        SELECT
            u.*,
            t.nome AS tecnico
        FROM unidades u
        LEFT JOIN tecnicos t ON t.id = u.tecnico_id
        WHERE u.equipamento_id = ?
        ORDER BY u.status, u.mac
    """, (id,)).fetchall()

    conn.close()

    html = """
    <div class="stat-row">
        <h1>MACs — {{ equipamento.nome }}</h1>
        <a class="btn btn-secondary"
           href="{{ url_for('equipamentos') }}">
           Voltar
        </a>
    </div>

    {% if current_user.tem_perfil('admin', 'almoxarifado') %}
    <div class="card">
        <h2>📷 Ler MAC pela foto</h2>
        <p class="muted">Tire uma foto da etiqueta. A imagem é processada no seu navegador apenas para encontrar o MAC; ela não é enviada nem salva no banco.</p>
        <input id="foto-mac" type="file" accept="image/*" capture="environment">
        <div id="ocr-status" class="muted small" style="margin-top:8px;"></div>
        <div class="form-group" style="margin-top:10px;">
            <label>MAC encontrado</label>
            <input id="mac-detectado" type="text" placeholder="Aguardando foto..." readonly>
        </div>
        <form id="form-ocr-mac" method="post" style="margin-top:10px;">
            <input id="mac-ocr-hidden" type="hidden" name="mac">
            <button id="btn-salvar-ocr" type="submit" class="btn btn-green" disabled>Salvar MAC encontrado</button>
        </form>
    </div>

    <div class="card">
        <h2>Adicionar MAC manualmente</h2>

        <form method="post" class="toolbar">
            <input class="search"
                   type="text"
                   name="mac"
                   placeholder="Ex.: AA:BB:CC:DD:EE:FF"
                   required>

            <button type="submit">Adicionar ao estoque</button>
        </form>
    </div>
    {% endif %}

    <div class="section card">
        <h2>Equipamentos cadastrados</h2>

        {% if unidades %}
        <div class="table-wrap">
            <table>
                <tr>
                    <th>MAC</th>
                    <th>Status</th>
                    <th>Técnico</th>
                </tr>

                {% for u in unidades %}
                <tr>
                    <td><a href="{{ url_for('historico_mac', mac=u.mac) }}"><strong>{{ u.mac }}</strong></a></td>

                    <td>
                        {% if u.status == 'estoque' %}
                            <span class="badge badge-green">ESTOQUE</span>
                        {% else %}
                            <span class="badge badge-yellow">COM TÉCNICO</span>
                        {% endif %}
                    </td>

                    <td>{{ u.tecnico or '-' }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% else %}
            <div class="empty">
                Nenhum MAC cadastrado.
            </div>
        {% endif %}
    </div>
    """

    html += """
    <script src="https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js"></script>
    <script>
    (function() {
        const foto = document.getElementById('foto-mac');
        const status = document.getElementById('ocr-status');
        const detectado = document.getElementById('mac-detectado');
        const hidden = document.getElementById('mac-ocr-hidden');
        const salvar = document.getElementById('btn-salvar-ocr');
        if (!foto) return;

        function extrairMAC(texto) {
            const t = (texto || '').toUpperCase();
            const padroes = [
                /\b([0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/,
                /\b[0-9A-F]{4}(?:[ .:-][0-9A-F]{4}){2}\b/,
                /\b[0-9A-F]{12}\b/
            ];
            for (const p of padroes) {
                const m = t.match(p);
                if (m) {
                    const bruto = m[0].replace(/[^0-9A-F]/g, '');
                    if (bruto.length === 12) return bruto.match(/../g).join(':');
                }
            }
            return '';
        }

        foto.addEventListener('change', async function() {
            if (!foto.files || !foto.files[0]) return;
            const arquivo = foto.files[0];
            status.textContent = 'Lendo a etiqueta...';
            detectado.value = '';
            hidden.value = '';
            salvar.disabled = true;
            try {
                const resultado = await Tesseract.recognize(arquivo, 'eng', {
                    logger: m => {
                        if (m.status === 'recognizing text' && typeof m.progress === 'number') {
                            status.textContent = 'Lendo a etiqueta... ' + Math.round(m.progress * 100) + '%';
                        }
                    }
                });
                const mac = extrairMAC(resultado.data.text);
                if (!mac) {
                    status.textContent = 'Não encontrei um MAC com segurança. Tente uma foto mais próxima e nítida.';
                    return;
                }
                detectado.value = mac;
                hidden.value = mac;
                salvar.disabled = false;
                status.textContent = 'MAC encontrado. Confira antes de salvar.';
            } catch (erro) {
                console.error(erro);
                status.textContent = 'Não foi possível ler a foto. Você ainda pode cadastrar o MAC manualmente abaixo.';
            }
        });
    })();
    </script>
    """

    return pagina(
        "MACs",
        html,
        equipamento=equipamento,
        unidades=unidades
    )


# =========================================================
# HISTÓRICO DE MAC
# =========================================================

@app.route("/mac/<path:mac>/historico")
@exigir_perfis("admin", "almoxarifado", "tecnico", "consulta")
def historico_mac(mac):
    mac = mac.upper().replace("-", ":").replace(".", ":")
    conn = conectar()
    unidade = conn.execute("""SELECT u.*, e.nome AS equipamento, t.nome AS tecnico FROM unidades u JOIN equipamentos e ON e.id = u.equipamento_id LEFT JOIN tecnicos t ON t.id = u.tecnico_id WHERE u.mac = ?""", (mac,)).fetchone()
    movimentos = conn.execute("""SELECT m.*, e.nome AS equipamento, t.nome AS tecnico FROM movimentacoes m JOIN equipamentos e ON e.id = m.equipamento_id LEFT JOIN tecnicos t ON t.id = m.tecnico_id WHERE m.mac = ? ORDER BY m.id DESC""", (mac,)).fetchall()
    conn.close()
    if not unidade:
        flash("MAC não encontrado.", "danger")
        return redirect(url_for("buscar", q=mac))
    html="""
    <div class="stat-row"><h1>Histórico do MAC</h1><a class="btn btn-secondary" href="{{ url_for('macs', id=unidade.equipamento_id) }}">Voltar</a></div>
    <div class="card"><h2>{{ unidade.mac }}</h2><p class="muted">{{ unidade.equipamento }} · Status: {{ unidade.status }} · Técnico: {{ unidade.tecnico or '-' }}</p></div>
    <div class="section card"><h2>Movimentações</h2>{% if movimentos %}<div class="table-wrap"><table><tr><th>Data</th><th>Tipo</th><th>Quantidade</th><th>Técnico</th><th>Observação</th></tr>{% for m in movimentos %}<tr><td>{{ m.data }}</td><td>{{ m.tipo|upper }}</td><td>{{ m.quantidade }}</td><td>{{ m.tecnico or '-' }}</td><td>{{ m.observacao or '-' }}</td></tr>{% endfor %}</table></div>{% else %}<div class="empty">Nenhuma movimentação registrada.</div>{% endif %}</div>
    """
    return pagina("Histórico MAC", html, unidade=unidade, movimentos=movimentos)


# =========================================================
# ENTRADA
# =========================================================

# =========================================================
# MOVIMENTAÇÕES — ENTRADA / SAÍDA
# =========================================================

@app.route("/movimentacao/macs-disponiveis")
@exigir_perfis("admin", "almoxarifado", "tecnico")
def movimentacao_macs_disponiveis():
    equipamento_id = request.args.get("equipamento_id", type=int)
    modo = (request.args.get("modo") or "estoque").lower()
    busca = (request.args.get("q") or "").strip().upper()
    if not equipamento_id:
        return jsonify({"ok": False, "macs": []}), 400
    conn = conectar()
    equipamento = conn.execute("SELECT * FROM equipamentos WHERE id = ?", (equipamento_id,)).fetchone()
    if not equipamento or not equipamento["possui_mac"]:
        conn.close()
        return jsonify({"ok": False, "macs": []}), 400
    params = [equipamento_id]
    where = "u.equipamento_id = ?"
    if modo == "estoque":
        where += " AND u.status = 'estoque' AND u.tecnico_id IS NULL"
    if busca:
        where += " AND UPPER(u.mac) LIKE ?"
        params.append("%" + busca + "%")
    rows = conn.execute(f"SELECT u.id, u.mac, u.status, t.nome AS tecnico FROM unidades u LEFT JOIN tecnicos t ON t.id=u.tecnico_id WHERE {where} ORDER BY u.mac LIMIT 100", params).fetchall()
    conn.close()
    return jsonify({"ok": True, "macs": [dict(r) for r in rows]})


def _normalizar_mac(valor):
    """Normaliza o identificador da unidade sem exigir formato de MAC.

    O sistema trata o campo como um identificador único da unidade.
    Portanto, pode receber MAC tradicional (AA:BB:CC:DD:EE:FF),
    número de série, etiqueta com letras/números, ou outro identificador
    usado pelo provedor.
    """
    valor = str(valor or "").strip()
    if not valor:
        return ""

    # Mantém letras, números e separadores exatamente como informados,
    # apenas padronizando para maiúsculas e espaços nas extremidades.
    valor = valor.upper()

    # Evita gravar quebras de linha/caracteres de controle no identificador.
    if any(ord(ch) < 32 for ch in valor):
        return ""

    # Limite razoável para impedir valores acidentalmente enormes.
    if len(valor) > 100:
        return ""

    return valor


def _html_movimentacao_camera():
    return r'''
    <div class="card" style="margin-top:12px;">
      <h3>📷 Ler MAC pela câmera</h3>
      <p class="muted small">Tire uma foto da etiqueta. O reconhecimento acontece no navegador; a foto não é salva no banco.</p>
      <input type="file" class="mov-foto-mac" accept="image/*" capture="environment">
      <div class="mov-ocr-status muted small" style="margin-top:8px;"></div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js"></script>
    <script>
    (function(){
      const foto=document.querySelector('.mov-foto-mac');
      const status=document.querySelector('.mov-ocr-status');
      const input=document.querySelector('input[name="mac"]');
      if(!foto||!input)return;
      function extrairMAC(txt){
        const t=(txt||'').toUpperCase();
        const ps=[/\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/,/\b[0-9A-F]{4}(?:[ .:-][0-9A-F]{4}){2}\b/,/\b[0-9A-F]{12}\b/];
        for(const p of ps){const m=t.match(p);if(m){const b=m[0].replace(/[^0-9A-F]/g,'');if(b.length===12)return b.match(/../g).join(':');}}
        return '';
      }
      foto.addEventListener('change',async()=>{
        if(!foto.files?.[0])return;
        status.textContent='Lendo a etiqueta...';
        try{const r=await Tesseract.recognize(foto.files[0],'eng');const mac=extrairMAC(r.data.text);if(mac){input.value=mac;input.dispatchEvent(new Event('input'));status.textContent='MAC encontrado: '+mac+' — confira antes de confirmar.';}else status.textContent='Não encontrei um MAC. Tente uma foto mais próxima e nítida ou informe o MAC manualmente.';}
        catch(e){status.textContent='Não foi possível ler a foto. Informe o MAC manualmente.';}
      });
    })();
    </script>
    '''


@app.route("/movimentacao/entrada", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado", "tecnico")
def entrada():
    conn = conectar()
    equipamentos_lista = conn.execute("SELECT * FROM equipamentos ORDER BY nome").fetchall()
    tecnicos_lista = conn.execute("SELECT * FROM tecnicos WHERE ativo = 1 ORDER BY nome").fetchall()
    if request.method == "POST":
        equipamento_id = request.form.get("equipamento_id")
        tecnico_id = request.form.get("tecnico_id") or None
        if current_user.tem_perfil("tecnico") and not current_user.tem_perfil("admin", "almoxarifado"):
            tecnico_pessoal = tecnico_do_usuario()
            tecnico_id = str(tecnico_pessoal["id"]) if tecnico_pessoal else None
        mac = _normalizar_mac(request.form.get("mac", ""))
        observacao = request.form.get("observacao", "").strip()
        if not equipamento_id:
            conn.close(); flash("Selecione o equipamento.", "danger"); return redirect(url_for("entrada"))
        equipamento = conn.execute("SELECT * FROM equipamentos WHERE id = ?", (equipamento_id,)).fetchone()
        if not equipamento:
            conn.close(); flash("Equipamento inválido.", "danger"); return redirect(url_for("entrada"))
        if equipamento["possui_mac"]:
            if not mac:
                conn.close(); flash("Informe ou pesquise o MAC do equipamento. Você também pode usar a câmera.", "danger"); return redirect(url_for("entrada"))
            unidade = conn.execute("SELECT * FROM unidades WHERE equipamento_id = ? AND mac = ?", (equipamento_id, mac)).fetchone()
            if unidade:
                conn.execute("UPDATE unidades SET status='estoque', tecnico_id=NULL WHERE id=?", (unidade["id"],))
            else:
                conn.execute("INSERT INTO unidades (equipamento_id, mac, status) VALUES (?, ?, 'estoque')", (equipamento_id, mac))
            conn.execute("INSERT INTO movimentacoes (equipamento_id,tipo,quantidade,mac,tecnico_id,observacao,data) VALUES (?, 'entrada', 1, ?, ?, ?, ?)", (equipamento_id,mac,tecnico_id,observacao,hoje()))
        else:
            try: quantidade=max(1,int(request.form.get("quantidade",1)))
            except ValueError: quantidade=1
            conn.execute("INSERT INTO movimentacoes (equipamento_id,tipo,quantidade,tecnico_id,observacao,data) VALUES (?, 'entrada', ?, ?, ?, ?)", (equipamento_id,quantidade,tecnico_id,observacao,hoje()))
        conn.commit(); conn.close(); flash("Entrada registrada com sucesso.", "success"); return redirect(url_for("movimentacoes"))
    conn.close()
    html = '''
    <h1>Registrar entrada</h1>
    <div class="card"><form method="post">
      <div class="form-group"><label>Equipamento *</label><select name="equipamento_id" id="mov-equip" required><option value="">Selecione...</option>{% for e in equipamentos_lista %}<option value="{{ e.id }}" data-mac="{{ 1 if e.possui_mac else 0 }}">{{ e.nome }}{% if e.possui_mac %} — possui MAC{% endif %}</option>{% endfor %}</select></div>
      <div class="form-group"><label>Quantidade</label><input type="number" name="quantidade" min="1" value="1"><div class="muted small">Para equipamentos com MAC, cada unidade é identificada individualmente.</div></div>
      <div class="form-group"><label>MAC</label><input type="text" name="mac" id="mov-mac" placeholder="Digite o identificador / MAC da unidade" autocomplete="off"></div>
      <div id="mac-pesquisa-area" class="form-group" style="display:none;"><label>🔎 Pesquisar MAC já cadastrado</label><input type="text" id="mac-busca" placeholder="Digite parte do MAC..."><div id="mac-resultados" class="mac-check-list" style="margin-top:8px;"></div><div id="mac-status" class="muted small"></div></div>
      {% if current_user.tem_perfil('admin', 'almoxarifado') %}<div class="form-group"><label>Técnico responsável</label><select name="tecnico_id"><option value="">Não informado</option>{% for t in tecnicos_lista %}<option value="{{ t.id }}">{{ t.nome }}</option>{% endfor %}</select></div>{% else %}<div class="form-group"><label>Técnico responsável</label><input value="{{ (tecnico_pessoal.nome if tecnico_pessoal else 'Não vinculado') }}" disabled></div>{% endif %}
      <div class="form-group"><label>Observação</label><textarea name="observacao" placeholder="Ex.: equipamento devolvido pelo técnico..."></textarea></div>
      <button type="submit" class="btn-green">Registrar entrada</button> <a class="btn btn-secondary" href="{{ url_for('movimentacoes') }}">Cancelar</a>
    </form></div>
    <div id="camera-mac" style="display:none;">''' + _html_movimentacao_camera() + '''</div>
    <script>
    (function(){const eq=document.getElementById('mov-equip'),area=document.getElementById('mac-pesquisa-area'),busca=document.getElementById('mac-busca'),res=document.getElementById('mac-resultados'),st=document.getElementById('mac-status'),mac=document.getElementById('mov-mac'),cam=document.getElementById('camera-mac');
      function carregar(){const o=eq.options[eq.selectedIndex],on=o&&o.dataset.mac==='1';area.style.display=on?'block':'none';cam.style.display=on?'block':'none';res.innerHTML='';st.textContent='';busca.value='';if(on) buscar();}
      async function buscar(){if(!eq.value||eq.options[eq.selectedIndex].dataset.mac!=='1')return;const q=encodeURIComponent(busca.value||'');st.textContent='Pesquisando...';try{const r=await fetch('{{ url_for("movimentacao_macs_disponiveis") }}?equipamento_id='+eq.value+'&modo=todos&q='+q);const d=await r.json();res.innerHTML='';(d.macs||[]).forEach(u=>{const b=document.createElement('button');b.type='button';b.className='btn btn-secondary';b.style.margin='3px';b.textContent=u.mac+' — '+(u.status==='estoque'?'ESTOQUE':'COM '+(u.tecnico||'TÉCNICO'));b.onclick=()=>{mac.value=u.mac;};res.appendChild(b);});st.textContent=(d.macs||[]).length+' MAC(s) encontrado(s).';}catch(e){st.textContent='Erro ao pesquisar MACs.';}}
      eq.addEventListener('change',carregar);busca.addEventListener('input',buscar);carregar();
    })();
    </script>
    '''
    return pagina("Entrada", html, equipamentos_lista=equipamentos_lista, tecnicos_lista=tecnicos_lista, tecnico_pessoal=tecnico_do_usuario() if current_user.tem_perfil('tecnico') else None)


@app.route("/movimentacao/saida", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado", "tecnico")
def saida():
    conn = conectar()
    equipamentos_lista = conn.execute("SELECT * FROM equipamentos ORDER BY nome").fetchall()
    tecnicos_lista = conn.execute("SELECT * FROM tecnicos WHERE ativo = 1 ORDER BY nome").fetchall()
    if request.method == "POST":
        equipamento_id=request.form.get("equipamento_id"); tecnico_id=request.form.get("tecnico_id") or None; mac=_normalizar_mac(request.form.get("mac", "")); observacao=request.form.get("observacao", "").strip()
        if current_user.tem_perfil("tecnico") and not current_user.tem_perfil("admin", "almoxarifado"):
            tecnico_pessoal = tecnico_do_usuario()
            tecnico_id = str(tecnico_pessoal["id"]) if tecnico_pessoal else None
        if not equipamento_id:
            conn.close(); flash("Selecione o equipamento.","danger"); return redirect(url_for("saida"))
        equipamento=conn.execute("SELECT * FROM equipamentos WHERE id=?",(equipamento_id,)).fetchone()
        if not equipamento:
            conn.close(); flash("Equipamento inválido.","danger"); return redirect(url_for("saida"))
        if not tecnico_id:
            conn.close(); flash("Selecione o técnico responsável pela saída.","danger"); return redirect(url_for("saida"))
        if equipamento["possui_mac"]:
            if not mac:
                conn.close(); flash("Pesquise, selecione ou leia pela câmera o MAC que está saindo.","danger"); return redirect(url_for("saida"))
            unidade=conn.execute("SELECT * FROM unidades WHERE equipamento_id=? AND mac=? AND status='estoque' AND tecnico_id IS NULL",(equipamento_id,mac)).fetchone()
            if not unidade:
                conn.close(); flash("Esse MAC não está disponível no estoque.","danger"); return redirect(url_for("saida"))
            conn.execute("UPDATE unidades SET status='tecnico', tecnico_id=? WHERE id=?",(tecnico_id,unidade["id"]))
            conn.execute("INSERT INTO movimentacoes (equipamento_id,tipo,quantidade,mac,tecnico_id,observacao,data) VALUES (?, 'saida', 1, ?, ?, ?, ?)",(equipamento_id,mac,tecnico_id,observacao,hoje()))
        else:
            try: quantidade=max(1,int(request.form.get("quantidade",1)))
            except ValueError: quantidade=1
            disponivel=estoque_equipamento(conn,equipamento_id)-reservado_equipamento(conn,equipamento_id)
            if quantidade>disponivel:
                conn.close(); flash(f"Estoque insuficiente. Disponível: {disponivel}.","danger"); return redirect(url_for("saida"))
            conn.execute("INSERT INTO movimentacoes (equipamento_id,tipo,quantidade,tecnico_id,observacao,data) VALUES (?, 'saida', ?, ?, ?, ?)",(equipamento_id,quantidade,tecnico_id,observacao,hoje()))
        conn.commit(); conn.close(); flash("Saída registrada com sucesso.","success"); return redirect(url_for("movimentacoes"))
    conn.close()
    html='''
    <h1>Registrar saída</h1><div class="card"><form method="post">
      <div class="form-group"><label>Equipamento *</label><select name="equipamento_id" id="mov-equip" required><option value="">Selecione...</option>{% for e in equipamentos_lista %}<option value="{{ e.id }}" data-mac="{{ 1 if e.possui_mac else 0 }}">{{ e.nome }}{% if e.possui_mac %} — possui MAC{% endif %}</option>{% endfor %}</select></div>
      <div class="form-group"><label>Quantidade</label><input type="number" name="quantidade" min="1" value="1"></div>
      <div class="form-group"><label>MAC</label><input type="text" name="mac" id="mov-mac" placeholder="Digite o identificador / MAC da unidade" autocomplete="off"></div>
      <div id="mac-pesquisa-area" class="form-group" style="display:none;"><label>🔎 Pesquisar MAC disponível no estoque</label><input type="text" id="mac-busca" placeholder="Digite parte do MAC..."><div id="mac-resultados" class="mac-check-list" style="margin-top:8px;"></div><div id="mac-status" class="muted small"></div></div>
      {% if current_user.tem_perfil('admin', 'almoxarifado') %}<div class="form-group"><label>Técnico responsável *</label><select name="tecnico_id" required><option value="">Selecione...</option>{% for t in tecnicos_lista %}<option value="{{ t.id }}">{{ t.nome }}</option>{% endfor %}</select></div>{% else %}<div class="form-group"><label>Técnico responsável</label><input value="{{ (tecnico_pessoal.nome if tecnico_pessoal else 'Não vinculado') }}" disabled></div>{% endif %}
      <div class="form-group"><label>Observação</label><textarea name="observacao" placeholder="Ex.: instalação no cliente..."></textarea></div>
      <button type="submit" class="btn-red">Registrar saída</button> <a class="btn btn-secondary" href="{{ url_for('movimentacoes') }}">Cancelar</a>
    </form></div><div id="camera-mac" style="display:none;">''' + _html_movimentacao_camera() + '''</div>
    <script>
    (function(){const eq=document.getElementById('mov-equip'),area=document.getElementById('mac-pesquisa-area'),busca=document.getElementById('mac-busca'),res=document.getElementById('mac-resultados'),st=document.getElementById('mac-status'),mac=document.getElementById('mov-mac'),cam=document.getElementById('camera-mac');
      function carregar(){const o=eq.options[eq.selectedIndex],on=o&&o.dataset.mac==='1';area.style.display=on?'block':'none';cam.style.display=on?'block':'none';res.innerHTML='';st.textContent='';busca.value='';if(on) buscar();}
      async function buscar(){if(!eq.value||eq.options[eq.selectedIndex].dataset.mac!=='1')return;const q=encodeURIComponent(busca.value||'');st.textContent='Pesquisando MACs do estoque...';try{const r=await fetch('{{ url_for("movimentacao_macs_disponiveis") }}?equipamento_id='+eq.value+'&modo=estoque&q='+q);const d=await r.json();res.innerHTML='';(d.macs||[]).forEach(u=>{const b=document.createElement('button');b.type='button';b.className='btn btn-green';b.style.margin='3px';b.textContent=u.mac;b.onclick=()=>{mac.value=u.mac;};res.appendChild(b);});st.textContent=(d.macs||[]).length+' MAC(s) disponível(is).';}catch(e){st.textContent='Erro ao pesquisar MACs.';}}
      eq.addEventListener('change',carregar);busca.addEventListener('input',buscar);carregar();
    })();
    </script>'''
    return pagina("Saída", html, equipamentos_lista=equipamentos_lista, tecnicos_lista=tecnicos_lista, tecnico_pessoal=tecnico_do_usuario() if current_user.tem_perfil('tecnico') else None)


# =========================================================
# HISTÓRICO
# =========================================================

@app.route("/movimentacoes")
@exigir_perfis("admin", "almoxarifado", "tecnico", "consulta")
def movimentacoes():
    pesquisa = request.args.get("q", "").strip()
    tecnico_id = request.args.get("tecnico_id", "").strip()

    conn = conectar()

    if tecnico_id:
        try:
            tecnico_id_int = int(tecnico_id)
        except ValueError:
            tecnico_id_int = 0

        movimentos = conn.execute("""
            SELECT
                m.*,
                e.nome AS equipamento,
                t.nome AS tecnico
            FROM movimentacoes m
            JOIN equipamentos e ON e.id = m.equipamento_id
            LEFT JOIN tecnicos t ON t.id = m.tecnico_id
            WHERE m.tecnico_id = ?
            ORDER BY m.id DESC
        """, (tecnico_id_int,)).fetchall()
    elif pesquisa:
        movimentos = conn.execute("""
            SELECT
                m.*,
                e.nome AS equipamento,
                t.nome AS tecnico
            FROM movimentacoes m
            JOIN equipamentos e ON e.id = m.equipamento_id
            LEFT JOIN tecnicos t ON t.id = m.tecnico_id
            WHERE (LOWER(e.nome) = LOWER(?)
               OR (' ' || LOWER(e.nome) || ' ') LIKE ('% ' || LOWER(?) || ' %')
               OR e.nome LIKE ?)
               OR m.mac LIKE ?
               OR t.nome LIKE ?
               OR m.observacao LIKE ?
            ORDER BY m.id DESC
        """, (
            pesquisa, pesquisa, f"%{pesquisa}%",
            f"%{pesquisa}%", f"%{pesquisa}%", f"%{pesquisa}%"
        )).fetchall()
    else:
        movimentos = conn.execute("""
            SELECT
                m.*,
                e.nome AS equipamento,
                t.nome AS tecnico
            FROM movimentacoes m
            JOIN equipamentos e ON e.id = m.equipamento_id
            LEFT JOIN tecnicos t ON t.id = m.tecnico_id
            ORDER BY m.id DESC
            LIMIT 300
        """).fetchall()

    conn.close()

    html = """
    <div class="stat-row">
        <h1>Movimentações</h1>

        {% if current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
        <div class="actions">
            <a class="btn btn-green"
               href="{{ url_for('entrada') }}">
               + Entrada
            </a>

            <a class="btn btn-red"
               href="{{ url_for('saida') }}">
               + Saída
            </a>
        </div>
        {% endif %}
    </div>

    <div class="card">
        <form method="get" class="toolbar">
            <input class="search"
                   type="text"
                   name="q"
                   value="{{ pesquisa }}"
                   placeholder="Pesquisar equipamento, MAC ou técnico">

            <button type="submit">Pesquisar</button>

            {% if pesquisa or tecnico_id %}
                <a class="btn btn-secondary"
                   href="{{ url_for('movimentacoes') }}">
                   Limpar
                </a>
            {% endif %}
        </form>
    </div>

    <div class="section card">
        {% if movimentos %}
        <div class="table-wrap">
            <table>
                <tr>
                    <th>Data</th>
                    <th>Tipo</th>
                    <th>Equipamento</th>
                    <th>Quantidade</th>
                    <th>MAC</th>
                    <th>Técnico</th>
                    <th>Observação</th>
                </tr>

                {% for m in movimentos %}
                <tr>
                    <td>{{ m.data }}</td>

                    <td>
                        {% if m.tipo == 'entrada' %}
                            <span class="badge badge-green">ENTRADA</span>
                        {% else %}
                            <span class="badge badge-red">SAÍDA</span>
                        {% endif %}
                    </td>

                    <td>{{ m.equipamento }}</td>
                    <td>{{ m.quantidade }}</td>
                    <td>{{ m.mac or '-' }}</td>
                    <td>{{ m.tecnico or '-' }}</td>
                    <td>{{ m.observacao or '-' }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% else %}
            <div class="empty">Nenhuma movimentação encontrada.</div>
        {% endif %}
    </div>
    """

    return pagina(
        "Movimentações",
        html,
        movimentos=movimentos,
        pesquisa=pesquisa,
        tecnico_id=tecnico_id
    )


# =========================================================
# AGENDAMENTOS
# =========================================================

@app.route("/agendamentos", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado", "tecnico", "consulta")
def agendamentos():
    conn = conectar()

    tecnicos_lista = conn.execute("""
        SELECT *
        FROM tecnicos
        WHERE ativo = 1
        ORDER BY nome
    """).fetchall()

    equipamentos_lista = conn.execute("""
        SELECT *
        FROM equipamentos
        ORDER BY nome
    """).fetchall()

    if request.method == "POST":
        tecnico_id = request.form.get("tecnico_id")
        if current_user.tem_perfil("tecnico"):
            tecnico = tecnico_do_usuario()
            if not tecnico:
                conn.close()
                flash("Seu usuário não está vinculado a um técnico. Peça ao administrador para fazer o vínculo.", "danger")
                return redirect(url_for("agendamentos"))
            tecnico_id = str(tecnico["id"])
        data_agendamento = request.form.get("data")
        observacao = request.form.get("observacao", "").strip()

        if not tecnico_id or not data_agendamento:
            conn.close()
            flash(
                "Informe o técnico e a data do agendamento.",
                "danger"
            )
            return redirect(url_for("agendamentos"))

        equipamentos_ids = request.form.getlist("equipamento_id")
        quantidades = request.form.getlist("quantidade")

        itens = []

        for equipamento_id, quantidade in zip(
            equipamentos_ids,
            quantidades
        ):
            if not equipamento_id:
                continue

            try:
                quantidade = int(quantidade)
            except ValueError:
                continue

            if quantidade <= 0:
                continue

            itens.append((int(equipamento_id), quantidade))

        if not itens:
            conn.close()
            flash(
                "Adicione pelo menos um equipamento ao agendamento.",
                "danger"
            )
            return redirect(url_for("agendamentos"))

        # Verifica estoque disponível
        for equipamento_id, quantidade in itens:
            estoque = estoque_equipamento(conn, equipamento_id)
            reservado = reservado_equipamento(conn, equipamento_id)

            disponivel = estoque - reservado

            if quantidade > disponivel:
                equipamento = conn.execute(
                    "SELECT nome FROM equipamentos WHERE id = ?",
                    (equipamento_id,)
                ).fetchone()

                conn.close()

                flash(
                    f"Estoque insuficiente para {equipamento['nome']}. "
                    f"Disponível: {disponivel}.",
                    "danger"
                )

                return redirect(url_for("agendamentos"))

        cursor = conn.execute("""
            INSERT INTO agendamentos (
                tecnico_id,
                data,
                observacao,
                status,
                criado_em
            )
            VALUES (?, ?, ?, 'aberto', ?)
        """, (
            tecnico_id,
            data_agendamento,
            observacao,
            datetime.now().isoformat()
        ))

        agendamento_id = cursor.lastrowid

        for equipamento_id, quantidade in itens:
            conn.execute("""
                INSERT INTO agendamento_itens (
                    agendamento_id,
                    equipamento_id,
                    quantidade
                )
                VALUES (?, ?, ?)
            """, (
                agendamento_id,
                equipamento_id,
                quantidade
            ))

        conn.commit()
        conn.close()

        flash("Agendamento criado com sucesso.", "success")
        return redirect(url_for("agendamentos"))

    if current_user.tem_perfil("tecnico"):
        tecnico = tecnico_do_usuario()
        if tecnico:
            lista = conn.execute("""
                SELECT a.*, t.nome AS tecnico FROM agendamentos a JOIN tecnicos t ON t.id = a.tecnico_id
                WHERE a.tecnico_id = ?
                ORDER BY CASE WHEN a.status = 'aberto' THEN 0 ELSE 1 END, a.data, a.id DESC
            """, (tecnico["id"],)).fetchall()
        else:
            lista = []
    else:
        lista = conn.execute("""
            SELECT
                a.*,
                t.nome AS tecnico
            FROM agendamentos a
            JOIN tecnicos t ON t.id = a.tecnico_id
            ORDER BY
            CASE WHEN a.status = 'aberto' THEN 0 ELSE 1 END,
            a.data,
            a.id DESC
    """).fetchall()

    detalhes = {}

    for a in lista:
        detalhes[a["id"]] = conn.execute("""
            SELECT
                ai.quantidade,
                e.nome
            FROM agendamento_itens ai
            JOIN equipamentos e ON e.id = ai.equipamento_id
            WHERE ai.agendamento_id = ?
        """, (a["id"],)).fetchall()

    conn.close()

    html = """
    <div class="stat-row">
        <h1>Agendamentos</h1>
    </div>

    {% if current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
    <div class="card">
        <h2>Novo agendamento</h2>

        <form method="post">

            <div class="form-grid">

                {% if current_user.tem_perfil('tecnico') %}
                <div class="form-group">
                    <label>Técnico</label>
                    <input value="{{ (tecnico_pessoal.nome if tecnico_pessoal else 'Não vinculado') }}" disabled>
                </div>
                {% else %}
                <div class="form-group">
                    <label>Técnico *</label>
                    <select name="tecnico_id" required>
                        <option value="">Selecione...</option>
                        {% for t in tecnicos_lista %}<option value="{{ t.id }}">{{ t.nome }}</option>{% endfor %}
                    </select>
                </div>
                {% endif %}

                <div class="form-group">
                    <label>Data *</label>
                    <input type="date"
                           name="data"
                           value="{{ hoje }}"
                           required>
                </div>

                <div class="form-group full">
                    <label>Equipamentos do agendamento</label>
                    <p style="margin:0 0 10px; color:#94a3b8; font-size:13px;">Adicione quantos equipamentos precisar. Cada linha permite escolher o equipamento e a quantidade.</p>

                    <div id="agendamento-itens">
                        <div class="toolbar agendamento-item" style="margin-bottom:10px;">
                            <select name="equipamento_id" required>
                                <option value="">Selecione...</option>
                                {% for e in equipamentos_lista %}
                                <option value="{{ e.id }}">{{ e.nome }}</option>
                                {% endfor %}
                            </select>

                            <input type="number"
                                   name="quantidade"
                                   min="1"
                                   value="1"
                                   required>

                            <button type="button" class="btn btn-red remover-item" style="display:none;">Remover</button>
                        </div>
                    </div>

                    <button type="button" class="btn" id="adicionar-item" style="margin-top:5px;">+ Adicionar equipamento</button>
                </div>

                <div class="form-group full">
                    <label>Observação</label>
                    <textarea name="observacao"
                              placeholder="Ex.: separação para instalação de amanhã..."></textarea>
                </div>

            </div>

            <button type="submit">Criar agendamento</button>
        </form>

        <script>
        (function() {
            const container = document.getElementById('agendamento-itens');
            const botaoAdicionar = document.getElementById('adicionar-item');

            if (!container || !botaoAdicionar) return;

            function atualizarBotoesRemover() {
                const itens = container.querySelectorAll('.agendamento-item');
                itens.forEach(function(item) {
                    const botao = item.querySelector('.remover-item');
                    if (botao) botao.style.display = itens.length > 1 ? 'inline-flex' : 'none';
                });
            }

            botaoAdicionar.addEventListener('click', function() {
                const primeiro = container.querySelector('.agendamento-item');
                const novo = primeiro.cloneNode(true);
                const select = novo.querySelector('select');
                const quantidade = novo.querySelector('input[name="quantidade"]');

                select.value = '';
                select.removeAttribute('required');
                quantidade.value = '1';
                novo.querySelector('.remover-item').style.display = 'inline-flex';

                container.appendChild(novo);
                atualizarBotoesRemover();
            });

            container.addEventListener('click', function(event) {
                if (!event.target.classList.contains('remover-item')) return;

                const itens = container.querySelectorAll('.agendamento-item');
                if (itens.length > 1) {
                    event.target.closest('.agendamento-item').remove();
                    atualizarBotoesRemover();
                }
            });

            atualizarBotoesRemover();
        })();
        </script>
    </div>
    {% endif %}

    <div class="section card">
        <h2>Agendamentos cadastrados</h2>

        {% if lista %}
        <div class="table-wrap">
            <table>
                <tr>
                    <th>Data</th>
                    <th>Técnico</th>
                    <th>Equipamentos</th>
                    <th>Status</th>
                    <th>Observação</th>
                    <th>Ações</th>
                </tr>

                {% for a in lista %}
                <tr>
                    <td>{{ a.data }}</td>
                    <td>{{ a.tecnico }}</td>

                    <td>
                        {% for item in detalhes[a.id] %}
                            {{ item.nome }} × {{ item.quantidade }}<br>
                        {% endfor %}
                    </td>

                    <td>
                        {% if a.status == 'aberto' %}
                            <span class="badge badge-yellow">ABERTO</span>
                        {% elif a.status == 'concluido' %}
                            <span class="badge badge-green">CONCLUÍDO</span>
                        {% else %}
                            <span class="badge badge-red">CANCELADO</span>
                        {% endif %}
                    </td>

                    <td>{{ a.observacao or '-' }}</td>

                    <td>
                        {% if a.status == 'aberto' and current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
                        <div class="actions">
                            <a class="btn btn-green"
                               href="{{ url_for('concluir_agendamento', id=a.id) }}">
                               Concluir
                            </a>

                            <a class="btn btn-red"
                               href="{{ url_for('cancelar_agendamento', id=a.id) }}">
                               Cancelar
                            </a>
                        </div>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% else %}
            <div class="empty">Nenhum agendamento cadastrado.</div>
        {% endif %}
    </div>
    """

    return pagina(
        "Agendamentos",
        html,
        tecnicos_lista=tecnicos_lista,
        equipamentos_lista=equipamentos_lista,
        lista=lista,
        detalhes=detalhes,
        hoje=hoje(),
        tecnico_pessoal=tecnico_do_usuario() if current_user.tem_perfil('tecnico') else None
    )


@app.route("/agendamentos/<int:id>/concluir")
@exigir_perfis("admin", "almoxarifado", "tecnico")
def concluir_agendamento(id):
    conn = conectar()

    agendamento = conn.execute("""
        SELECT *
        FROM agendamentos
        WHERE id = ?
    """, (id,)).fetchone()

    if not agendamento:
        conn.close()
        flash("Agendamento não encontrado.", "danger")
        return redirect(url_for("agendamentos"))

    if current_user.tem_perfil("tecnico") and not current_user.tem_perfil("admin", "almoxarifado"):
        tecnico_pessoal = tecnico_do_usuario()
        if not tecnico_pessoal or int(agendamento["tecnico_id"]) != int(tecnico_pessoal["id"]):
            conn.close()
            flash("Você só pode alterar seus próprios agendamentos.", "danger")
            return redirect(url_for("agendamentos"))

    conn.execute("""
        UPDATE agendamentos
        SET status = 'concluido'
        WHERE id = ?
    """, (id,))

    conn.commit()
    conn.close()

    flash(
        "Agendamento concluído. Registre a saída dos equipamentos na tela de Saída.",
        "success"
    )

    return redirect(url_for("agendamentos"))


@app.route("/agendamentos/<int:id>/cancelar")
@exigir_perfis("admin", "almoxarifado", "tecnico")
def cancelar_agendamento(id):
    conn = conectar()

    agendamento = conn.execute("SELECT * FROM agendamentos WHERE id = ?", (id,)).fetchone()
    if not agendamento:
        conn.close()
        flash("Agendamento não encontrado.", "danger")
        return redirect(url_for("agendamentos"))

    if current_user.tem_perfil("tecnico") and not current_user.tem_perfil("admin", "almoxarifado"):
        tecnico_pessoal = tecnico_do_usuario()
        if not tecnico_pessoal or int(agendamento["tecnico_id"]) != int(tecnico_pessoal["id"]):
            conn.close()
            flash("Você só pode alterar seus próprios agendamentos.", "danger")
            return redirect(url_for("agendamentos"))

    conn.execute("""
        UPDATE agendamentos
        SET status = 'cancelado'
        WHERE id = ?
          AND status = 'aberto'
    """, (id,))

    conn.commit()
    conn.close()

    flash("Agendamento cancelado.", "success")

    return redirect(url_for("agendamentos"))


# =========================================================
# KITS PREVENTIVOS
# =========================================================

def _mac_ids_validos(conn, equipamento_id, ids, tecnico_id=None, status='estoque'):
    """Retorna unidades MAC válidas para um equipamento.
    Em estoque: livres para entrar no kit.
    Em kit: já vinculadas ao técnico informado.
    """
    ids = [str(x) for x in ids if str(x).isdigit()]
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    params = [equipamento_id, *[int(x) for x in ids]]
    sql = f"SELECT * FROM unidades WHERE equipamento_id = ? AND id IN ({placeholders}) AND status = ?"
    params.append(status)
    if status == "estoque":
        sql += " AND tecnico_id IS NULL"
    elif tecnico_id is not None:
        sql += " AND tecnico_id = ?"
        params.append(tecnico_id)
    return conn.execute(sql, params).fetchall()


@app.route("/kits-preventivos", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado", "tecnico")
def kits_preventivos():
    conn = conectar()
    tecnicos_lista = conn.execute("SELECT id, nome, ativo FROM tecnicos ORDER BY ativo DESC, nome").fetchall()

    # Técnico só pode consultar o próprio kit. A administração de kits
    # (adicionar/remover itens e configurar padrões) continua restrita.
    if current_user.tem_perfil("tecnico") and not current_user.tem_perfil("admin", "almoxarifado"):
        tecnico_pessoal = tecnico_do_usuario()
        if not tecnico_pessoal:
            conn.close()
            flash("Seu usuário não está vinculado a um técnico.", "danger")
            return redirect(url_for("index"))
        return redirect(url_for("kit_tecnico", tecnico_id=tecnico_pessoal["id"]))

    if request.method == "POST":
        tecnico_id = request.form.get("tecnico_id")
        equipamento_id = request.form.get("equipamento_id")
        mac_ids = request.form.getlist("mac_unidade_ids")
        try:
            quantidade = int(request.form.get("quantidade_padrao", 0))
        except ValueError:
            quantidade = 0

        if not tecnico_id or not equipamento_id or quantidade < 1:
            conn.close()
            flash("Informe o técnico, o equipamento e uma quantidade padrão válida.", "danger")
            return redirect(url_for("kits_preventivos"))

        equipamento = conn.execute("SELECT * FROM equipamentos WHERE id = ?", (equipamento_id,)).fetchone()
        if not equipamento:
            conn.close()
            flash("Equipamento inválido.", "danger")
            return redirect(url_for("kits_preventivos"))

        if equipamento["possui_mac"] and len(mac_ids) != quantidade:
            conn.close()
            flash(f"Para {equipamento['nome']}, selecione exatamente {quantidade} MAC(s) para o kit.", "danger")
            return redirect(url_for("kits_preventivos"))

        if equipamento["possui_mac"]:
            unidades = _mac_ids_validos(conn, equipamento_id, mac_ids, status="estoque")
            if len(unidades) != quantidade:
                conn.close()
                flash("Um ou mais MACs selecionados não estão mais disponíveis em estoque. Atualize a página e tente novamente.", "danger")
                return redirect(url_for("kits_preventivos"))

        kit = conn.execute("SELECT * FROM kits_preventivos WHERE tecnico_id = ?", (tecnico_id,)).fetchone()
        if not kit:
            cur = conn.execute("INSERT INTO kits_preventivos (tecnico_id, criado_em) VALUES (?, ?)", (tecnico_id, datetime.now().isoformat()))
            kit_id = cur.lastrowid
        else:
            kit_id = kit["id"]

        existente = conn.execute(
            "SELECT * FROM kit_preventivo_itens WHERE kit_id = ? AND equipamento_id = ?",
            (kit_id, equipamento_id)
        ).fetchone()

        if existente:
            item_id = existente["id"]
            conn.execute(
                "UPDATE kit_preventivo_itens SET quantidade_padrao = quantidade_padrao + ?, quantidade_atual = quantidade_atual + ? WHERE id = ?",
                (quantidade, quantidade, item_id)
            )
        else:
            conn.execute(
                "INSERT INTO kit_preventivo_itens (kit_id, equipamento_id, quantidade_padrao, quantidade_atual) VALUES (?, ?, ?, ?)",
                (kit_id, equipamento_id, quantidade, quantidade)
            )

        if equipamento["possui_mac"]:
            for u in unidades:
                conn.execute(
                    "UPDATE unidades SET status = 'kit', tecnico_id = ? WHERE id = ?",
                    (tecnico_id, u["id"])
                )
                conn.execute("""
                    INSERT INTO kit_preventivo_movimentos
                    (kit_id, equipamento_id, tipo, quantidade, mac, usuario_id, data, observacao)
                    VALUES (?, ?, 'entrada_kit', 1, ?, ?, ?, ?)
                """, (
                    kit_id, equipamento_id, u["mac"], int(current_user.id), hoje(),
                    "MAC selecionado manualmente para o kit"
                ))
        else:
            conn.execute("""
                INSERT INTO kit_preventivo_movimentos
                (kit_id, equipamento_id, tipo, quantidade, mac, usuario_id, data, observacao)
                VALUES (?, ?, 'entrada_kit', ?, NULL, ?, ?, ?)
            """, (
                kit_id, equipamento_id, quantidade, int(current_user.id), hoje(),
                "Item sem MAC adicionado ao kit"
            ))

        conn.commit()
        conn.close()
        registrar_auditoria("KIT_ITEM_CRIADO", f"Técnico {tecnico_id}; equipamento {equipamento_id}; padrão {quantidade}")
        flash("Item adicionado ao kit preventivo. Se o equipamento já estava no kit, a quantidade foi somada.", "success")
        return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))

    equipamentos_lista = conn.execute("SELECT * FROM equipamentos ORDER BY nome").fetchall()
    resumo = []
    for t in tecnicos_lista:
        kit = conn.execute("SELECT id FROM kits_preventivos WHERE tecnico_id = ?", (t["id"],)).fetchone()
        if kit:
            itens = conn.execute("SELECT quantidade_padrao, quantidade_atual FROM kit_preventivo_itens WHERE kit_id = ?", (kit["id"],)).fetchall()
            total_itens = len(itens)
            pendencias = sum(max(0, i["quantidade_padrao"] - i["quantidade_atual"]) for i in itens)
        else:
            total_itens = 0
            pendencias = 0
        resumo.append({"id": t["id"], "nome": t["nome"], "ativo": t["ativo"], "total_itens": total_itens, "pendencias": pendencias})
    conn.close()

    html = """
    <div class="stat-row"><h1>🧰 Kits preventivos</h1></div>
    <div class="card">
        <h2>Adicionar item ao kit</h2>
        <p class="muted">Defina a quantidade padrão. Se o equipamento tiver MAC, selecione exatamente quais unidades ficarão com o técnico.</p>
        <form method="post" id="form-add-kit">
            <div class="form-grid">
                <div class="form-group"><label>Técnico *</label><select name="tecnico_id" required><option value="">Selecione...</option>{% for t in tecnicos_lista if t.ativo %}<option value="{{ t.id }}">{{ t.nome }}</option>{% endfor %}</select></div>
                <div class="form-group"><label>Equipamento *</label><select name="equipamento_id" id="kit-equipamento" required><option value="">Selecione...</option>{% for e in equipamentos_lista %}<option value="{{ e.id }}" data-mac="{{ 1 if e.possui_mac else 0 }}">{{ e.nome }}{% if e.possui_mac %} — possui MAC{% endif %}</option>{% endfor %}</select></div>
                <div class="form-group"><label>Quantidade padrão *</label><input type="number" name="quantidade_padrao" id="kit-quantidade" min="1" value="1" required></div>
            </div>
            <div id="kit-mac-area" class="form-group" style="display:none; margin-top:12px;">
                <label>Pesquisar e selecionar MACs *</label>
                <input type="text" id="kit-mac-busca" placeholder="Ex.: A4:5E:60" autocomplete="off">
                <div id="kit-mac-lista" class="mac-check-list"></div>
                <div class="muted small">Digite parte do MAC para filtrar. Apenas MACs disponíveis em estoque aparecem.</div>
                <div id="kit-mac-status" class="muted small" style="margin-top:6px;"></div>
            </div>
            <button type="submit">Adicionar ao kit</button>
        </form>
    </div>

    <div class="section card"><h2>Técnicos</h2>
        <div class="table-wrap"><table><tr><th>Técnico</th><th>Itens</th><th>Pendência</th><th>Ação</th></tr>
        {% for r in resumo %}<tr><td><strong>{{ r.nome }}</strong>{% if not r.ativo %} <span class="badge">INATIVO</span>{% endif %}</td><td>{{ r.total_itens }}</td><td>{% if r.pendencias > 0 %}<span class="badge badge-yellow">{{ r.pendencias }} unidade(s)</span>{% else %}<span class="badge badge-green">OK</span>{% endif %}</td><td><a class="btn btn-blue" href="{{ url_for('kit_tecnico', tecnico_id=r.id) }}">Abrir kit</a></td></tr>{% endfor %}
        </table></div>
    </div>
    """

    html += """
    <script>
    (function(){
      const eq=document.getElementById('kit-equipamento'), qtd=document.getElementById('kit-quantidade'), area=document.getElementById('kit-mac-area'), busca=document.getElementById('kit-mac-busca'), lista=document.getElementById('kit-mac-lista'), status=document.getElementById('kit-mac-status');
      let macData=[]; if(!eq) return;
      function render(){const selecionados=new Set(Array.from(lista.querySelectorAll('input:checked')).map(c=>c.value));const f=(busca.value||'').toUpperCase(); lista.innerHTML=''; const rows=macData.filter(u=>u.mac.toUpperCase().includes(f)); rows.forEach(u=>{const l=document.createElement('label');l.className='mac-check-item';const c=document.createElement('input');c.type='checkbox';c.name='mac_unidade_ids';c.value=u.id;c.checked=selecionados.has(String(u.id));l.appendChild(c);const sp=document.createElement('span');sp.textContent=u.mac;l.appendChild(sp);lista.appendChild(l);}); const totalSelecionados=Array.from(lista.querySelectorAll('input:checked')).length; status.textContent=macData.length?(totalSelecionados+' selecionado(s) de '+(qtd.value||0)+' necessário(s) — '+rows.length+' encontrado(s).'):'Nenhum MAC disponível em estoque.';}
      async function load(){const o=eq.options[eq.selectedIndex], on=o&&o.dataset.mac==='1';area.style.display=on?'block':'none';macData=[];lista.innerHTML='';busca.value='';status.textContent='';if(!on||!eq.value)return;status.textContent='Carregando MACs disponíveis...';try{const r=await fetch('{{ url_for("macs_disponiveis_kit") }}?equipamento_id='+encodeURIComponent(eq.value));const d=await r.json();if(!d.ok)throw 0;macData=d.macs||[];render();}catch(e){status.textContent='Não foi possível carregar os MACs disponíveis.';}}
      eq.addEventListener('change',load);qtd.addEventListener('input',render);busca.addEventListener('input',render);lista.addEventListener('change',render);
    })();
    </script>
    """
    return pagina("Kits preventivos", html, tecnicos_lista=tecnicos_lista, equipamentos_lista=equipamentos_lista, resumo=resumo)


@app.route("/kits-preventivos/macs-disponiveis")
@exigir_perfis("admin", "almoxarifado", "tecnico")
def macs_disponiveis_kit():
    equipamento_id = request.args.get("equipamento_id")
    conn = conectar()
    equipamento = conn.execute("SELECT * FROM equipamentos WHERE id = ?", (equipamento_id,)).fetchone()
    if not equipamento or not equipamento["possui_mac"]:
        conn.close()
        return jsonify({"ok": False, "erro": "Equipamento sem controle por MAC."}), 400
    rows = conn.execute("""
        SELECT id, mac FROM unidades
        WHERE equipamento_id = ? AND status = 'estoque' AND tecnico_id IS NULL
        ORDER BY mac
    """, (equipamento_id,)).fetchall()
    conn.close()
    return jsonify({"ok": True, "macs": [{"id": r["id"], "mac": r["mac"]} for r in rows]})


@app.route("/kits-preventivos/<int:tecnico_id>", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado", "tecnico")
def kit_tecnico(tecnico_id):
    conn = conectar()
    if current_user.tem_perfil("tecnico") and not current_user.tem_perfil("admin", "almoxarifado"):
        tecnico_pessoal = tecnico_do_usuario()
        if not tecnico_pessoal or int(tecnico_pessoal["id"]) != int(tecnico_id):
            conn.close()
            flash("Você só pode acessar o seu próprio kit preventivo.", "danger")
            return redirect(url_for("kits_preventivos"))

    tecnico = conn.execute("SELECT * FROM tecnicos WHERE id = ?", (tecnico_id,)).fetchone()
    if not tecnico:
        conn.close(); flash("Técnico não encontrado.", "danger"); return redirect(url_for("kits_preventivos"))

    kit = conn.execute("SELECT * FROM kits_preventivos WHERE tecnico_id = ?", (tecnico_id,)).fetchone()
    if not kit:
        cur = conn.execute("INSERT INTO kits_preventivos (tecnico_id, criado_em) VALUES (?, ?)", (tecnico_id, datetime.now().isoformat()))
        conn.commit()
        kit = conn.execute("SELECT * FROM kits_preventivos WHERE id = ?", (cur.lastrowid,)).fetchone()

    if request.method == "POST":
        acao = request.form.get("acao")
        item_id = request.form.get("item_id")

        if current_user.tem_perfil("tecnico") and not current_user.tem_perfil("admin", "almoxarifado"):
            if acao not in ("consumir", "vincular_macs", "renovar_item", "renovar_todos"):
                conn.close()
                flash("Essa ação não está disponível para técnicos.", "danger")
                return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))

        if acao == "consumir":
            item = conn.execute("SELECT * FROM kit_preventivo_itens WHERE id = ? AND kit_id = ?", (item_id, kit["id"])).fetchone()
            equipamento = conn.execute("SELECT * FROM equipamentos WHERE id = ?", (item["equipamento_id"],)).fetchone() if item else None
            mac_ids = request.form.getlist("mac_unidade_ids")
            try: quantidade = int(request.form.get("quantidade", 0))
            except ValueError: quantidade = 0
            if not item or not equipamento or quantidade < 1 or quantidade > item["quantidade_atual"]:
                conn.close(); flash("Quantidade inválida para o consumo.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
            if equipamento["possui_mac"]:
                if len(mac_ids) != quantidade:
                    conn.close(); flash(f"Selecione exatamente {quantidade} MAC(s) para registrar o consumo.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
                unidades = _mac_ids_validos(conn, equipamento["id"], mac_ids, tecnico_id=tecnico_id, status="kit")
                if len(unidades) != quantidade:
                    conn.close(); flash("Um ou mais MACs selecionados não pertencem mais a este kit.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
                for u in unidades:
                    conn.execute("UPDATE unidades SET status = 'usado', tecnico_id = NULL WHERE id = ?", (u["id"],))
                    conn.execute("""
                        INSERT INTO movimentacoes
                        (equipamento_id, tipo, quantidade, mac, tecnico_id, observacao, data)
                        VALUES (?, 'saida', 1, ?, ?, ?, ?)
                    """, (equipamento["id"], u["mac"], tecnico_id, "Baixa por consumo do kit preventivo", hoje()))
                    conn.execute("""
                        INSERT INTO kit_preventivo_movimentos
                        (kit_id, equipamento_id, tipo, quantidade, mac, usuario_id, data, observacao)
                        VALUES (?, ?, 'consumo', 1, ?, ?, ?, ?)
                    """, (kit["id"], equipamento["id"], u["mac"], int(current_user.id), hoje(), "Consumo de unidade MAC do kit; baixa registrada como saída"))
            else:
                conn.execute("""
                    INSERT INTO movimentacoes
                    (equipamento_id, tipo, quantidade, tecnico_id, observacao, data)
                    VALUES (?, 'saida', ?, ?, ?, ?)
                """, (equipamento["id"], quantidade, tecnico_id, "Baixa por consumo do kit preventivo", hoje()))
                conn.execute("""
                    INSERT INTO kit_preventivo_movimentos
                    (kit_id, equipamento_id, tipo, quantidade, mac, usuario_id, data, observacao)
                    VALUES (?, ?, 'consumo', ?, NULL, ?, ?, ?)
                """, (kit["id"], equipamento["id"], quantidade, int(current_user.id), hoje(), "Consumo de item sem MAC do kit; baixa registrada como saída"))
            conn.execute("UPDATE kit_preventivo_itens SET quantidade_atual = quantidade_atual - ? WHERE id = ?", (quantidade, item_id))
            conn.commit(); conn.close()
            registrar_auditoria("KIT_CONSUMO", f"Técnico {tecnico_id}; item {item_id}; quantidade {quantidade}")
            flash("Consumo registrado no kit.", "success")
            return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))

        if acao == "remover":
            item = conn.execute("SELECT * FROM kit_preventivo_itens WHERE id = ? AND kit_id = ?", (item_id, kit["id"])).fetchone()
            if item:
                equipamento = conn.execute("SELECT * FROM equipamentos WHERE id = ?", (item["equipamento_id"],)).fetchone()
                if equipamento["possui_mac"]:
                    conn.execute("UPDATE unidades SET status = 'estoque', tecnico_id = NULL WHERE equipamento_id = ? AND tecnico_id = ? AND status = 'kit'", (item["equipamento_id"], tecnico_id))
                conn.execute("DELETE FROM kit_preventivo_itens WHERE id = ?", (item_id,))
                conn.commit()
                flash("Item removido do kit.", "success")
            conn.close()
            return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))

        if acao == "vincular_macs":
            item = conn.execute("""
                SELECT i.*, e.nome, e.possui_mac
                FROM kit_preventivo_itens i JOIN equipamentos e ON e.id = i.equipamento_id
                WHERE i.id = ? AND i.kit_id = ?
            """, (item_id, kit["id"])).fetchone()
            mac_ids = request.form.getlist("mac_unidade_ids")
            if not item or not item["possui_mac"]:
                conn.close(); flash("Item inválido para vinculação de MAC.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
            vinculados = conn.execute("SELECT COUNT(*) FROM unidades WHERE equipamento_id = ? AND tecnico_id = ? AND status = 'kit'", (item["equipamento_id"], tecnico_id)).fetchone()[0]
            falta_vinculo = max(0, item["quantidade_atual"] - vinculados)
            if len(mac_ids) != falta_vinculo:
                conn.close(); flash(f"Selecione exatamente {falta_vinculo} MAC(s) para vincular ao item.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
            unidades = _mac_ids_validos(conn, item["equipamento_id"], mac_ids, status="estoque")
            if len(unidades) != falta_vinculo:
                conn.close(); flash("Um ou mais MACs não estão disponíveis em estoque.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
            for u in unidades:
                conn.execute("UPDATE unidades SET status = 'kit', tecnico_id = ? WHERE id = ?", (tecnico_id, u["id"]))
                conn.execute("""
                    INSERT INTO kit_preventivo_movimentos
                    (kit_id, equipamento_id, tipo, quantidade, mac, usuario_id, data, observacao)
                    VALUES (?, ?, 'vinculacao', 1, ?, ?, ?, ?)
                """, (kit["id"], item["equipamento_id"], u["mac"], int(current_user.id), hoje(), "Vinculação de MAC ao kit"))
            conn.commit(); conn.close()
            registrar_auditoria("KIT_MAC_VINCULADO", f"Técnico {tecnico_id}; item {item_id}; quantidade {falta_vinculo}")
            flash("MAC(s) vinculado(s) ao kit.", "success")
            return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))

        if acao == "renovar_item":
            item = conn.execute("""
                SELECT i.*, e.nome, e.possui_mac
                FROM kit_preventivo_itens i JOIN equipamentos e ON e.id = i.equipamento_id
                WHERE i.id = ? AND i.kit_id = ?
            """, (item_id, kit["id"])).fetchone()
            if not item:
                conn.close(); flash("Item do kit não encontrado.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
            falta = max(0, item["quantidade_padrao"] - item["quantidade_atual"])
            if falta == 0:
                conn.close(); flash("Esse item já está completo.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
            if item["possui_mac"]:
                mac_ids = request.form.getlist("mac_unidade_ids")
                if len(mac_ids) != falta:
                    conn.close(); flash(f"Selecione exatamente {falta} MAC(s) para renovar este item.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
                unidades = _mac_ids_validos(conn, item["equipamento_id"], mac_ids, status="estoque")
                if len(unidades) != falta:
                    conn.close(); flash("Um ou mais MACs selecionados não estão disponíveis em estoque.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
                for u in unidades:
                    conn.execute("UPDATE unidades SET status = 'kit', tecnico_id = ? WHERE id = ?", (tecnico_id, u["id"]))
                    conn.execute("""
                        INSERT INTO movimentacoes
                        (equipamento_id, tipo, quantidade, mac, tecnico_id, observacao, data)
                        VALUES (?, 'saida', 1, ?, ?, ?, ?)
                    """, (item["equipamento_id"], u["mac"], tecnico_id, "Saída para reposição do kit preventivo", hoje()))
                    conn.execute("""
                        INSERT INTO kit_preventivo_movimentos
                        (kit_id, equipamento_id, tipo, quantidade, mac, usuario_id, data, observacao)
                        VALUES (?, ?, 'renovacao', 1, ?, ?, ?, ?)
                    """, (kit["id"], item["equipamento_id"], u["mac"], int(current_user.id), hoje(), "Renovação do kit com MAC selecionado; saída registrada"))
            else:
                disponiveis = estoque_equipamento(conn, item["equipamento_id"])
                if disponiveis < falta:
                    conn.close(); flash(f"Estoque insuficiente para {item['nome']}: faltam {falta}, disponíveis {disponiveis}.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
                conn.execute("INSERT INTO movimentacoes (equipamento_id, tipo, quantidade, tecnico_id, observacao, data) VALUES (?, 'saida', ?, ?, ?, ?)", (item["equipamento_id"], falta, tecnico_id, "Renovação do kit preventivo", hoje()))
                conn.execute("""
                    INSERT INTO kit_preventivo_movimentos
                    (kit_id, equipamento_id, tipo, quantidade, mac, usuario_id, data, observacao)
                    VALUES (?, ?, 'renovacao', ?, NULL, ?, ?, ?)
                """, (kit["id"], item["equipamento_id"], falta, int(current_user.id), hoje(), "Renovação do kit preventivo"))
            conn.execute("UPDATE kit_preventivo_itens SET quantidade_atual = quantidade_atual + ? WHERE id = ?", (falta, item_id))
            conn.commit(); conn.close()
            registrar_auditoria("KIT_RENOVADO_ITEM", f"Técnico {tecnico_id}; item {item_id}; quantidade {falta}")
            flash("Item do kit renovado.", "success")
            return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))

    # Confirmação da renovação geral. Para cada item com MAC, os IDs selecionados
    # precisam pertencer ao estoque e corresponder exatamente à falta.
    if request.method == "POST" and request.form.get("acao") == "renovar_todos":
        itens = conn.execute("""
            SELECT i.*, e.nome, e.possui_mac
            FROM kit_preventivo_itens i JOIN equipamentos e ON e.id = i.equipamento_id
            WHERE i.kit_id = ? ORDER BY e.nome
        """, (kit["id"],)).fetchall()

        # Valida tudo antes de alterar o banco, para não deixar o kit parcialmente renovado.
        planos = []
        erro = None
        for item in itens:
            falta = max(0, item["quantidade_padrao"] - item["quantidade_atual"])
            if falta <= 0:
                continue
            if item["possui_mac"]:
                mac_ids = request.form.getlist(f"macs_item_{item['id']}")
                if len(mac_ids) != falta:
                    erro = f"{item['nome']}: selecione exatamente {falta} MAC(s)."
                    break
                unidades = _mac_ids_validos(conn, item["equipamento_id"], mac_ids, status="estoque")
                if len(unidades) != falta:
                    erro = f"{item['nome']}: um ou mais MACs não estão mais disponíveis em estoque."
                    break
                planos.append((item, falta, unidades))
            else:
                disponiveis = estoque_equipamento(conn, item["equipamento_id"])
                if disponiveis < falta:
                    erro = f"Estoque insuficiente para {item['nome']}: faltam {falta}, disponíveis {disponiveis}."
                    break
                planos.append((item, falta, []))

        if erro:
            conn.close()
            flash(erro, "danger")
            return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id, renovar=1))

        for item, falta, unidades in planos:
            if item["possui_mac"]:
                for u in unidades:
                    conn.execute("UPDATE unidades SET status = 'kit', tecnico_id = ? WHERE id = ?", (tecnico_id, u["id"]))
                    conn.execute("""
                        INSERT INTO movimentacoes
                        (equipamento_id, tipo, quantidade, mac, tecnico_id, observacao, data)
                        VALUES (?, 'saida', 1, ?, ?, ?, ?)
                    """, (item["equipamento_id"], u["mac"], tecnico_id, "Saída para reposição do kit preventivo", hoje()))
                    conn.execute("""
                        INSERT INTO kit_preventivo_movimentos
                        (kit_id, equipamento_id, tipo, quantidade, mac, usuario_id, data, observacao)
                        VALUES (?, ?, 'renovacao', 1, ?, ?, ?, ?)
                    """, (kit["id"], item["equipamento_id"], u["mac"], int(current_user.id), hoje(), "Renovação semanal com MAC selecionado; saída registrada"))
            else:
                conn.execute("""
                    INSERT INTO movimentacoes
                    (equipamento_id, tipo, quantidade, tecnico_id, observacao, data)
                    VALUES (?, 'saida', ?, ?, ?, ?)
                """, (item["equipamento_id"], falta, tecnico_id, "Renovação do kit preventivo", hoje()))
                conn.execute("""
                    INSERT INTO kit_preventivo_movimentos
                    (kit_id, equipamento_id, tipo, quantidade, mac, usuario_id, data, observacao)
                    VALUES (?, ?, 'renovacao', ?, NULL, ?, ?, ?)
                """, (kit["id"], item["equipamento_id"], falta, int(current_user.id), hoje(), "Renovação semanal do kit preventivo"))
            conn.execute("UPDATE kit_preventivo_itens SET quantidade_atual = quantidade_atual + ? WHERE id = ?", (falta, item["id"]))

        conn.commit()
        conn.close()
        registrar_auditoria("KIT_RENOVADO", f"Técnico {tecnico_id}; itens renovados {len(planos)}")
        flash("Kit renovado com sucesso.", "success")
        return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))

    # Renovação geral continua prática: para itens MAC, se houver falta, a tela
    # solicita a escolha dos MACs antes de executar; itens sem MAC podem ser renovados diretamente.
    if request.args.get("renovar") == "1":
        itens = conn.execute("SELECT i.*, e.nome, e.possui_mac FROM kit_preventivo_itens i JOIN equipamentos e ON e.id = i.equipamento_id WHERE i.kit_id = ? ORDER BY e.nome", (kit["id"],)).fetchall()
        pendencias_mac = []
        for item in itens:
            falta = max(0, item["quantidade_padrao"] - item["quantidade_atual"])
            if falta > 0 and item["possui_mac"]:
                disponiveis = conn.execute("SELECT id, mac FROM unidades WHERE equipamento_id = ? AND status = 'estoque' AND tecnico_id IS NULL ORDER BY mac", (item["equipamento_id"],)).fetchall()
                pendencias_mac.append({"item": item, "falta": falta, "macs": disponiveis})
        if pendencias_mac:
            conn.close()
            html = """
            <div class="stat-row"><h1>🔄 Renovar kit — {{ tecnico.nome }}</h1><a class="btn btn-secondary" href="{{ url_for('kit_tecnico', tecnico_id=tecnico.id) }}">Voltar</a></div>
            <div class="card"><p class="muted">Selecione os MACs que substituirão os equipamentos utilizados. Itens sem MAC podem ser renovados automaticamente na mesma confirmação.</p></div>
            <form method="post" class="card">
            <input type="hidden" name="acao" value="renovar_todos">
            {% for p in pendencias_mac %}
              <div class="card" style="margin-bottom:12px;">
                <h3>{{ p.item.nome }} — selecionar {{ p.falta }} MAC(s)</h3>
                {% if p.macs %}
                  <input type="text" class="kit-renova-busca" data-item="{{ p.item.id }}" placeholder="Pesquisar MAC..." autocomplete="off">
                  <div class="kit-renova-lista" data-item="{{ p.item.id }}">{% for m in p.macs %}<label class="mac-check-item"><input type="checkbox" name="macs_item_{{ p.item.id }}" value="{{ m.id }}"><span>{{ m.mac }}</span></label>{% endfor %}</div>
                  <div class="muted small">Selecione exatamente {{ p.falta }} MAC(s).</div>
                {% else %}<div class="empty">Nenhum MAC disponível em estoque.</div>{% endif %}
              </div>
            {% endfor %}
            <button type="submit" class="btn btn-green">Confirmar renovação do kit</button>
            </form>
            <script>
            document.querySelectorAll('.kit-renova-busca').forEach(inp=>{inp.addEventListener('input',()=>{const f=inp.value.toUpperCase();const box=document.querySelector('.kit-renova-lista[data-item="'+inp.dataset.item+'"]');box.querySelectorAll('.mac-check-item').forEach(x=>{x.style.display=x.innerText.toUpperCase().includes(f)?'flex':'none';});});});
            </script>
            """
            return pagina("Renovar kit", html, tecnico=tecnico, pendencias_mac=pendencias_mac)

        # Se não houver pendências de MAC, renova automaticamente os itens sem MAC.
        for item in itens:
            falta = max(0, item["quantidade_padrao"] - item["quantidade_atual"])
            if falta <= 0: continue
            disponiveis = estoque_equipamento(conn, item["equipamento_id"])
            if disponiveis < falta:
                conn.close(); flash(f"Estoque insuficiente para {item['nome']}: faltam {falta}, disponíveis {disponiveis}.", "danger"); return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))
            conn.execute("INSERT INTO movimentacoes (equipamento_id, tipo, quantidade, tecnico_id, observacao, data) VALUES (?, 'saida', ?, ?, ?, ?)", (item["equipamento_id"], falta, tecnico_id, "Renovação do kit preventivo", hoje()))
            conn.execute("INSERT INTO kit_preventivo_movimentos (kit_id, equipamento_id, tipo, quantidade, mac, usuario_id, data, observacao) VALUES (?, ?, 'renovacao', ?, NULL, ?, ?, ?)", (kit["id"], item["equipamento_id"], falta, int(current_user.id), hoje(), "Renovação semanal do kit preventivo"))
            conn.execute("UPDATE kit_preventivo_itens SET quantidade_atual = quantidade_atual + ? WHERE id = ?", (falta, item["id"]))
        conn.commit(); conn.close()
        registrar_auditoria("KIT_RENOVADO", f"Técnico {tecnico_id}")
        flash("Kit renovado com sucesso.", "success")
        return redirect(url_for("kit_tecnico", tecnico_id=tecnico_id))

    itens = conn.execute("""
        SELECT i.*, e.nome, e.possui_mac
        FROM kit_preventivo_itens i JOIN equipamentos e ON e.id = i.equipamento_id
        WHERE i.kit_id = ? ORDER BY e.nome
    """, (kit["id"],)).fetchall()
    equipamentos_lista = conn.execute("SELECT * FROM equipamentos ORDER BY nome").fetchall()
    historico = conn.execute("""
        SELECT m.*, strftime('%d/%m/%Y %H:%M:%S', COALESCE(m.data_hora, m.data || ' 00:00:00')) AS data_hora_exibicao, e.nome AS equipamento, u.nome AS usuario
        FROM kit_preventivo_movimentos m
        JOIN equipamentos e ON e.id = m.equipamento_id
        LEFT JOIN usuarios u ON u.id = m.usuario_id
        WHERE m.kit_id = ?
        ORDER BY COALESCE(m.data_hora, m.data || ' 00:00:00') DESC, m.id DESC
    """, (kit["id"],)).fetchall()

    # MACs atualmente vinculados a este técnico, agrupados por equipamento.
    macs_kit = {}
    macs_disponiveis = {}
    for row in conn.execute("""
        SELECT
            u.id, u.equipamento_id, u.mac,
            (
                SELECT strftime('%d/%m/%Y %H:%M:%S', COALESCE(kpm.data_hora, kpm.data || ' 00:00:00'))
                FROM kit_preventivo_movimentos kpm
                WHERE kpm.kit_id = ?
                  AND kpm.equipamento_id = u.equipamento_id
                  AND kpm.mac = u.mac
                  AND kpm.tipo IN ('entrada_kit', 'vinculacao', 'renovacao')
                ORDER BY kpm.id DESC
                LIMIT 1
            ) AS colocado_em
        FROM unidades u
        WHERE u.tecnico_id = ? AND u.status = 'kit'
        ORDER BY u.mac
    """, (kit["id"], tecnico_id)).fetchall():
        macs_kit.setdefault(row["equipamento_id"], []).append(row)
    for row in conn.execute("""
        SELECT u.id, u.equipamento_id, u.mac
        FROM unidades u
        WHERE u.status = 'estoque' AND u.tecnico_id IS NULL
        ORDER BY u.mac
    """).fetchall():
        macs_disponiveis.setdefault(row["equipamento_id"], []).append(row)
    conn.close()

    html = """
    <div class="stat-row"><h1>🧰 Kit preventivo — {{ tecnico.nome }}</h1><a class="btn btn-secondary" href="{{ url_for('kits_preventivos') }}">Voltar</a></div>
    <div class="card">
        <div class="actions"><a class="btn btn-green" href="{{ url_for('kit_tecnico', tecnico_id=tecnico.id, renovar=1) }}">🔄 Renovar kit</a></div>
        <p class="muted">Os itens ficam reservados no kit. A baixa definitiva do estoque acontece quando o técnico registra o consumo; nesse momento o sistema gera automaticamente uma <strong>SAÍDA</strong> com data, hora e MAC/identificador.</p>
    </div>
    <div class="card"><h2>Itens do kit</h2>
    {% if itens %}<div class="table-wrap"><table><tr><th>Equipamento</th><th>Padrão</th><th>Atual</th><th>Falta</th><th>MAC/Identificador</th><th>Colocado no kit</th><th>Ação</th></tr>
    {% for i in itens %}
      <tr>
        <td>{{ i.nome }}{% if i.possui_mac %} <span class="badge badge-blue">MAC</span>{% endif %}</td>
        <td>{{ i.quantidade_padrao }}</td><td>{{ i.quantidade_atual }}</td>
        <td>{% if i.quantidade_padrao > i.quantidade_atual %}<span class="badge badge-yellow">{{ i.quantidade_padrao - i.quantidade_atual }}</span>{% else %}<span class="badge badge-green">OK</span>{% endif %}</td>
        <td>
          {% if i.possui_mac and macs_kit.get(i.equipamento_id) %}
            {% for m in macs_kit.get(i.equipamento_id) %}<div><strong>{{ m.mac }}</strong></div>{% endfor %}
          {% elif i.possui_mac %}<span class="muted">Nenhum MAC vinculado</span>
          {% else %}<span class="muted">Não se aplica</span>{% endif %}
        </td>
        <td>
          {% if i.possui_mac and macs_kit.get(i.equipamento_id) %}
            {% for m in macs_kit.get(i.equipamento_id) %}<div>{{ m.colocado_em }}</div>{% endfor %}
          {% elif i.possui_mac %}-{% else %}Não se aplica{% endif %}
        </td>
        <td>
          {% if i.quantidade_atual > 0 %}
          <form method="post" class="toolbar" style="margin-bottom:8px;">
            <input type="hidden" name="acao" value="consumir"><input type="hidden" name="item_id" value="{{ i.id }}">
            <input type="number" name="quantidade" min="1" max="{{ i.quantidade_atual }}" value="1" style="max-width:90px">
            {% if i.possui_mac %}
              <select name="mac_unidade_ids" multiple size="3" style="min-width:240px;">
                {% for m in macs_kit.get(i.equipamento_id, []) %}<option value="{{ m.id }}">{{ m.mac }}</option>{% endfor %}
              </select>
            {% endif %}
            <button class="btn btn-blue" type="submit">Registrar consumo</button>
          </form>
          {% endif %}
          {% if i.possui_mac and i.quantidade_atual > (macs_kit.get(i.equipamento_id, [])|length) %}
            <form method="post" class="toolbar" style="margin-bottom:8px;">
              <input type="hidden" name="acao" value="vincular_macs"><input type="hidden" name="item_id" value="{{ i.id }}">
              <select name="mac_unidade_ids" multiple size="3" style="min-width:240px;">
                {% for m in macs_disponiveis.get(i.equipamento_id, []) %}<option value="{{ m.id }}">{{ m.mac }}</option>{% endfor %}
              </select>
              <button class="btn btn-green" type="submit">Vincular MAC(s)</button>
            </form>
          {% endif %}
          {% if current_user.tem_perfil('admin', 'almoxarifado') %}
          <form method="post"><input type="hidden" name="acao" value="remover"><input type="hidden" name="item_id" value="{{ i.id }}"><button class="btn btn-red" type="submit">Remover</button></form>
          {% endif %}
        </td>
      </tr>
    {% endfor %}</table></div>
    {% else %}<div class="empty">Nenhum item configurado neste kit.</div>{% endif %}
    </div>
    {% if current_user.tem_perfil('admin', 'almoxarifado') %}<div class="card"><h2>Adicionar item</h2><form method="post"><div class="form-grid"><div class="form-group"><label>Equipamento *</label><select name="equipamento_id" id="kit-equipamento-detalhe" required><option value="">Selecione...</option>{% for e in equipamentos_lista %}<option value="{{ e.id }}" data-mac="{{ 1 if e.possui_mac else 0 }}">{{ e.nome }}{% if e.possui_mac %} — possui MAC{% endif %}</option>{% endfor %}</select></div><div class="form-group"><label>Quantidade padrão *</label><input type="number" name="quantidade_padrao" id="kit-quantidade-detalhe" min="1" value="1" required></div></div><input type="hidden" name="tecnico_id" value="{{ tecnico.id }}"><div id="kit-mac-area-detalhe" class="form-group" style="display:none;margin-top:10px;"><label>Pesquisar e selecionar MACs *</label><input type="text" id="kit-mac-busca-detalhe" placeholder="Ex.: A4:5E:60" autocomplete="off"><div id="kit-mac-lista-detalhe" class="mac-check-list"></div><div class="muted small">Digite parte do MAC para filtrar. Apenas MACs disponíveis em estoque aparecem.</div><div id="kit-mac-status-detalhe" class="muted small"></div></div><button type="submit" formaction="{{ url_for('kits_preventivos') }}">Adicionar ao kit</button></form></div>{% endif %}
    <div class="card"><h2>Histórico completo do kit</h2>{% if historico %}<div class="table-wrap"><table><tr><th>Data e hora</th><th>Equipamento</th><th>MAC/Identificador</th><th>Tipo</th><th>Quantidade</th><th>Usuário</th><th>Observação</th></tr>{% for h in historico %}<tr><td>{{ h.data_hora_exibicao }}</td><td>{{ h.equipamento }}</td><td>{{ h.mac or '-' }}</td><td><span class="badge">{{ h.tipo|upper }}</span></td><td>{{ h.quantidade }}</td><td>{{ h.usuario or '-' }}</td><td>{{ h.observacao or '-' }}</td></tr>{% endfor %}</table></div>{% else %}<div class="empty">Nenhuma movimentação do kit ainda.</div>{% endif %}</div>
    """

    html += """
    <script>
    (function(){
      const eq=document.getElementById('kit-equipamento-detalhe'),qtd=document.getElementById('kit-quantidade-detalhe'),area=document.getElementById('kit-mac-area-detalhe'),busca=document.getElementById('kit-mac-busca-detalhe'),lista=document.getElementById('kit-mac-lista-detalhe'),st=document.getElementById('kit-mac-status-detalhe');let macData=[];if(!eq)return;
      function render(){const selecionados=new Set(Array.from(lista.querySelectorAll('input:checked')).map(c=>c.value));const f=(busca.value||'').toUpperCase();lista.innerHTML='';const rows=macData.filter(u=>u.mac.toUpperCase().includes(f));rows.forEach(u=>{const l=document.createElement('label');l.className='mac-check-item';const c=document.createElement('input');c.type='checkbox';c.name='mac_unidade_ids';c.value=u.id;c.checked=selecionados.has(String(u.id));l.appendChild(c);const sp=document.createElement('span');sp.textContent=u.mac;l.appendChild(sp);lista.appendChild(l);});st.textContent=macData.length?(lista.querySelectorAll('input:checked').length+' selecionado(s) de '+(qtd.value||0)+' necessário(s) — '+rows.length+' encontrado(s).'):'Nenhum MAC disponível em estoque.';}
      async function load(){const o=eq.options[eq.selectedIndex],on=o&&o.dataset.mac==='1';area.style.display=on?'block':'none';macData=[];lista.innerHTML='';busca.value='';if(!on||!eq.value)return;st.textContent='Carregando MACs disponíveis...';try{const r=await fetch('{{ url_for("macs_disponiveis_kit") }}?equipamento_id='+encodeURIComponent(eq.value));const d=await r.json();if(!d.ok)throw 0;macData=d.macs||[];render();}catch(e){st.textContent='Não foi possível carregar os MACs.';}}
      eq.addEventListener('change',load);qtd.addEventListener('input',render);busca.addEventListener('input',render);lista.addEventListener('change',render);
    })();
    </script>
    """
    return pagina("Kit preventivo", html, tecnico=tecnico, itens=itens, equipamentos_lista=equipamentos_lista, historico=historico, macs_kit=macs_kit, macs_disponiveis=macs_disponiveis)


# =========================================================
# DEFEITOS
# =========================================================


@app.route("/defeitos", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado", "tecnico", "consulta")
def defeitos():
    conn = conectar()

    equipamentos_lista = conn.execute("""
        SELECT *
        FROM equipamentos
        ORDER BY nome
    """).fetchall()

    tecnicos_lista = conn.execute("""
        SELECT *
        FROM tecnicos
        ORDER BY nome
    """).fetchall()

    if request.method == "POST":
        equipamento_id = request.form.get("equipamento_id")
        mac = request.form.get("mac", "").strip().upper()
        descricao = request.form.get("descricao", "").strip()
        tecnico_id = request.form.get("tecnico_id") or None

        if not equipamento_id or not descricao:
            conn.close()
            flash(
                "Informe o equipamento e a descrição do defeito.",
                "danger"
            )
            return redirect(url_for("defeitos"))

        conn.execute("""
            INSERT INTO defeitos (
                equipamento_id,
                mac,
                descricao,
                data,
                status,
                tecnico_id
            )
            VALUES (?, ?, ?, ?, 'aberto', ?)
        """, (
            equipamento_id,
            mac or None,
            descricao,
            hoje(),
            tecnico_id
        ))

        conn.commit()
        conn.close()

        flash("Defeito registrado.", "success")
        return redirect(url_for("defeitos"))

    lista = conn.execute("""
        SELECT
            d.*,
            e.nome AS equipamento,
            t.nome AS tecnico
        FROM defeitos d
        JOIN equipamentos e ON e.id = d.equipamento_id
        LEFT JOIN tecnicos t ON t.id = d.tecnico_id
        ORDER BY
            CASE WHEN d.status = 'aberto' THEN 0 ELSE 1 END,
            d.id DESC
    """).fetchall()

    conn.close()

    html = """
    <h1>Equipamentos com defeito</h1>

    {% if current_user.tem_perfil('admin', 'almoxarifado', 'tecnico') %}
    <div class="card">
        <h2>Registrar defeito</h2>

        <form method="post">

            <div class="form-grid">

                <div class="form-group">
                    <label>Equipamento *</label>
                    <select name="equipamento_id" required>
                        <option value="">Selecione...</option>

                        {% for e in equipamentos_lista %}
                        <option value="{{ e.id }}">
                            {{ e.nome }}
                        </option>
                        {% endfor %}
                    </select>
                </div>

                <div class="form-group">
                    <label>MAC, se aplicável</label>
                    <input type="text"
                           name="mac"
                           placeholder="Digite o identificador / MAC da unidade">
                </div>

                <div class="form-group">
                    <label>Técnico</label>
                    <select name="tecnico_id">
                        <option value="">Não informado</option>

                        {% for t in tecnicos_lista %}
                        <option value="{{ t.id }}">
                            {{ t.nome }}
                        </option>
                        {% endfor %}
                    </select>
                </div>

                <div class="form-group full">
                    <label>Descrição do defeito *</label>

                    <textarea name="descricao"
                              required
                              placeholder="Descreva o problema encontrado..."></textarea>
                </div>

            </div>

            <button type="submit" class="btn-red">
                Registrar defeito
            </button>

        </form>
    </div>
    {% endif %}

    <div class="section card">
        <h2>Defeitos registrados</h2>

        {% if lista %}
        <div class="table-wrap">
            <table>
                <tr>
                    <th>Data</th>
                    <th>Equipamento</th>
                    <th>MAC</th>
                    <th>Técnico</th>
                    <th>Descrição</th>
                    <th>Status</th>
                    <th>Ação</th>
                </tr>

                {% for d in lista %}
                <tr>
                    <td>{{ d.data }}</td>
                    <td>{{ d.equipamento }}</td>
                    <td>{{ d.mac or '-' }}</td>
                    <td>{{ d.tecnico or '-' }}</td>
                    <td>{{ d.descricao }}</td>

                    <td>
                        {% if d.status == 'aberto' %}
                            <span class="badge badge-red">ABERTO</span>
                        {% elif d.status == 'consertado' %}
                            <span class="badge badge-green">CONSERTADO</span>
                        {% else %}
                            <span class="badge">DESCARTADO</span>
                        {% endif %}
                    </td>

                    <td>
                        {% if d.status == 'aberto' and current_user.tem_perfil('admin', 'almoxarifado') %}
                        <div class="actions">
                            <a class="btn btn-green"
                               href="{{ url_for('status_defeito', id=d.id, status='consertado') }}">
                               Consertado
                            </a>

                            <a class="btn btn-red"
                               href="{{ url_for('status_defeito', id=d.id, status='descartado') }}">
                               Descartado
                            </a>
                        </div>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% else %}
            <div class="empty">
                Nenhum defeito registrado.
            </div>
        {% endif %}
    </div>
    """

    return pagina(
        "Defeitos",
        html,
        equipamentos_lista=equipamentos_lista,
        tecnicos_lista=tecnicos_lista,
        lista=lista
    )


@app.route("/defeitos/<int:id>/status")
@exigir_perfis("admin", "almoxarifado")
def status_defeito(id):
    status = request.args.get("status")

    if status not in ("consertado", "descartado"):
        flash("Status inválido.", "danger")
        return redirect(url_for("defeitos"))

    conn = conectar()

    conn.execute("""
        UPDATE defeitos
        SET status = ?
        WHERE id = ?
    """, (status, id))

    conn.commit()
    conn.close()

    flash("Status do defeito atualizado.", "success")

    return redirect(url_for("defeitos"))


# =========================================================
# FECHAMENTO SEMANAL
# =========================================================


@app.route("/fechamento-semanal/tecnico/<int:tecnico_id>")
@exigir_perfis("admin", "almoxarifado")
def relatorio_semanal_tecnico(tecnico_id):
    """Relatório detalhado de uma semana para um técnico.

    Se a semana estiver fechada, os limites registrados no fechamento são
    usados para que o relatório permaneça exatamente igual ao momento do
    fechamento. Se estiver aberta, todos os registros do período aparecem.
    """
    inicio, fim = periodo_semana(request.args.get("inicio"))
    conn = conectar()
    tecnico = conn.execute("SELECT * FROM tecnicos WHERE id = ?", (tecnico_id,)).fetchone()
    if not tecnico:
        conn.close()
        flash("Técnico não encontrado.", "danger")
        return redirect(url_for("fechamento_semanal", inicio=inicio))

    fechamento = conn.execute(
        "SELECT * FROM fechamentos_semanais WHERE tecnico_id = ? AND semana_inicio = ?",
        (tecnico_id, inicio)
    ).fetchone()
    # Um fechamento sem movimentações também precisa ficar congelado. Por isso
    # usamos a data/hora do fechamento como limite, e não somente o último ID.
    limite_mov = " AND COALESCE(m.data_hora, m.data || ' 00:00:00') <= ?" if fechamento else ""
    params_limite_mov = (fechamento["fechado_em"],) if fechamento else ()

    movimentos = conn.execute(f"""
        SELECT m.id, m.data, strftime('%d/%m/%Y %H:%M:%S', COALESCE(m.data_hora, m.data || ' 00:00:00')) AS data_hora,
               m.tipo, m.quantidade, m.mac, m.observacao, e.nome AS equipamento
        FROM movimentacoes m
        JOIN equipamentos e ON e.id = m.equipamento_id
        WHERE m.tecnico_id = ? AND m.data BETWEEN ? AND ?{limite_mov}
        ORDER BY COALESCE(m.data_hora, m.data || ' 00:00:00') ASC, m.id ASC
    """, (tecnico_id, inicio, fim, *params_limite_mov)).fetchall()

    entradas = sum(int(m["quantidade"] or 0) for m in movimentos if m["tipo"] == "entrada")
    saidas = sum(int(m["quantidade"] or 0) for m in movimentos if m["tipo"] == "saida")

    por_equipamento = conn.execute(f"""
        SELECT e.nome AS equipamento,
               SUM(CASE WHEN m.tipo = 'entrada' THEN m.quantidade ELSE 0 END) AS entradas,
               SUM(CASE WHEN m.tipo = 'saida' THEN m.quantidade ELSE 0 END) AS saidas,
               SUM(m.quantidade) AS total
        FROM movimentacoes m
        JOIN equipamentos e ON e.id = m.equipamento_id
        WHERE m.tecnico_id = ? AND m.data BETWEEN ? AND ?{limite_mov}
        GROUP BY m.equipamento_id
        ORDER BY e.nome
    """, (tecnico_id, inicio, fim, *params_limite_mov)).fetchall()

    kit = conn.execute("SELECT * FROM kits_preventivos WHERE tecnico_id = ?", (tecnico_id,)).fetchone()
    kit_movimentos = []
    kit_itens = []
    kit_macs = []
    if kit:
        limite_kit = " AND COALESCE(kpm.data_hora, kpm.data || ' 00:00:00') <= ?" if fechamento else ""
        params_limite_kit = (fechamento["fechado_em"],) if fechamento else ()
        kit_movimentos = conn.execute(f"""
            SELECT kpm.id, strftime('%d/%m/%Y %H:%M:%S', COALESCE(kpm.data_hora, kpm.data || ' 00:00:00')) AS data_hora,
                   kpm.tipo, kpm.quantidade, kpm.mac, kpm.observacao,
                   e.nome AS equipamento, u.nome AS usuario
            FROM kit_preventivo_movimentos kpm
            JOIN equipamentos e ON e.id = kpm.equipamento_id
            LEFT JOIN usuarios u ON u.id = kpm.usuario_id
            WHERE kpm.kit_id = ? AND kpm.data BETWEEN ? AND ?{limite_kit}
            ORDER BY COALESCE(kpm.data_hora, kpm.data || ' 00:00:00') ASC, kpm.id ASC
        """, (kit["id"], inicio, fim, *params_limite_kit)).fetchall()
        kit_itens = conn.execute("""
            SELECT i.*, e.nome, e.possui_mac
            FROM kit_preventivo_itens i JOIN equipamentos e ON e.id = i.equipamento_id
            WHERE i.kit_id = ? ORDER BY e.nome
        """, (kit["id"],)).fetchall()
        kit_macs = conn.execute("""
            SELECT u.mac, e.nome AS equipamento,
                   (SELECT strftime('%d/%m/%Y %H:%M:%S', COALESCE(kpm.data_hora, kpm.data || ' 00:00:00'))
                    FROM kit_preventivo_movimentos kpm
                    WHERE kpm.kit_id = ? AND kpm.mac = u.mac
                      AND kpm.tipo IN ('entrada_kit','vinculacao','renovacao')
                    ORDER BY kpm.id DESC LIMIT 1) AS colocado_em
            FROM unidades u JOIN equipamentos e ON e.id = u.equipamento_id
            WHERE u.tecnico_id = ? AND u.status = 'kit'
            ORDER BY e.nome, u.mac
        """, (kit["id"], tecnico_id)).fetchall()

    conn.close()
    html = """
    <div class="stat-row">
      <h1>Relatório semanal — {{ tecnico.nome }}</h1>
      <span class="badge badge-blue">{{ inicio }} até {{ fim }}</span>
    </div>
    <div class="actions" style="margin-bottom:15px;">
      <a class="btn btn-secondary" href="{{ url_for('fechamento_semanal', inicio=inicio) }}">← Voltar</a>
      {% if fechamento %}<span class="badge badge-green">SEMANA FECHADA em {{ fechamento.fechado_em }}</span>{% else %}<span class="badge badge-yellow">SEMANA ABERTA</span>{% endif %}
    </div>
    <div class="card"><h2>Resumo</h2><div class="stats-grid">
      <div class="stat-card"><div class="stat-number">{{ entradas }}</div><div class="stat-label">Entradas</div></div>
      <div class="stat-card"><div class="stat-number">{{ saidas }}</div><div class="stat-label">Saídas</div></div>
      <div class="stat-card"><div class="stat-number">{{ movimentos|length }}</div><div class="stat-label">Movimentações</div></div>
      <div class="stat-card"><div class="stat-number">{{ kit_movimentos|length }}</div><div class="stat-label">Movimentos do kit</div></div>
    </div></div>
    <div class="card"><h2>Entradas e saídas</h2>
      {% if movimentos %}<div class="table-wrap"><table><tr><th>Data e hora</th><th>Tipo</th><th>Equipamento</th><th>Qtd.</th><th>MAC/Identificador</th><th>Observação</th></tr>
      {% for m in movimentos %}<tr><td>{{ m.data_hora }}</td><td>{% if m.tipo == 'entrada' %}<span class="badge badge-green">ENTRADA</span>{% else %}<span class="badge badge-red">SAÍDA</span>{% endif %}</td><td>{{ m.equipamento }}</td><td>{{ m.quantidade }}</td><td>{{ m.mac or '-' }}</td><td>{{ m.observacao or '-' }}</td></tr>{% endfor %}
      </table></div>{% else %}<div class="empty">Nenhuma entrada ou saída registrada nesta semana.</div>{% endif %}
    </div>
    <div class="card"><h2>Resumo por equipamento</h2>
      {% if por_equipamento %}<div class="table-wrap"><table><tr><th>Equipamento</th><th>Entradas</th><th>Saídas</th><th>Total movimentado</th></tr>{% for e in por_equipamento %}<tr><td>{{ e.equipamento }}</td><td>{{ e.entradas }}</td><td>{{ e.saidas }}</td><td>{{ e.total }}</td></tr>{% endfor %}</table></div>{% else %}<div class="empty">Nenhum equipamento movimentado nesta semana.</div>{% endif %}
    </div>
    <div class="card"><h2>Kit preventivo — histórico da semana</h2>
      {% if kit_movimentos %}<div class="table-wrap"><table><tr><th>Data e hora</th><th>Tipo</th><th>Equipamento</th><th>MAC/Identificador</th><th>Qtd.</th><th>Usuário</th><th>Observação</th></tr>{% for k in kit_movimentos %}<tr><td>{{ k.data_hora }}</td><td>{{ k.tipo|upper }}</td><td>{{ k.equipamento }}</td><td>{{ k.mac or '-' }}</td><td>{{ k.quantidade }}</td><td>{{ k.usuario or '-' }}</td><td>{{ k.observacao or '-' }}</td></tr>{% endfor %}</table></div>{% else %}<div class="empty">Nenhuma movimentação do kit nesta semana.</div>{% endif %}
    </div>
    <div class="card"><h2>Equipamentos atualmente no kit</h2>
      {% if kit_itens %}<div class="table-wrap"><table><tr><th>Equipamento</th><th>Padrão</th><th>Atual</th><th>MAC/Identificador</th><th>Colocado em</th></tr>
      {% for i in kit_itens %}<tr><td>{{ i.nome }}</td><td>{{ i.quantidade_padrao }}</td><td>{{ i.quantidade_atual }}</td><td>{% if i.possui_mac %}{% for m in kit_macs if m.equipamento == i.nome %}{{ m.mac }}{% if not loop.last %}<br>{% endif %}{% endfor %}{% else %}-{% endif %}</td><td>{% if i.possui_mac %}{% for m in kit_macs if m.equipamento == i.nome %}{{ m.colocado_em }}{% if not loop.last %}<br>{% endif %}{% endfor %}{% else %}-{% endif %}</td></tr>{% endfor %}</table></div>{% else %}<div class="empty">Nenhum item configurado no kit.</div>{% endif %}
    </div>
    """
    return pagina("Relatório semanal", html, tecnico=tecnico, inicio=inicio, fim=fim, fechamento=fechamento, entradas=entradas, saidas=saidas, movimentos=movimentos, por_equipamento=por_equipamento, kit_movimentos=kit_movimentos, kit_itens=kit_itens, kit_macs=kit_macs)


@app.route("/fechamento-semanal", methods=["GET", "POST"])
@exigir_perfis("admin", "almoxarifado")
def fechamento_semanal():
    inicio, fim = periodo_semana(request.args.get("inicio") or request.form.get("inicio"))
    conn = conectar()
    tecnicos_lista = conn.execute(
        "SELECT id, nome FROM tecnicos WHERE ativo = 1 ORDER BY nome"
    ).fetchall()
    selecionado = request.args.get("tecnico_id") or request.form.get("tecnico_id")

    if request.method == "POST":
        if not selecionado:
            conn.close()
            flash("Selecione um técnico.", "danger")
            return redirect(url_for("fechamento_semanal", inicio=inicio))

        try:
            tecnico_id_int = int(selecionado)
        except ValueError:
            conn.close()
            flash("Técnico inválido.", "danger")
            return redirect(url_for("fechamento_semanal", inicio=inicio))

        acao = request.form.get("acao", "fechar")
        existente = conn.execute(
            "SELECT * FROM fechamentos_semanais WHERE tecnico_id = ? AND semana_inicio = ?",
            (tecnico_id_int, inicio)
        ).fetchone()

        if acao == "reabrir":
            if not existente:
                conn.close()
                flash("Esta semana já está aberta.", "warning")
                return redirect(url_for("fechamento_semanal", inicio=inicio))
            conn.execute("DELETE FROM fechamentos_semanais WHERE id = ?", (existente["id"],))
            conn.commit()
            conn.close()
            registrar_auditoria(
                "REABRIR_SEMANA",
                f"Técnico ID {tecnico_id_int}; semana {inicio} a {fim}"
            )
            flash("Semana reaberta. Novas movimentações voltarão a entrar no relatório.", "success")
            return redirect(url_for("fechamento_semanal", inicio=inicio))

        if existente:
            conn.close()
            flash("Esta semana já foi fechada para esse técnico.", "danger")
            return redirect(url_for("fechamento_semanal", tecnico_id=tecnico_id_int, inicio=inicio))

        ultimo = conn.execute(
            "SELECT MAX(id) AS id FROM movimentacoes "
            "WHERE tecnico_id = ? AND data BETWEEN ? AND ?",
            (tecnico_id_int, inicio, fim)
        ).fetchone()["id"]

        ultimo_kit = conn.execute(
            """
            SELECT MAX(kpm.id) AS id
            FROM kit_preventivo_movimentos kpm
            JOIN kits_preventivos k ON k.id = kpm.kit_id
            WHERE k.tecnico_id = ? AND kpm.data BETWEEN ? AND ?
            """,
            (tecnico_id_int, inicio, fim)
        ).fetchone()["id"]

        fechado_em = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            """
            INSERT INTO fechamentos_semanais
            (tecnico_id, semana_inicio, semana_fim, fechado_por, fechado_em,
             ultimo_movimento_id, ultimo_kit_movimento_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tecnico_id_int, inicio, fim, int(current_user.id), fechado_em,
                ultimo, ultimo_kit
            )
        )
        conn.commit()
        conn.close()
        registrar_auditoria(
            "FECHAR_SEMANA",
            f"Técnico ID {tecnico_id_int}; semana {inicio} a {fim}; "
            f"último movimento {ultimo or '-'}; último movimento do kit {ultimo_kit or '-'}"
        )
        flash("Semana fechada com sucesso. O relatório ficou congelado.", "success")
        return redirect(url_for("fechamento_semanal", inicio=inicio))

    resumo = []
    detalhes = []

    for t in tecnicos_lista:
        fechamento = conn.execute(
            "SELECT * FROM fechamentos_semanais WHERE tecnico_id = ? AND semana_inicio = ?",
            (t["id"], inicio)
        ).fetchone()

        limite_mov = " AND COALESCE(m.data_hora, m.data || ' 00:00:00') <= ?" if fechamento else ""
        params_limite_mov = (fechamento["fechado_em"],) if fechamento else ()

        entradas = conn.execute(
            f"""
            SELECT COALESCE(SUM(m.quantidade), 0)
            FROM movimentacoes m
            WHERE m.tecnico_id = ? AND m.tipo = 'entrada'
              AND m.data BETWEEN ? AND ?{limite_mov}
            """,
            (t["id"], inicio, fim, *params_limite_mov)
        ).fetchone()[0]

        saidas = conn.execute(
            f"""
            SELECT COALESCE(SUM(m.quantidade), 0)
            FROM movimentacoes m
            WHERE m.tecnico_id = ? AND m.tipo = 'saida'
              AND m.data BETWEEN ? AND ?{limite_mov}
            """,
            (t["id"], inicio, fim, *params_limite_mov)
        ).fetchone()[0]

        movimentos = conn.execute(
            f"""
            SELECT
                m.id, m.data, strftime('%d/%m/%Y %H:%M:%S', COALESCE(m.data_hora, m.data || ' 00:00:00')) AS data_hora,
                m.tipo, m.quantidade, m.mac, m.observacao,
                e.nome AS equipamento
            FROM movimentacoes m
            JOIN equipamentos e ON e.id = m.equipamento_id
            WHERE m.tecnico_id = ? AND m.data BETWEEN ? AND ?{limite_mov}
            ORDER BY COALESCE(m.data_hora, m.data || ' 00:00:00') DESC, m.id DESC
            """,
            (t["id"], inicio, fim, *params_limite_mov)
        ).fetchall()

        por_equipamento = conn.execute(
            f"""
            SELECT
                e.nome AS equipamento,
                SUM(CASE WHEN m.tipo = 'entrada' THEN m.quantidade ELSE 0 END) AS entradas,
                SUM(CASE WHEN m.tipo = 'saida' THEN m.quantidade ELSE 0 END) AS saidas,
                SUM(m.quantidade) AS total
            FROM movimentacoes m
            JOIN equipamentos e ON e.id = m.equipamento_id
            WHERE m.tecnico_id = ? AND m.data BETWEEN ? AND ?{limite_mov}
            GROUP BY m.equipamento_id
            ORDER BY e.nome
            """,
            (t["id"], inicio, fim, *params_limite_mov)
        ).fetchall()

        kit = conn.execute(
            "SELECT * FROM kits_preventivos WHERE tecnico_id = ?",
            (t["id"],)
        ).fetchone()
        kit_itens = []
        kit_macs = {}
        kit_pendencias = 0
        kit_movimentos = []

        if kit:
            kit_itens = conn.execute(
                """
                SELECT i.id, i.equipamento_id, i.quantidade_padrao,
                       i.quantidade_atual, e.nome, e.possui_mac
                FROM kit_preventivo_itens i
                JOIN equipamentos e ON e.id = i.equipamento_id
                WHERE i.kit_id = ?
                ORDER BY e.nome
                """,
                (kit["id"],)
            ).fetchall()
            kit_pendencias = sum(
                max(0, i["quantidade_padrao"] - i["quantidade_atual"])
                for i in kit_itens
            )

            mac_rows = conn.execute(
                """
                SELECT
                    u.equipamento_id, u.mac,
                    (
                        SELECT COALESCE(kpm.data_hora, kpm.data || ' 00:00:00')
                        FROM kit_preventivo_movimentos kpm
                        WHERE kpm.kit_id = ?
                          AND kpm.equipamento_id = u.equipamento_id
                          AND kpm.mac = u.mac
                          AND kpm.tipo IN ('entrada_kit', 'vinculacao', 'renovacao')
                        ORDER BY kpm.id DESC
                        LIMIT 1
                    ) AS colocado_em
                FROM unidades u
                WHERE u.tecnico_id = ? AND u.status = 'kit'
                ORDER BY u.equipamento_id, u.mac
                """,
                (kit["id"], t["id"])
            ).fetchall()
            for row in mac_rows:
                kit_macs.setdefault(row["equipamento_id"], []).append(row)

            limite_kit = " AND COALESCE(kpm.data_hora, kpm.data || ' 00:00:00') <= ?" if fechamento else ""
            params_limite_kit = (fechamento["fechado_em"],) if fechamento else ()
            kit_movimentos = conn.execute(
                f"""
                SELECT
                    kpm.id, kpm.data, strftime('%d/%m/%Y %H:%M:%S', COALESCE(kpm.data_hora, kpm.data || ' 00:00:00')) AS data_hora,
                    kpm.tipo, kpm.quantidade, kpm.mac, kpm.observacao,
                    e.nome AS equipamento, u.nome AS usuario
                FROM kit_preventivo_movimentos kpm
                JOIN equipamentos e ON e.id = kpm.equipamento_id
                LEFT JOIN usuarios u ON u.id = kpm.usuario_id
                WHERE kpm.kit_id = ? AND kpm.data BETWEEN ? AND ?{limite_kit}
                ORDER BY COALESCE(kpm.data_hora, kpm.data || ' 00:00:00') DESC, kpm.id DESC
                """,
                (kit["id"], inicio, fim, *params_limite_kit)
            ).fetchall()

        resumo.append({
            "id": t["id"],
            "nome": t["nome"],
            "entradas": entradas,
            "saidas": saidas,
            "total_movimentos": len(movimentos),
            "fechado": bool(fechamento),
            "kit_pendencias": kit_pendencias,
            "kit_movimentos": len(kit_movimentos),
            "fechado_em": fechamento["fechado_em"] if fechamento else None,
        })
        detalhes.append({
            "id": t["id"],
            "nome": t["nome"],
            "movimentos": movimentos,
            "por_equipamento": por_equipamento,
            "kit": kit,
            "kit_itens": kit_itens,
            "kit_macs": kit_macs,
            "kit_movimentos": kit_movimentos,
        })

    conn.close()
    inicio_date = date.fromisoformat(inicio)
    prev_inicio = inicio_date.fromordinal(inicio_date.toordinal() - 7).isoformat()
    next_inicio = inicio_date.fromordinal(inicio_date.toordinal() + 7).isoformat()

    html = """
    <div class="stat-row">
        <h1>Fechamento semanal</h1>
        <span class="badge badge-blue">{{ inicio }} até {{ fim }}</span>
        <div class="actions" style="margin-left:auto;">
            <a class="btn btn-secondary" href="{{ url_for('fechamento_semanal', inicio=prev_inicio) }}">← Semana anterior</a>
            <a class="btn btn-blue" href="{{ url_for('fechamento_semanal') }}">Semana atual</a>
            <a class="btn btn-secondary" href="{{ url_for('fechamento_semanal', inicio=next_inicio) }}">Próxima semana →</a>
        </div>
    </div>

    <div class="card">
        <p class="muted">
            Este fechamento reúne <strong>todas as entradas e saídas do almoxarifado</strong>
            vinculadas ao técnico, incluindo as baixas geradas pelo consumo do kit preventivo, com data, hora, equipamento, quantidade, MAC/identificador
            e observação. Ao fechar a semana, o relatório fica congelado com os registros existentes
            naquele momento. Para corrigir algo, reabra a semana, faça a correção e feche novamente.
        </p>
    </div>

    <div class="card">
        <h2>Resumo dos técnicos</h2>
        <div class="table-wrap">
            <table>
                <tr>
                    <th>Técnico</th><th>Entradas</th><th>Saídas</th>
                    <th>Movimentos</th><th>Kit</th><th>Status</th><th>Ações</th>
                </tr>
                {% for r in resumo %}
                <tr>
                    <td><strong>{{ r.nome }}</strong></td>
                    <td>{{ r.entradas }}</td>
                    <td>{{ r.saidas }}</td>
                    <td>{{ r.total_movimentos }}</td>
                    <td>
                        {% if r.kit_movimentos %}{{ r.kit_movimentos }} registro(s){% else %}-{% endif %}
                        {% if r.kit_pendencias %}<br><span class="badge badge-yellow">{{ r.kit_pendencias }} para repor</span>{% endif %}
                    </td>
                    <td>
                        {% if r.fechado %}
                            <span class="badge badge-green">FECHADO</span>
                            {% if r.fechado_em %}<div class="muted small">{{ r.fechado_em }}</div>{% endif %}
                        {% else %}
                            <span class="badge badge-yellow">ABERTO</span>
                        {% endif %}
                    </td>
                    <td>
                        <div class="actions">
                            <a class="btn btn-blue" href="{{ url_for('relatorio_semanal_tecnico', tecnico_id=r.id, inicio=inicio) }}">Ver relatório</a>
                            <a class="btn btn-green" href="{{ url_for('kit_tecnico', tecnico_id=r.id) }}">Abrir kit</a>
                            {% if r.fechado %}
                            <form method="post" style="display:inline" onsubmit="return confirm('Reabrir a semana deste técnico? O relatório voltará a aceitar novos registros.');">
                                <input type="hidden" name="tecnico_id" value="{{ r.id }}">
                                <input type="hidden" name="inicio" value="{{ inicio }}">
                                <input type="hidden" name="acao" value="reabrir">
                                <button class="btn btn-yellow" type="submit">Reabrir semana</button>
                            </form>
                            {% else %}
                            <form method="post" style="display:inline" onsubmit="return confirm('Fechar esta semana? Depois disso o relatório ficará congelado até ser reaberto.');">
                                <input type="hidden" name="tecnico_id" value="{{ r.id }}">
                                <input type="hidden" name="inicio" value="{{ inicio }}">
                                <input type="hidden" name="acao" value="fechar">
                                <button class="btn btn-green" type="submit">Fechar semana</button>
                            </form>
                            {% endif %}
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </div>

    {% for d in detalhes %}
    <div class="section card" id="tecnico-{{ d.id }}">
        <h2>{{ d.nome }}</h2>

        <h3>Resumo por equipamento</h3>
        {% if d.por_equipamento %}
        <div class="table-wrap"><table>
            <tr><th>Equipamento</th><th>Entradas</th><th>Saídas</th><th>Total</th></tr>
            {% for e in d.por_equipamento %}
            <tr><td>{{ e.equipamento }}</td><td>{{ e.entradas }}</td><td>{{ e.saidas }}</td><td>{{ e.total }}</td></tr>
            {% endfor %}
        </table></div>
        {% else %}<div class="empty">Nenhuma movimentação nesta semana.</div>{% endif %}

        <h3>Movimentações detalhadas</h3>
        {% if d.movimentos %}
        <div class="table-wrap"><table>
            <tr><th>Data e hora</th><th>Tipo</th><th>Equipamento</th><th>Qtd.</th><th>MAC/Identificador</th><th>Observação</th></tr>
            {% for m in d.movimentos %}
            <tr>
                <td>{{ m.data_hora }}</td>
                <td>{% if m.tipo == 'entrada' %}<span class="badge badge-green">ENTRADA</span>{% else %}<span class="badge badge-red">SAÍDA</span>{% endif %}</td>
                <td>{{ m.equipamento }}</td>
                <td>{{ m.quantidade }}</td>
                <td>{{ m.mac or '-' }}</td>
                <td>{{ m.observacao or '-' }}</td>
            </tr>
            {% endfor %}
        </table></div>
        {% else %}<div class="empty">Nenhuma movimentação detalhada registrada.</div>{% endif %}

        <h3>Kit preventivo — situação atual</h3>
        {% if d.kit_itens %}
        <div class="table-wrap"><table>
            <tr><th>Equipamento</th><th>Padrão</th><th>Atual</th><th>MAC/Identificador no kit</th><th>Colocado no kit</th><th>Repor</th></tr>
            {% for i in d.kit_itens %}
            <tr>
                <td>{{ i.nome }}{% if i.possui_mac %} <span class="badge badge-blue">MAC</span>{% endif %}</td>
                <td>{{ i.quantidade_padrao }}</td>
                <td>{{ i.quantidade_atual }}</td>
                <td>
                    {% if i.possui_mac and d.kit_macs.get(i.equipamento_id) %}
                        {% for m in d.kit_macs.get(i.equipamento_id) %}<div><strong>{{ m.mac }}</strong></div>{% endfor %}
                    {% elif i.possui_mac %}<span class="muted">Nenhum</span>
                    {% else %}-{% endif %}
                </td>
                <td>
                    {% if i.possui_mac and d.kit_macs.get(i.equipamento_id) %}
                        {% for m in d.kit_macs.get(i.equipamento_id) %}<div>{{ m.colocado_em }}</div>{% endfor %}
                    {% elif i.possui_mac %}-{% else %}Não se aplica{% endif %}
                </td>
                <td>{% set falta=[i.quantidade_padrao-i.quantidade_atual,0]|max %}{% if falta %}<span class="badge badge-yellow">{{ falta }}</span>{% else %}<span class="badge badge-green">OK</span>{% endif %}</td>
            </tr>
            {% endfor %}
        </table></div>
        {% else %}<div class="empty">Este técnico ainda não possui um kit preventivo configurado.</div>{% endif %}

        <h3>Histórico do kit na semana</h3>
        {% if d.kit_movimentos %}
        <div class="table-wrap"><table>
            <tr><th>Data e hora</th><th>Tipo</th><th>Equipamento</th><th>MAC/Identificador</th><th>Qtd.</th><th>Usuário</th><th>Observação</th></tr>
            {% for k in d.kit_movimentos %}
            <tr>
                <td>{{ k.data_hora }}</td>
                <td><span class="badge">{{ k.tipo|upper }}</span></td>
                <td>{{ k.equipamento }}</td>
                <td>{{ k.mac or '-' }}</td>
                <td>{{ k.quantidade }}</td>
                <td>{{ k.usuario or '-' }}</td>
                <td>{{ k.observacao or '-' }}</td>
            </tr>
            {% endfor %}
        </table></div>
        {% else %}<div class="empty">Nenhuma movimentação do kit nesta semana.</div>{% endif %}
    </div>
    {% endfor %}
    """
    return pagina("Fechamento semanal", html, inicio=inicio, fim=fim, resumo=resumo, detalhes=detalhes, prev_inicio=prev_inicio, next_inicio=next_inicio)


# =========================================================
# RELATÓRIOS
# =========================================================

@app.route("/relatorios")
@exigir_perfis("admin", "almoxarifado", "consulta")
def relatorios():
    conn = conectar()

    equipamentos_lista = conn.execute("""
        SELECT *
        FROM equipamentos
        ORDER BY nome
    """).fetchall()

    relatorio = []

    for e in equipamentos_lista:
        estoque = estoque_equipamento(conn, e["id"])
        reservado = reservado_equipamento(conn, e["id"])

        entradas = conn.execute("""
            SELECT COALESCE(SUM(quantidade), 0)
            FROM movimentacoes
            WHERE equipamento_id = ?
              AND tipo = 'entrada'
        """, (e["id"],)).fetchone()[0]

        saidas = conn.execute("""
            SELECT COALESCE(SUM(quantidade), 0)
            FROM movimentacoes
            WHERE equipamento_id = ?
              AND tipo = 'saida'
        """, (e["id"],)).fetchone()[0]

        relatorio.append({
            "nome": e["nome"],
            "categoria": e["categoria"] or "-",
            "estoque": estoque,
            "reservado": reservado,
            "disponivel": max(0, estoque - reservado),
            "entradas": entradas,
            "saidas": saidas,
            "minimo": e["estoque_minimo"]
        })

    total_movimentos = conn.execute(
        "SELECT COUNT(*) FROM movimentacoes"
    ).fetchone()[0]

    total_mac = conn.execute(
        "SELECT COUNT(*) FROM unidades"
    ).fetchone()[0]

    consumo_tecnicos = conn.execute("""
        SELECT t.nome,
               COALESCE(SUM(CASE WHEN m.tipo = 'saida' THEN m.quantidade ELSE 0 END), 0) AS saidas,
               COALESCE(SUM(CASE WHEN m.tipo = 'entrada' THEN m.quantidade ELSE 0 END), 0) AS entradas
        FROM tecnicos t
        LEFT JOIN movimentacoes m ON m.tecnico_id = t.id
        GROUP BY t.id
        ORDER BY saidas DESC, t.nome
    """).fetchall()

    conn.close()

    html = """
    <h1>Relatórios</h1>

    <div class="grid">
        <div class="card">
            <div class="muted">Movimentações</div>
            <div class="number blue">{{ total_movimentos }}</div>
        </div>

        <div class="card">
            <div class="muted">Equipamentos com MAC</div>
            <div class="number orange">{{ total_mac }}</div>
        </div>
    </div>

    {% if current_user.tem_perfil('admin', 'almoxarifado') %}
    <div class="section card"><a class="btn" href="{{ url_for('fechamento_semanal') }}">Abrir fechamento semanal</a></div>
    {% endif %}

    <div class="section card">
        <h2>Consumo por técnico</h2>
        {% if consumo_tecnicos %}<div class="table-wrap"><table><tr><th>Técnico</th><th>Saídas</th><th>Entradas</th></tr>{% for t in consumo_tecnicos %}<tr><td>{{ t.nome }}</td><td>{{ t.saidas }}</td><td>{{ t.entradas }}</td></tr>{% endfor %}</table></div>{% else %}<div class="empty">Ainda não há movimentações por técnico.</div>{% endif %}
    </div>

    <div class="section card">
        <h2>Resumo do estoque</h2>

        <div class="table-wrap">
            <table>
                <tr>
                    <th>Equipamento</th>
                    <th>Categoria</th>
                    <th>Estoque</th>
                    <th>Reservado</th>
                    <th>Disponível</th>
                    <th>Entradas</th>
                    <th>Saídas</th>
                    <th>Mínimo</th>
                </tr>

                {% for r in relatorio %}
                <tr>
                    <td>{{ r.nome }}</td>
                    <td>{{ r.categoria }}</td>

                    <td class="{% if r.estoque <= r.minimo %}red{% else %}green{% endif %}">
                        {{ r.estoque }}
                    </td>

                    <td>{{ r.reservado }}</td>

                    <td>
                        <strong>{{ r.disponivel }}</strong>
                    </td>

                    <td>{{ r.entradas }}</td>
                    <td>{{ r.saidas }}</td>
                    <td>{{ r.minimo }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </div>
    """

    return pagina(
        "Relatórios",
        html,
        relatorio=relatorio,
        total_movimentos=total_movimentos,
        total_mac=total_mac,
        consumo_tecnicos=consumo_tecnicos
    )


# =========================================================
# BACKUP
# =========================================================

@app.route("/backup")
def backup():
    if not DB_PATH.exists():
        flash("Banco de dados ainda não existe.", "danger")
        return redirect(url_for("index"))

    nome = f"almoxarifado_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    destino = BACKUP_DIR / nome

    shutil.copy2(DB_PATH, destino)

    flash(f"Backup criado: {nome}", "success")

    return send_file(
        destino,
        as_attachment=True,
        download_name=nome
    )


# =========================================================
# INICIALIZAÇÃO
# =========================================================

if __name__ == "__main__":
    print("=" * 55)
    print(" SPEEDNET - SISTEMA DE ALMOXARIFADO")
    print("=" * 55)
    print("Sistema iniciado.")
    print("Acesse no navegador:")
    print("http://127.0.0.1:5000")
    print("=" * 55)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )