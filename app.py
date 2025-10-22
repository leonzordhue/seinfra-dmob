"""
SEINFRA/AM - DMOB - SISTEMA DE CONSULTA COMPLETO
COM MEDIDAS DE SEGURANÇA ADICIONAIS
"""

from flask import Flask, render_template, jsonify, request
import psycopg2
from datetime import datetime
import socket
import os
from functools import wraps
import re

app = Flask(__name__)

# =============================================================================
# CONFIGURAÇÕES DE SEGURANÇA
# =============================================================================

# Chave secreta para sessões (altere em produção)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'sua_chave_secreta_muito_forte_aqui_altere_em_producao_123!')

# Desativar debug em produção
app.config['DEBUG'] = os.environ.get('DEBUG', 'False').lower() == 'true'

# Headers de segurança
@app.after_request
def set_security_headers(response):
    """Adiciona headers de segurança HTTP"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdnjs.cloudflare.com"
    return response

# Rate limiting simples
from collections import defaultdict
import time

request_log = defaultdict(list)
MAX_REQUESTS_PER_MINUTE = 60

def rate_limit(f):
    """Decorator para limitar requisições por IP"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        
        # Limpa requisições antigas
        request_log[ip] = [req_time for req_time in request_log[ip] if now - req_time < 60]
        
        # Verifica se excedeu o limite
        if len(request_log[ip]) >= MAX_REQUESTS_PER_MINUTE:
            return jsonify({'error': 'Limite de requisições excedido. Tente novamente em 1 minuto.'}), 429
        
        request_log[ip].append(now)
        return f(*args, **kwargs)
    return decorated_function

# Validação de entrada
def sanitize_input(input_string, max_length=100):
    """Sanitiza entrada do usuário"""
    if not input_string:
        return ""
    
    # Remove caracteres potencialmente perigosos
    sanitized = re.sub(r'[<>"\']', '', str(input_string))
    
    # Limita o tamanho
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()

# =============================================================================
# CONEXÃO COM BANCO (COM SEGURANÇA)
# =============================================================================

def get_db_connection():
    """Estabelece conexão com o banco PostgreSQL com tratamento de erro"""
    try:
        conn = psycopg2.connect(
            host=os.environ.get('DB_HOST', 'localhost'),
            database=os.environ.get('DB_NAME', 'seinfra_amazonas'),
            user=os.environ.get('DB_USER', 'postgres'),
            password=os.environ.get('DB_PASSWORD', '123456'),
            port=os.environ.get('DB_PORT', '5432')
        )
        return conn
    except Exception as e:
        print(f"❌ ERRO DE CONEXÃO: {e}")
        return None

# =============================================================================
# MIDDLEWARES DE SEGURANÇA
# =============================================================================

@app.before_request
def security_checks():
    """Verificações de segurança antes de cada requisição"""
    
    # Bloqueia user-agents suspeitos
    user_agent = request.headers.get('User-Agent', '')
    suspicious_agents = ['sqlmap', 'nikto', 'metasploit', 'nmap']
    
    if any(agent in user_agent.lower() for agent in suspicious_agents):
        return jsonify({'error': 'Acesso não autorizado'}), 403
    
    # Valida content-type para POST
    if request.method == 'POST':
        if request.content_type != 'application/json':
            return jsonify({'error': 'Content-Type deve ser application/json'}), 400

# =============================================================================
# FUNÇÕES EXISTENTES (MANTIDAS)
# =============================================================================

def detectar_tem_obra_e_contrato(numero_ct_cv, situacao):
    """Lógica para determinar se tem obra (mantida intacta)"""
    if situacao is None:
        situacao = ""
    
    situacao_limpa = str(situacao).lower().strip()
    numero_ct_cv = str(numero_ct_cv).strip() if numero_ct_cv else ""
    
    # Situações com obra
    situacoes_com_obra = [
        'concluído', 'concluido', 'concluída', 'concluida', 
        'em obra', 'execução', 'implantado', 'construído', 'construido',
        'paralisado', 'andamento', 'licitado'
    ]
    
    # Situações sem obra  
    situacoes_sem_obra = [
        'a visitar', 'visitado', 'não informada', 'não informado',
        'obra extinta', 'extinto', 'cancelado'
    ]
    
    # 1. Verifica situações com obra
    for situacao_obra in situacoes_com_obra:
        if situacao_obra in situacao_limpa:
            contrato = numero_ct_cv if numero_ct_cv else None
            return True, contrato
    
    # 2. Verifica situações sem obra
    for situacao_sem in situacoes_sem_obra:
        if situacao_sem in situacao_limpa:
            return False, None
    
    # 3. CT/CV sozinho indica obra
    if numero_ct_cv and numero_ct_cv != "":
        return True, numero_ct_cv
    
    # 4. Padrão: não tem obra
    return False, None

# =============================================================================
# ROTAS PRINCIPAIS (COM PROTEÇÃO)
# =============================================================================

@app.route('/')
@rate_limit
def index():
    """Página inicial"""
    return render_template('index.html', data_atual=datetime.now().strftime("%d/%m/%Y"))

@app.route('/admin')
def admin():
    """Página administrativa"""
    return render_template('admin.html')

@app.route('/api/municipios')
@rate_limit
def api_municipios():
    """API: Lista de municípios"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Erro de conexão com o banco'}), 500
            
        cur = conn.cursor()
        cur.execute("SELECT id, nome FROM municipios ORDER BY nome")
        municipios = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify([{'id': m[0], 'nome': m[1]} for m in municipios])
    except Exception as e:
        print(f"❌ Erro API Municipios: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@app.route('/api/ramais/<int:municipio_id>')
@rate_limit
def api_ramais(municipio_id):
    """API: Ramais por município"""
    try:
        # Valida ID do município
        if not isinstance(municipio_id, int) or municipio_id <= 0:
            return jsonify({'error': 'ID de município inválido'}), 400
            
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Erro de conexão com o banco'}), 500
            
        cur = conn.cursor()
        cur.execute("""
            SELECT id, codigo, descricao, extensao_km, numero_ct_cv, situacao, revestimento
            FROM ramais WHERE municipio_id = %s ORDER BY descricao
        """, (municipio_id,))
        ramais = cur.fetchall()
        cur.close()
        conn.close()
        
        ramais_formatados = []
        for r in ramais:
            tem_obra, numero_contrato = detectar_tem_obra_e_contrato(r[4], r[5])
            ramais_formatados.append({
                'id': r[0], 'codigo': r[1] or "", 'descricao': r[2] or "",
                'extensao_km': r[3] or "", 'tem_obra': tem_obra,
                'numero_contrato': numero_contrato, 'revestimento': r[6] or ""
            })
        
        return jsonify(ramais_formatados)
    except Exception as e:
        print(f"❌ Erro API Ramais: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@app.route('/api/ramal/<int:ramal_id>')
@rate_limit
def api_ramal_detalhes(ramal_id):
    """API: Detalhes do ramal"""
    try:
        # Valida ID do ramal
        if not isinstance(ramal_id, int) or ramal_id <= 0:
            return jsonify({'error': 'ID de ramal inválido'}), 400
            
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Erro de conexão com o banco'}), 500
            
        cur = conn.cursor()
        cur.execute("""
            SELECT r.id, r.codigo, r.descricao, r.extensao_km, r.numero_ct_cv, 
                   r.situacao, r.revestimento, r.classificacao, r.segmentacao, 
                   r.rodovia_acesso, r.ponto_referencia, r.local_inicio, 
                   r.local_termino, r.ano_conclusao, m.nome as municipio_nome
            FROM ramais r JOIN municipios m ON r.municipio_id = m.id
            WHERE r.id = %s
        """, (ramal_id,))
        ramal = cur.fetchone()
        cur.close()
        conn.close()
        
        if not ramal:
            return jsonify({'error': 'Ramal não encontrado'}), 404
        
        tem_obra, numero_contrato = detectar_tem_obra_e_contrato(ramal[4], ramal[5])
        
        return jsonify({
            'id': ramal[0], 'codigo': ramal[1] or "", 'descricao': ramal[2] or "",
            'extensao_km': ramal[3] or "", 'tem_obra': tem_obra, 'numero_contrato': numero_contrato,
            'revestimento': ramal[6] or "", 'classificacao': ramal[7] or "", 'segmentacao': ramal[8] or "",
            'rodovia_acesso': ramal[9] or "", 'ponto_referencia': ramal[10] or "", 
            'local_inicio': ramal[11] or "", 'local_termino': ramal[12] or "", 
            'ano_conclusao': ramal[13] or "", 'municipio_nome': ramal[14] or ""
        })
    except Exception as e:
        print(f"❌ Erro API Detalhes Ramal: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@app.route('/api/rodovias')
@rate_limit
def api_rodovias():
    """API: Lista de rodovias"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Erro de conexão com o banco'}), 500
            
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT rodovia FROM rodovias 
            WHERE rodovia IS NOT NULL AND rodovia != '' ORDER BY rodovia
        """)
        rodovias = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify([{'rodovia': r[0]} for r in rodovias])
    except Exception as e:
        print(f"❌ Erro API Rodovias: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@app.route('/api/rodovia/<string:nome_rodovia>')
@rate_limit
def api_rodovia_detalhes(nome_rodovia):
    """API: Detalhes da rodovia"""
    try:
        # Sanitiza nome da rodovia
        nome_rodovia = sanitize_input(nome_rodovia, 50)
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Erro de conexão com o banco'}), 500
            
        cur = conn.cursor()
        cur.execute("""
            SELECT id, rodovia, codigo_ser_snv, extensao, regiao, sentido,
                   jurisdicao, inicio, final, descricao, tipo_revestimento, faixa_dominio
            FROM rodovias WHERE rodovia = %s ORDER BY codigo_ser_snv
        """, (nome_rodovia,))
        trechos = cur.fetchall()
        
        # Calcula extensão total
        extensao_total = 0
        for trecho in trechos:
            extensao = trecho[3]
            if extensao:
                try:
                    if isinstance(extensao, str):
                        extensao_limpa = extensao.lower().replace('km', '').replace(',', '.').strip()
                        extensao_limpa = ''.join(c for c in extensao_limpa if c.isdigit() or c == '.')
                        if extensao_limpa:
                            extensao_total += float(extensao_limpa)
                    else:
                        extensao_total += float(extensao)
                except (ValueError, TypeError):
                    continue
        
        cur.close()
        conn.close()
        
        return jsonify({
            'rodovia': nome_rodovia,
            'extensao_total': f"{extensao_total:.2f} km",
            'total_trechos': len(trechos),
            'trechos': [{
                'id': t[0], 'rodovia': t[1], 'codigo_ser_snv': t[2], 'extensao': t[3],
                'regiao': t[4], 'sentido': t[5], 'jurisdicao': t[6], 'inicio': t[7],
                'final': t[8], 'descricao': t[9], 'tipo_revestimento': t[10], 'faixa_dominio': t[11]
            } for t in trechos]
        })
    except Exception as e:
        print(f"❌ Erro API Detalhes Rodovia: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@app.route('/api/solicitacao', methods=['POST'])
@rate_limit
def api_solicitacao():
    """API: Registra solicitação com validação"""
    try:
        data = request.get_json()
        
        # Validação básica
        if not data:
            return jsonify({'success': False, 'message': 'Dados inválidos'}), 400
            
        print(f"📝 Nova solicitação: {data}")
        return jsonify({'success': True, 'message': 'Solicitação registrada com sucesso!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/cadastro-ramal', methods=['POST'])
@rate_limit
def api_cadastro_ramal():
    """API: Cadastra novo ramal com validação"""
    try:
        data = request.get_json()
        
        # Validação básica
        if not data:
            return jsonify({'success': False, 'message': 'Dados inválidos'}), 400
            
        print(f"📝 Novo cadastro de ramal: {data}")
        return jsonify({'success': True, 'message': 'Solicitação de cadastro registrada com sucesso!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# =============================================================================
# MANUTENÇÃO E HEALTH CHECK
# =============================================================================

@app.route('/health')
def health_check():
    """Endpoint para verificar saúde da aplicação"""
    try:
        conn = get_db_connection()
        if conn:
            conn.close()
            return jsonify({'status': 'healthy', 'database': 'connected'})
        else:
            return jsonify({'status': 'unhealthy', 'database': 'disconnected'}), 500
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """Tratamento para páginas não encontradas"""
    return jsonify({'error': 'Endpoint não encontrado'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Tratamento para erros internos"""
    return jsonify({'error': 'Erro interno do servidor'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Tratamento para limite de requisições excedido"""
    return jsonify({'error': 'Limite de requisições excedido. Tente novamente em 1 minuto.'}), 429

# =============================================================================
# INICIALIZAÇÃO SEGURA
# =============================================================================

def get_ip_address():
    """Obtém IP local"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

if __name__ == '__main__':
    print("🚀 SEINFRA/AM - SISTEMA DE CONSULTA COMPLETO")
    print("🛡️  Modo Seguro Ativado")
    
    # Avisos de segurança
    if app.config['DEBUG']:
        print("⚠️  AVISO: Modo DEBUG ativado - Desative em produção!")
    
    if app.config['SECRET_KEY'] == 'sua_chave_secreta_muito_forte_aqui_altere_em_producao_123!':
        print("⚠️  AVISO: Chave secreta padrão - Altere em produção!")
    
    print("\n📍 Rotas disponíveis:")
    print("   • GET  /                     - Página inicial")
    print("   • GET  /health               - Health check")
    print("   • GET  /api/municipios       - Lista municípios") 
    print("   • GET  /api/ramais/<id>      - Ramais por município")
    print("   • GET  /api/ramal/<id>       - Detalhes do ramal")
    print("   • GET  /api/rodovias         - Lista rodovias")
    print("   • GET  /api/rodovia/<nome>   - Detalhes da rodovia")
    
    ip_local = get_ip_address()
    print(f"\n🌐 ACESSO:")
    print(f"   Local: http://localhost:5011")
    print(f"   Rede:  http://{ip_local}:5011")
    print("\n⚡ Servidor rodando com proteções de segurança...")
    
    # Em produção, use: waitress ou gunicorn
    app.run(
        debug=app.config['DEBUG'], 
        host='0.0.0.0', 
        port=5011,
        threaded=True
    )