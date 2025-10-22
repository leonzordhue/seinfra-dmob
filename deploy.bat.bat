@echo off
chcp 65001 > nul
echo.
echo ==================================================
echo    SEINFRA/AM - INSTALAÇÃO SEGURA DO SISTEMA
echo ==================================================
echo.

:: Verificar Python
python --version > nul 2>&1
if errorlevel 1 (
    echo ❌ Python não encontrado. Instale Python 3.8+ primeiro!
    echo 📥 Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo ✅ Python encontrado
echo 📦 Instalando/atualizando pip...
python -m pip install --upgrade pip

:: Verificar se .env existe
if not exist .env (
    echo.
    echo 📋 CRIANDO ARQUIVO DE CONFIGURAÇÃO...
    copy .env.example .env > nul 2>&1
    if errorlevel 1 (
        echo ❌ Arquivo .env.example não encontrado
        echo 💡 Crie um arquivo .env com suas configurações
    ) else (
        echo ✅ Arquivo .env criado. Configure as variáveis nele.
    )
)

echo.
echo 🔄 INSTALANDO DEPENDÊNCIAS...
echo.

:: Tentar psycopg2-binary primeiro (mais fácil no Windows)
echo Tentando instalar psycopg2-binary...
pip install psycopg2-binary --no-cache-dir

if errorlevel 1 (
    echo.
    echo ❌ Falha na instalação do psycopg2-binary
    echo 🔧 Tentando método alternativo...
    
    :: Método alternativo - versão mais recente
    pip install psycopg2 --no-cache-dir
    
    if errorlevel 1 (
        echo.
        echo ❌❌ ERRO CRÍTICO: Não foi possível instalar o psycopg2
        echo.
        echo 📋 SOLUÇÕES:
        echo 1. Instale o Microsoft Visual C++ Build Tools
        echo    Download: https://visualstudio.microsoft.com/visual-cpp-build-tools/
        echo.
        echo 2. Ou use PostgreSQL em outro servidor e atualize as configurações no .env
        echo.
        echo 3. Para desenvolvimento, você pode usar SQLite temporariamente
        echo.
        pause
        exit /b 1
    )
)

echo.
echo ✅ psycopg2 instalado com sucesso!
echo 📦 Instalando outras dependências...

:: Instalar outras dependências
pip install Flask==2.3.3 python-dotenv==1.0.0 waitress==2.1.2 Werkzeug==2.3.7

echo.
echo 🔒 VERIFICANDO CONFIGURAÇÕES DE SEGURANÇA...
python -c "
import os
from dotenv import load_dotenv
load_dotenv()

print('=== CONFIGURAÇÕES DE SEGURANÇA ===')
debug_mode = os.getenv('DEBUG', 'False').lower() == 'true'
secret_key = os.getenv('SECRET_KEY', '')

if debug_mode:
    print('⚠️  AVISO: DEBUG está ativado - desative em produção!')
else:
    print('✅ DEBUG desativado')

if len(secret_key) >= 32:
    print('✅ SECRET_KEY: Tamanho adequado')
else:
    print('⚠️  AVISO: SECRET_KEY muito curta - use pelo menos 32 caracteres!')

db_host = os.getenv('DB_HOST', 'localhost')
print(f'📊 Database Host: {db_host}')
"

echo.
echo 🧪 TESTANDO APLICAÇÃO...
python -c "
try:
    from app import app
    print('✅ Aplicação carregada com sucesso!')
    print('✅ Todas as dependências estão funcionando!')
except Exception as e:
    print(f'❌ Erro ao carregar aplicação: {e}')
    print('💡 Verifique as configurações do banco de dados no arquivo .env')
"

echo.
echo ==================================================
echo                 🚀 INSTALAÇÃO CONCLUÍDA!
echo ==================================================
echo.
echo 📝 PRÓXIMOS PASSOS:
echo.
echo 1. Edite o arquivo .env com suas configurações:
echo    - DB_HOST, DB_NAME, DB_USER, DB_PASSWORD
echo    - SECRET_KEY (use uma chave forte)
echo    - DEBUG=False (em produção)
echo.
echo 2. Execute o sistema:
echo    python app.py
echo.
echo 3. Para produção:
echo    waitress-serve --host=0.0.0.0 --port=5011 app:app
echo.
echo 🌐 ACESSO: http://localhost:5011
echo.
pause