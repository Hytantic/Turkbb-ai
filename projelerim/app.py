# =============================================================================
# TurkBBIai Backend - Secure Flask Server
# =============================================================================
# Güvenli, production-ready Flask backend
# Author: TurkBBI
# Python 3.10+
# =============================================================================

import os
import sys
import time
import base64
import random
import string
import smtplib
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from email.mime.text import MIMEText

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# =============================================================================
# ENVIRONMENT VE KONFIGÜRASYON
# =============================================================================

# .env dosyasını yükle
load_dotenv()

# Flask app oluştur
app = Flask(__name__)

# CORS ayarları - sadece belirlenen origin'lere izin ver
allowed_origins = os.getenv('ALLOWED_ORIGINS', 'http://localhost:8000').split(',')
CORS(app, origins=allowed_origins, supports_credentials=True)

# Loglama yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('backend.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# =============================================================================
# ENVIRONMENT VARIABLES
# =============================================================================

# Gmail ayarları
GMAIL_SENDER = os.getenv('GMAIL_SENDER')
GMAIL_APP_PASSWORD = os.getenv('GMAIL_APP_PASSWORD')

# Creator email
CREATOR_EMAIL = os.getenv('CREATOR_EMAIL', '').lower()

# Gemini API keys
API_KEYS_STR = os.getenv('GEMINI_API_KEYS', '')
if not API_KEYS_STR:
    logger.error("KRITIK: GEMINI_API_KEYS environment variable bulunamadi!")
    sys.exit(1)

API_KEYS = [key.strip() for key in API_KEYS_STR.split(',') if key.strip()]
if not API_KEYS:
    logger.error("KRITIK: Gecerli API key bulunamadi!")
    sys.exit(1)

logger.info(f"Yuklenen API key sayisi: {len(API_KEYS)}")

# Rate limit ayarları (saniye)
RATE_LIMIT_CHAT = int(os.getenv('RATE_LIMIT_CHAT', '2'))
RATE_LIMIT_IMAGE = int(os.getenv('RATE_LIMIT_IMAGE', '5'))
RATE_LIMIT_EMAIL = int(os.getenv('RATE_LIMIT_EMAIL', '30'))

# Flask ayarları
FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
FLASK_PORT = int(os.getenv('FLASK_PORT', '5000'))

# =============================================================================
# GLOBAL DEĞİŞKENLER
# =============================================================================

# API key rotation için
current_key_index = 0

# Verification code'lar (production'da Redis kullanın)
verification_codes = {}

# Rate limiting için IP bazlı son istek zamanları
last_request_time = defaultdict(lambda: defaultdict(float))

# =============================================================================
# YARDIMCI FONKSİYONLAR
# =============================================================================

def get_client_ip():
    """İstemcinin IP adresini güvenli şekilde al"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or 'unknown'


def check_rate_limit(endpoint, limit_seconds):
    """
    IP bazlı rate limiting kontrolü
    
    Args:
        endpoint: Endpoint adı (chat, image, email)
        limit_seconds: Minimum bekleme süresi (saniye)
    
    Returns:
        (allowed: bool, remaining: float)
    """
    client_ip = get_client_ip()
    current_time = time.time()
    last_time = last_request_time[client_ip][endpoint]
    
    elapsed = current_time - last_time
    
    if elapsed < limit_seconds:
        remaining = limit_seconds - elapsed
        return False, remaining
    
    last_request_time[client_ip][endpoint] = current_time
    return True, 0


def get_next_api_key():
    """
    Round-robin mantığıyla sıradaki API key'i al
    
    Returns:
        str: API key
    """
    global current_key_index
    current_key_index = (current_key_index + 1) % len(API_KEYS)
    return API_KEYS[current_key_index]


def generate_verification_code():
    """6 haneli doğrulama kodu oluştur"""
    return ''.join(random.choices(string.digits, k=6))


def sanitize_error_message(error):
    """
    Hata mesajını kullanıcı için güvenli hale getir
    Detaylı hata logda kalır, kullanıcıya genel mesaj gider
    """
    error_str = str(error)
    
    # API key sızıntısını önle
    for key in API_KEYS:
        error_str = error_str.replace(key, '***HIDDEN***')
    
    # Gmail şifre sızıntısını önle
    if GMAIL_APP_PASSWORD:
        error_str = error_str.replace(GMAIL_APP_PASSWORD, '***HIDDEN***')
    
    return error_str


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route('/send-code', methods=['POST'])
def send_code():
    """
    Email doğrulama kodu gönder
    
    Request JSON:
        {
            "email": "user@example.com"
        }
    
    Response JSON:
        {
            "success": true/false,
            "message": "..."
        }
    """
    # Rate limit kontrolü
    allowed, remaining = check_rate_limit('email', RATE_LIMIT_EMAIL)
    if not allowed:
        logger.warning(f"[RATE_LIMIT] Email IP: {get_client_ip()}, kalan: {remaining:.1f}s")
        return jsonify({
            'success': False,
            'message': f'Çok fazla istek. {int(remaining)} saniye sonra tekrar deneyin.'
        }), 429
    
    # Request body kontrolü
    data = request.json
    if not data or 'email' not in data:
        return jsonify({'success': False, 'message': 'Email gerekli'}), 400
    
    email = data.get('email', '').strip()
    
    if not email or '@' not in email:
        return jsonify({'success': False, 'message': 'Geçersiz email adresi'}), 400
    
    # Doğrulama kodu oluştur
    code = generate_verification_code()
    verification_codes[email] = {
        'code': code,
        'expires_at': datetime.now() + timedelta(minutes=10)
    }
    
    # Email gönder
    try:
        if not GMAIL_SENDER or not GMAIL_APP_PASSWORD:
            logger.error("Gmail credentials bulunamadi!")
            return jsonify({'success': False, 'message': 'Email servisi yapılandırılmamış'}), 500
        
        message = MIMEText(f"""
TurkBBIai Pro - Email Doğrulama

Doğrulama Kodunuz: {code}

Bu kodu 10 dakika içinde kullanın.

Not: Bu kodu kimseyle paylaşmayın.
        """)
        
        message['Subject'] = 'TurkBBIai - Doğrulama Kodu'
        message['From'] = GMAIL_SENDER
        message['To'] = email
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_SENDER, GMAIL_APP_PASSWORD)
            server.send_message(message)
        
        logger.info(f"[EMAIL] Kod gonderildi: {email}")
        return jsonify({'success': True, 'message': 'Doğrulama kodu gönderildi'})
        
    except Exception as e:
        logger.error(f"[EMAIL] Hata: {sanitize_error_message(e)}")
        return jsonify({'success': False, 'message': 'Email gönderilemedi. Lütfen tekrar deneyin.'}), 500


@app.route('/verify-code', methods=['POST'])
def verify_code():
    """
    Email doğrulama kodunu kontrol et
    
    Request JSON:
        {
            "email": "user@example.com",
            "code": "123456"
        }
    
    Response JSON:
        {
            "success": true/false,
            "message": "...",
            "is_creator": true/false  # sadece başarılı durumda
        }
    """
    data = request.json
    if not data:
        return jsonify({'success': False, 'message': 'Geçersiz istek'}), 400
    
    email = data.get('email', '').strip()
    code = data.get('code', '').strip()
    
    if not email or not code:
        return jsonify({'success': False, 'message': 'Email ve kod gerekli'}), 400
    
    # Kod kontrolü
    if email not in verification_codes:
        return jsonify({'success': False, 'message': 'Geçersiz veya süresi dolmuş kod'}), 400
    
    stored = verification_codes[email]
    
    # Süre kontrolü
    if datetime.now() > stored['expires_at']:
        del verification_codes[email]
        return jsonify({'success': False, 'message': 'Kod süresi dolmuş. Yeni kod isteyin.'}), 400
    
    # Kod eşleşme kontrolü
    if stored['code'] != code:
        return jsonify({'success': False, 'message': 'Yanlış doğrulama kodu'}), 400
    
    # Başarılı - kodu sil
    del verification_codes[email]
    
    # Creator kontrolü (frontend bu bilgiyi görmez, sadece backend kullanır)
    is_creator = (email.lower() == CREATOR_EMAIL)
    
    logger.info(f"[VERIFY] Basarili: {email}, Creator: {is_creator}")
    
    return jsonify({
        'success': True,
        'message': 'Doğrulama başarılı',
        'is_creator': is_creator
    })


@app.route('/chat', methods=['POST'])
def chat():
    """
    Gemini AI ile sohbet
    
    Request JSON:
        {
            "message": "Kullanıcı mesajı"
        }
    
    Response JSON:
        {
            "success": true/false,
            "response": "AI cevabı",  # sadece başarılı durumda
            "error": "..."  # sadece hata durumunda
        }
    """
    # Rate limit kontrolü
    allowed, remaining = check_rate_limit('chat', RATE_LIMIT_CHAT)
    if not allowed:
        logger.warning(f"[RATE_LIMIT] Chat IP: {get_client_ip()}, kalan: {remaining:.1f}s")
        return jsonify({
            'success': False,
            'error': f'Çok hızlı mesaj gönderiyorsunuz. {int(remaining)} saniye bekleyin.'
        }), 429
    
    # Request body kontrolü
    data = request.json
    if not data or 'message' not in data:
        return jsonify({'success': False, 'error': 'Mesaj gerekli'}), 400
    
    message = data.get('message', '').strip()
    
    if not message:
        return jsonify({'success': False, 'error': 'Boş mesaj gönderilemez'}), 400
    
    # Gemini API endpoint
    endpoint = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent'
    
    # Tüm key'leri dene
    attempt = 0
    api_key = API_KEYS[current_key_index]
    
    while attempt < len(API_KEYS):
        try:
            # Gemini API'ye istek gönder
            response = requests.post(
                f"{endpoint}?key={api_key}",
                json={
                    'contents': [{
                        'role': 'user',
                        'parts': [{'text': message}]
                    }]
                },
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            # Quota dolmuş, sıradakine geç
            if response.status_code == 429:
                logger.warning(f"[CHAT] Key {current_key_index + 1}/{len(API_KEYS)} quota doldu")
                api_key = get_next_api_key()
                attempt += 1
                continue
            
            # Diğer hatalar
            if response.status_code != 200:
                logger.error(f"[CHAT] API hatasi: {response.status_code}")
                return jsonify({
                    'success': False,
                    'error': 'AI servisi şu anda yanıt veremiyor. Lütfen tekrar deneyin.'
                }), 500
            
            # Başarılı cevap
            result = response.json()
            ai_response = result['candidates'][0]['content']['parts'][0]['text']
            
            logger.info(f"[CHAT] Basarili - Key: {current_key_index + 1}/{len(API_KEYS)}")
            
            return jsonify({
                'success': True,
                'response': ai_response
            })
            
        except requests.exceptions.Timeout:
            logger.error(f"[CHAT] Timeout - Key {current_key_index + 1}")
            if attempt < len(API_KEYS) - 1:
                api_key = get_next_api_key()
                attempt += 1
            else:
                return jsonify({
                    'success': False,
                    'error': 'İstek zaman aşımına uğradı. Lütfen tekrar deneyin.'
                }), 500
                
        except Exception as e:
            logger.error(f"[CHAT] Beklenmeyen hata: {sanitize_error_message(e)}")
            if attempt < len(API_KEYS) - 1:
                api_key = get_next_api_key()
                attempt += 1
            else:
                return jsonify({
                    'success': False,
                    'error': 'Bir hata oluştu. Lütfen tekrar deneyin.'
                }), 500
    
    # Tüm key'ler denendi ama sonuç alınamadı
    logger.error("[CHAT] Tum API keyleri tuketildi")
    return jsonify({
        'success': False,
        'error': 'Servis şu anda yoğun. Lütfen biraz sonra tekrar deneyin.'
    }), 503


@app.route('/generate-image', methods=['POST'])
def generate_image():
    """
    AI görsel oluştur
    
    Request JSON:
        {
            "prompt": "Görsel açıklaması"
        }
    
    Response JSON:
        {
            "success": true/false,
            "image": "data:image/png;base64,...",  # sadece başarılı durumda
            "error": "..."  # sadece hata durumunda
        }
    """
    # Rate limit kontrolü
    allowed, remaining = check_rate_limit('image', RATE_LIMIT_IMAGE)
    if not allowed:
        logger.warning(f"[RATE_LIMIT] Image IP: {get_client_ip()}, kalan: {remaining:.1f}s")
        return jsonify({
            'success': False,
            'error': f'Çok sık görsel oluşturuyorsunuz. {int(remaining)} saniye bekleyin.'
        }), 429
    
    # Request body kontrolü
    data = request.json
    if not data or 'prompt' not in data:
        return jsonify({'success': False, 'error': 'Prompt gerekli'}), 400
    
    prompt = data.get('prompt', '').strip()
    
    if not prompt:
        return jsonify({'success': False, 'error': 'Boş prompt gönderilemez'}), 400
    
    try:
        # Pollinations.ai kullan
        enhanced_prompt = f"high quality, detailed, professional: {prompt}"
        encoded_prompt = requests.utils.quote(enhanced_prompt)
        random_seed = str(int(time.time() * 1000) + random.randint(0, 100000))
        
        image_url = f'https://image.pollinations.ai/prompt/{encoded_prompt}'
        image_url += f'?width=1024&height=1024&seed={random_seed}&nologo=true&enhance=true'
        
        # Görseli indir
        response = requests.get(image_url, timeout=60)
        
        if response.status_code == 503:
            return jsonify({
                'success': False,
                'error': 'Görsel servisi yükleniyor. 20 saniye sonra tekrar deneyin.'
            }), 503
        
        if not response.ok:
            logger.error(f"[IMAGE] API hatasi: {response.status_code}")
            return jsonify({
                'success': False,
                'error': 'Görsel oluşturulamadı. Lütfen tekrar deneyin.'
            }), 500
        
        # Base64'e çevir
        image_base64 = base64.b64encode(response.content).decode('utf-8')
        
        logger.info(f"[IMAGE] Basarili - Prompt: {prompt[:50]}...")
        
        return jsonify({
            'success': True,
            'image': f'data:image/png;base64,{image_base64}'
        })
        
    except requests.exceptions.Timeout:
        logger.error("[IMAGE] Timeout")
        return jsonify({
            'success': False,
            'error': 'Görsel oluşturma zaman aşımına uğradı. Tekrar deneyin.'
        }), 500
        
    except Exception as e:
        logger.error(f"[IMAGE] Hata: {sanitize_error_message(e)}")
        return jsonify({
            'success': False,
            'error': 'Bir hata oluştu. Lütfen tekrar deneyin.'
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Sağlık kontrolü endpoint'i"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'api_keys_loaded': len(API_KEYS)
    })


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(e):
    """404 hatası için özel yanıt"""
    return jsonify({'error': 'Endpoint bulunamadı'}), 404


@app.errorhandler(500)
def internal_error(e):
    """500 hatası için özel yanıt"""
    logger.error(f"[500] Internal error: {sanitize_error_message(e)}")
    return jsonify({'error': 'Sunucu hatası oluştu'}), 500


# =============================================================================
# BAŞLATMA
# =============================================================================

if __name__ == '__main__':
    logger.info("=" * 70)
    logger.info("TurkBBIai Backend Server Baslatiliyor...")
    logger.info("=" * 70)
    logger.info(f"Flask Debug Mode: {FLASK_DEBUG}")
    logger.info(f"Port: {FLASK_PORT}")
    logger.info(f"API Keys: {len(API_KEYS)} adet yuklendi")
    logger.info(f"Rate Limits - Chat: {RATE_LIMIT_CHAT}s, Image: {RATE_LIMIT_IMAGE}s, Email: {RATE_LIMIT_EMAIL}s")
    logger.info(f"Allowed Origins: {', '.join(allowed_origins)}")
    logger.info("=" * 70)
    
    # Gmail kontrolü
    if not GMAIL_SENDER or not GMAIL_APP_PASSWORD:
        logger.warning("UYARI: Gmail credentials bulunamadi! Email gonderme calismayacak.")
        logger.warning("Lutfen .env dosyasinda GMAIL_SENDER ve GMAIL_APP_PASSWORD ayarlayin.")
    
    # Server başlat
    app.run(
        host='127.0.0.1',
        port=FLASK_PORT,
        debug=FLASK_DEBUG
    )
