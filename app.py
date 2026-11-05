import os, io, json, base64, sqlite3, secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'stegocrypt.db')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
ENCODED_DIR = os.path.join(BASE_DIR, 'encoded')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(ENCODED_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get('STEGOCRYPT_SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25 MB request limit


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            image_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode('utf-8'))


def encrypt_file(filename: str, data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    payload = json.dumps({
        'filename': filename,
        'data': base64.b64encode(data).decode('ascii')
    }).encode('utf-8')
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    # Envelope: magic(8) + salt(16) + nonce(12) + ciphertext
    return b'STEGOCR1' + salt + nonce + ciphertext


def decrypt_file(envelope: bytes, password: str):
    if len(envelope) < 8 + 16 + 12 + 16 or envelope[:8] != b'STEGOCR1':
        raise ValueError('This image does not contain a supported StegoCrypt payload.')
    salt = envelope[8:24]
    nonce = envelope[24:36]
    ciphertext = envelope[36:]
    key = derive_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    payload = json.loads(plaintext.decode('utf-8'))
    return secure_filename(payload['filename']) or 'recovered_file.bin', base64.b64decode(payload['data'])


def embed_bytes(image: Image.Image, payload: bytes) -> Image.Image:
    image = image.convert('RGB')
    pixels = list(image.getdata())
    # Prefix payload with a 4-byte big-endian length.
    raw = len(payload).to_bytes(4, 'big') + payload
    bits = [(byte >> shift) & 1 for byte in raw for shift in range(7, -1, -1)]
    if len(bits) > len(pixels) * 3:
        raise ValueError(f'Payload is too large for this image. Need at least {len(bits)} bits; image holds {len(pixels) * 3}. Try a larger PNG image.')
    out = []
    bit_index = 0
    for pixel in pixels:
        channels = list(pixel)
        for c in range(3):
            if bit_index < len(bits):
                channels[c] = (channels[c] & 0xFE) | bits[bit_index]
                bit_index += 1
        out.append(tuple(channels))
    result = Image.new('RGB', image.size)
    result.putdata(out)
    return result


def extract_bytes(image: Image.Image) -> bytes:
    pixels = list(image.convert('RGB').getdata())
    bits = [(channel & 1) for pixel in pixels for channel in pixel]
    def bytes_from_bits(bit_list):
        return bytes(sum(bit_list[i + j] << (7 - j) for j in range(8)) for i in range(0, len(bit_list), 8))
    if len(bits) < 32:
        raise ValueError('Image is too small or has no embedded data.')
    length = int.from_bytes(bytes_from_bits(bits[:32]), 'big')
    if length <= 0 or 32 + length * 8 > len(bits):
        raise ValueError('No valid StegoCrypt data was found in this image.')
    return bytes_from_bits(bits[32:32 + length * 8])


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if len(username) < 3:
            flash('Username must contain at least 3 characters.', 'danger')
        elif len(password) < 8:
            flash('Password must contain at least 8 characters.', 'danger')
        else:
            try:
                with get_db() as db:
                    db.execute('INSERT INTO users(username, password_hash) VALUES (?, ?)',
                               (username, generate_password_hash(password)))
                flash('Account created. Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('That username is already registered.', 'danger')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        flash('Incorrect username or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    with get_db() as db:
        files = db.execute('SELECT * FROM shared_files WHERE user_id = ? ORDER BY id DESC',
                           (session['user_id'],)).fetchall()
    return render_template('dashboard.html', files=files)


@app.route('/encode', methods=['GET', 'POST'])
@login_required
def encode():
    if request.method == 'POST':
        file = request.files.get('secret_file')
        carrier = request.files.get('carrier_image')
        password = request.form.get('encryption_password', '')
        if not file or not file.filename or not carrier or not carrier.filename:
            flash('Choose both a file to hide and a carrier image.', 'danger')
            return redirect(url_for('encode'))
        if len(password) < 8:
            flash('Use an encryption password with at least 8 characters.', 'danger')
            return redirect(url_for('encode'))
        try:
            original_name = secure_filename(file.filename) or 'secret_file.bin'
            carrier_img = Image.open(carrier.stream)
            if carrier_img.format not in ('PNG', 'JPEG', 'JPG', 'BMP', 'WEBP'):
                raise ValueError('Please upload a valid image file.')
            envelope = encrypt_file(original_name, file.read(), password)
            encoded_image = embed_bytes(carrier_img, envelope)
            image_name = secrets.token_hex(12) + '.png'
            image_path = os.path.join(ENCODED_DIR, image_name)
            encoded_image.save(image_path, format='PNG')
            with get_db() as db:
                db.execute('INSERT INTO shared_files(user_id, original_name, image_name) VALUES (?, ?, ?)',
                           (session['user_id'], original_name, image_name))
            return send_file(image_path, as_attachment=True, download_name='stegocrypt_' + image_name, mimetype='image/png')
        except Exception as exc:
            flash(str(exc) if isinstance(exc, ValueError) else 'Could not encode this file. Check that the image is valid and large enough.', 'danger')
            return redirect(url_for('encode'))
    return render_template('encode.html')


@app.route('/decode', methods=['GET', 'POST'])
@login_required
def decode():
    if request.method == 'POST':
        image_file = request.files.get('encoded_image')
        password = request.form.get('decryption_password', '')
        if not image_file or not image_file.filename:
            flash('Choose the StegoCrypt PNG image first.', 'danger')
            return redirect(url_for('decode'))
        try:
            image = Image.open(image_file.stream)
            envelope = extract_bytes(image)
            filename, content = decrypt_file(envelope, password)
            return send_file(io.BytesIO(content), as_attachment=True, download_name=filename, mimetype='application/octet-stream')
        except Exception:
            flash('Decoding failed. Make sure this is the original encoded PNG and the password is correct.', 'danger')
            return redirect(url_for('decode'))
    return render_template('decode.html')


@app.errorhandler(413)
def too_large(_error):
    flash('Upload is too large. Maximum request size is 25 MB.', 'danger')
    return redirect(request.referrer or url_for('dashboard'))


init_db()

if __name__ == '__main__':
    # Development server only. Use HTTPS and a production WSGI server before deployment.
    app.run(debug=True)
