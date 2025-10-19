import os
import hashlib
from pathlib import Path
from functools import wraps
from sqlalchemy import func, inspect
from PIL import Image, ImageOps, UnidentifiedImageError
import io
import time
import logging

from flask import (
    Flask, request, session, flash, render_template,
    redirect, url_for, abort
)
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

# === Paths y entorno ===
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(str(BASE_DIR / ".env"))

# === Inicializar Flask ===
app = Flask(__name__, instance_relative_config=True)
os.makedirs(app.instance_path, exist_ok=True)

# === Configuración de claves ===
secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY no está definido en .env o variable de entorno.")
app.secret_key = secret_key
app.config["WTF_CSRF_SECRET_KEY"] = os.getenv("WTF_CSRF_SECRET_KEY", app.secret_key)

# === Forzar firma SHA-256 (soluciona HMAC/OpenSSL unsupported) ===
class Sha256SessionInterface(SecureCookieSessionInterface):
    def get_signing_serializer(self, app):
        if not app.secret_key:
            return None
        signer_kwargs = {
            "key_derivation": "hmac",
            "digest_method": hashlib.sha256,
        }
        return URLSafeTimedSerializer(
            secret_key=app.secret_key,
            salt="cookie-session",
            serializer=self.serializer,
            signer_kwargs=signer_kwargs,
        )

app.session_interface = Sha256SessionInterface()

# === Base de datos SQLite (ruta absoluta en instance/) ===
db_path = os.path.join(app.instance_path, "deudas.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)  # ← única instancia

# --- Crear tablas si no existen (primera vez bajo mod_wsgi) ---
with app.app_context():
    try:
        inspector = inspect(db.engine)
        if not inspector.has_table("usuario"):
            app.logger.info("Inicializando esquema de BD…")
            db.create_all()
            app.logger.info("Esquema creado.")
    except Exception as e:
        app.logger.error(f"Error inicializando la BD: {e}")

# === Configuración de subidas ===
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "static", "perfiles")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'tiff', 'heic', 'heif', 'jfif'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

Image.MAX_IMAGE_PIXELS = 30_000_000
app.logger.setLevel(logging.DEBUG)

@app.before_request
def log_request():
    ct = request.headers.get('Content-Type')
    cl = request.headers.get('Content-Length')
    try:
        files_keys = list(request.files.keys())
        form_keys = list(request.form.keys())
    except Exception:
        files_keys, form_keys = [], []
    app.logger.debug(f"[REQ] {request.method} {request.path} CT={ct} CL={cl} files={files_keys} form_keys={form_keys}")

# ---------- Utilidades ----------

def hash_es_sha1(h: str) -> bool:
    """Detecta hashes legacy tipo pbkdf2:sha1 de Werkzeug."""
    try:
        return h.split(':', 2)[1].lower() == 'sha1'
    except Exception:
        return False

# --------------  MODELOS  --------------

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nick = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    imagen = db.Column(db.String(200), default='default.jpg')
    amigos = db.relationship('Amistad', backref='usuario', lazy=True)
    role = db.Column(db.String(20), nullable=False, default='user')
    aprobado = db.Column(db.Boolean, nullable=False, default=False)
    reset_password_hash = db.Column(db.String(255), nullable=True, default=None)
    reset_requested_at = db.Column(db.DateTime, nullable=True, default=None)

class Amistad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    solicitante_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    solicitado_id = db.Column(db.Integer, nullable=False)
    estado = db.Column(db.String(20), default='pendiente')

class Gasto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    amigo_id = db.Column(db.Integer, nullable=False)
    cantidad = db.Column(db.Float, nullable=False)
    descripcion = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    eliminado = db.Column(db.Boolean, nullable=False, default=False)
    eliminado_por_id = db.Column(db.Integer, nullable=True)
    eliminado_en = db.Column(db.DateTime, nullable=True)

# --------------  HELPERS DE SESIÓN/ROL  --------------

def usuario_autenticado():
    return session.get('usuario_id') is not None

def obtener_usuario_actual():
    uid = session.get('usuario_id')
    if not uid:
        return None
    return Usuario.query.get(uid)

def redirigir_si_autenticado(destino='dashboard'):
    if usuario_autenticado():
        return redirect(url_for(destino))
    return None

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        uid = session.get('usuario_id')
        if not uid:
            flash('Debes iniciar sesión', 'error')
            return redirect(url_for('login'))
        u = Usuario.query.get(uid)
        if not u:
            session.clear()
            flash('Tu sesión no es válida. Inicia sesión de nuevo.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = obtener_usuario_actual()
        if not u or u.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# --------------  ERRORES  --------------

@app.errorhandler(403)
def forbidden_handler(e):
    flash('No tienes permisos para acceder a esta sección.', 'error')
    return render_template('error.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('not-found.html'), 404

@app.errorhandler(413)
def file_too_large(e):
    flash('La imagen supera el límite permitido (10MB). Prueba con otra foto.', 'error')
    return redirect(url_for('perfil'))

# --------------  AVATARES  --------------

def process_and_save_avatar(file_storage, user_id, bg_color=(34, 34, 46)):
    raw_bytes = file_storage.read()
    if not raw_bytes:
        raise ValueError("Archivo vacío.")

    app.logger.debug(f"[IMG] Bytes recibidos: {len(raw_bytes)}")

    try:
        _tmp = Image.open(io.BytesIO(raw_bytes))
        _tmp.verify()
    except UnidentifiedImageError:
        raise ValueError("La imagen está corrupta o es de un formato no soportado.")
    except Exception as e:
        raise ValueError(f"Archivo no válido como imagen: {e}")

    img = Image.open(io.BytesIO(raw_bytes))
    app.logger.debug(f"[IMG] Detectado: fmt={getattr(img, 'format', None)} size={img.size} mode={img.mode}")

    try:
        img = ImageOps.exif_transpose(img)
    except Exception:
        pass

    try:
        if getattr(img, "is_animated", False):
            img.seek(0)
    except Exception:
        pass

    if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
        bg = Image.new("RGB", img.size, bg_color)
        img = img.convert("RGBA")
        bg.paste(img, mask=img.split()[-1])
        img = bg
    else:
        img = img.convert("RGB")

    w, h = img.size
    side = min(w, h)
    left = (w - side) // 2
    top = (h - side) // 2
    img = img.crop((left, top, left + side, top + side))

    target = (512, 512)
    if img.size != target:
        img = img.resize(target, Image.Resampling.LANCZOS)

    ts = int(time.time())
    filename = secure_filename(f"user_{user_id}_{ts}.jpg")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        img.save(filepath, format="JPEG", quality=82, optimize=True, progressive=True, subsampling="keep")
    except TypeError:
        img.save(filepath, format="JPEG", quality=82, optimize=True, progressive=True)

    app.logger.debug(f"[IMG] Guardado en: {filepath}")

    file_storage.stream.seek(0)
    return filename

# --------------  RUTAS  --------------

@app.route('/')
def index():
    if usuario_autenticado():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    redireccion = redirigir_si_autenticado('perfil')
    if redireccion:
        return redireccion

    if request.method == 'POST':
        nick = request.form['nick'].strip()
        email = request.form['email'].strip().lower()
        password_plana = request.form['password']

        if not nick or not email or not password_plana:
            flash('Todos los campos son obligatorios', 'error')
            return redirect(url_for('registro'))

        if Usuario.query.filter_by(nick=nick).first():
            flash('El nick ya está registrado', 'error')
            return redirect(url_for('registro'))

        if Usuario.query.filter_by(email=email).first():
            flash('El email ya está registrado', 'error')
            return redirect(url_for('registro'))

        nuevo_usuario = Usuario(
            nick=nick,
            email=email,
            password_hash=generate_password_hash(password_plana),  # pbkdf2:sha256 por defecto
            role='user',
            aprobado=False
        )
        db.session.add(nuevo_usuario)
        db.session.commit()

        flash('Registro recibido. Un administrador debe aprobar tu cuenta antes de poder iniciar sesión.', 'info')
        return redirect(url_for('login'))
    
    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    redireccion = redirigir_si_autenticado('perfil')
    if redireccion:
        return redireccion

    if request.method == 'POST':
        nick = request.form['nick'].strip()
        password = request.form['password']
        usuario = Usuario.query.filter_by(nick=nick).first()

        if not usuario:
            flash('Usuario o contraseña incorrectos.', 'error')
            return render_template('login.html')

        if not usuario.aprobado:
            flash('Tu cuenta está pendiente de aprobación por un administrador.', 'warning')
            return render_template('login.html')

        try:
            valido = check_password_hash(usuario.password_hash, password)
        except ValueError as e:
            app.logger.error(f"Fallo verificando password (posible SHA-1 bloqueado): {e}")
            if hash_es_sha1(usuario.password_hash):
                flash(
                    'Tu contraseña usa un algoritmo antiguo e incompatible con la política de seguridad actual. '
                    'Por favor usa "Recuperar cuenta" para generar una nueva contraseña.',
                    'error'
                )
                return render_template('login.html')
            flash('Error verificando credenciales. Contacta con el administrador.', 'error')
            return render_template('login.html')

        if not valido:
            flash('Usuario o contraseña incorrectos.', 'error')
            return render_template('login.html')

        # Si validase en otro entorno con SHA-1, re-hasheamos (defensivo; aquí normalmente no ocurrirá)
        if hash_es_sha1(usuario.password_hash):
            try:
                usuario.password_hash = generate_password_hash(password)
                db.session.commit()
                app.logger.info(f"Migrado hash de {usuario.nick} a pbkdf2:sha256")
            except Exception as e:
                app.logger.warning(f"No se pudo migrar hash de {usuario.nick}: {e}")
                db.session.rollback()

        session['usuario_id'] = usuario.id
        session.permanent = True
        flash('Inicio de sesión exitoso', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión correctamente', 'info')
    return redirect(url_for('index'))

@app.route('/recuperar-cuenta', methods=['GET', 'POST'])
def recuperar_cuenta():
    if usuario_autenticado():
        flash('Ya estás autenticado. Cambia tu contraseña desde tu perfil.', 'info')
        return redirect(url_for('perfil'))

    if request.method == 'POST':
        nick = request.form.get('nick', '').strip()
        nueva_pass = request.form.get('password', '')
        nueva_pass2 = request.form.get('password2', '')

        if not nick or not nueva_pass or not nueva_pass2:
            flash('Completa todos los campos.', 'error')
            return redirect(url_for('recuperar_cuenta'))

        if nueva_pass != nueva_pass2:
            flash('Las contraseñas no coinciden.', 'error')
            return redirect(url_for('recuperar_cuenta'))

        usuario = Usuario.query.filter_by(nick=nick).first()
        if not usuario:
            flash('Si el usuario existe, se procesará la solicitud.', 'info')
            return redirect(url_for('login'))

        usuario.reset_password_hash = generate_password_hash(nueva_pass)  # pbkdf2:sha256
        usuario.reset_requested_at = datetime.utcnow()
        db.session.commit()

        flash('Solicitud de cambio enviada. Un administrador debe aprobarla para aplicar la nueva contraseña.', 'success')
        return redirect(url_for('login'))

    return render_template('recuperar-cuenta.html')

@app.route('/dashboard')
@login_required
def dashboard():
    usuario = obtener_usuario_actual()
    if not usuario:
        session.clear()
        flash('Tu sesión no es válida. Inicia sesión de nuevo.', 'error')
        return redirect(url_for('login'))

    amistades = Amistad.query.filter(
        ((Amistad.solicitante_id == usuario.id) | (Amistad.solicitado_id == usuario.id)) &
        (Amistad.estado == 'aceptado')
    ).all()

    peticiones = Amistad.query.filter_by(solicitado_id=usuario.id, estado='pendiente').all()

    nombres_peticiones = {p.id: Usuario.query.get(p.solicitante_id).nick for p in peticiones}
    imagenes_peticiones = {p.id: Usuario.query.get(p.solicitante_id).imagen for p in peticiones}

    nombres_amistades, imagenes_amistades = {}, {}
    for a in amistades:
        amigo_id = amigo_id = a.solicitado_id if a.solicitante_id == usuario.id else a.solicitante_id
        amigo = Usuario.query.get(amigo_id)
        if amigo:
            nombres_amistades[amigo_id] = amigo.nick
            imagenes_amistades[amigo_id] = amigo.imagen

    return render_template(
        'dashboard.html',
        usuario=usuario,
        amistades=amistades,
        peticiones=peticiones,
        nombres_peticiones=nombres_peticiones,
        nombres_amistades=nombres_amistades,
        imagenes_peticiones=imagenes_peticiones,
        imagenes_amistades=imagenes_amistades
    )

@app.route('/buscar', methods=['GET'])
@login_required
def buscar():
    q = request.args.get('q', '').strip()
    usuario_actual = obtener_usuario_actual()
    
    resultados = Usuario.query.filter(
        Usuario.nick.like(f"%{q}%"), 
        Usuario.id != usuario_actual.id
    ).all()
    
    return render_template('buscar.html', resultados=resultados)

@app.route('/enviar_peticion/<int:id>')
@login_required
def enviar_peticion(id):
    usuario_actual = obtener_usuario_actual()
    
    if id == usuario_actual.id:
        flash('No puedes enviarte una petición a ti mismo', 'error')
        return redirect(url_for('buscar'))
    
    existente = Amistad.query.filter(
        ((Amistad.solicitante_id == usuario_actual.id) & (Amistad.solicitado_id == id)) |
        ((Amistad.solicitante_id == id) & (Amistad.solicitado_id == usuario_actual.id))
    ).first()
    
    if existente:
        if existente.estado == 'pendiente':
            if existente.solicitante_id == usuario_actual.id:
                flash('Ya has enviado una petición a este usuario', 'info')
            else:
                flash('Este usuario ya te ha enviado una petición', 'info')
        else:
            flash('Ya son amigos', 'info')
    else:
        amistad = Amistad(solicitante_id=usuario_actual.id, solicitado_id=id)
        db.session.add(amistad)
        db.session.commit()
        flash('Petición de amistad enviada', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/aceptar_peticion/<int:id>')
@login_required
def aceptar_peticion(id):
    peticion = Amistad.query.get_or_404(id)
    usuario_actual = obtener_usuario_actual()
    
    if peticion.solicitado_id != usuario_actual.id:
        flash('No tienes permiso para aceptar esta petición', 'error')
        return redirect(url_for('dashboard'))
    
    peticion.estado = 'aceptado'
    db.session.commit()
    flash('Petición aceptada. ¡Ahora son amigos!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/chat/<int:amigo_id>', methods=['GET', 'POST'])
@login_required
def chat(amigo_id):
    usuario_actual = obtener_usuario_actual()
    
    amistad = Amistad.query.filter(
        ((Amistad.solicitante_id == usuario_actual.id) & (Amistad.solicitado_id == amigo_id)) |
        ((Amistad.solicitante_id == amigo_id) & (Amistad.solicitado_id == usuario_actual.id)),
        Amistad.estado == 'aceptado'
    ).first()
    
    if not amistad:
        flash('Deben ser amigos para compartir gastos', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            cantidad = float(request.form['cantidad'])
            descripcion = request.form['descripcion'].strip()
            if cantidad <= 0:
                flash('La cantidad debe ser mayor a cero', 'error')
            elif not descripcion:
                flash('La descripción no puede estar vacía', 'error')
            else:
                nuevo_gasto = Gasto(
                    usuario_id=usuario_actual.id, 
                    amigo_id=amigo_id, 
                    cantidad=cantidad, 
                    descripcion=descripcion
                )
                db.session.add(nuevo_gasto)
                db.session.commit()
                flash('Gasto registrado correctamente', 'success')
        except ValueError:
            flash('Cantidad no válida', 'error')
        
        return redirect(url_for('chat', amigo_id=amigo_id))
    
    gastos = Gasto.query.filter(
        ((Gasto.usuario_id == usuario_actual.id) & (Gasto.amigo_id == amigo_id)) |
        ((Gasto.usuario_id == amigo_id) & (Gasto.amigo_id == usuario_actual.id))
    ).order_by(Gasto.timestamp.desc()).limit(10).all()
    
    total_usuario = db.session.query(func.coalesce(func.sum(Gasto.cantidad), 0.0)).filter(
        (Gasto.usuario_id == usuario_actual.id) &
        (Gasto.amigo_id == amigo_id) &
        (Gasto.eliminado == False)
    ).scalar() or 0.0

    total_amigo = db.session.query(func.coalesce(func.sum(Gasto.cantidad), 0.0)).filter(
        (Gasto.usuario_id == amigo_id) &
        (Gasto.amigo_id == usuario_actual.id) &
        (Gasto.eliminado == False)
    ).scalar() or 0.0

    balance = total_usuario - total_amigo
    
    amigo = Usuario.query.get_or_404(amigo_id)
    nombres = {g.usuario_id: Usuario.query.get(g.usuario_id).nick for g in gastos}
    
    if balance < 0:
        balance_msg = f"Le debes a {amigo.nick} {abs(balance):.2f}€"
    elif balance > 0:
        balance_msg = f"{amigo.nick} te debe {abs(balance):.2f}€"
    else:
        balance_msg = "Están en paz (balance cero)"
    
    return render_template('chat.html', 
                         gastos=gastos, 
                         amigo=amigo,
                         balance_msg=balance_msg,
                         nombres=nombres, 
                         balance=balance)

@app.post('/gasto/<int:gasto_id>/eliminar')
@login_required
def eliminar_gasto(gasto_id):
    usuario_actual = obtener_usuario_actual()
    gasto = Gasto.query.get_or_404(gasto_id)

    if gasto.usuario_id != usuario_actual.id:
        abort(403)

    if not gasto.eliminado:
        gasto.eliminado = True
        gasto.eliminado_por_id = usuario_actual.id
        gasto.eliminado_en = datetime.utcnow()
        db.session.commit()
        flash('Gasto eliminado.', 'success')

    volver_amigo_id = gasto.amigo_id if gasto.usuario_id == usuario_actual.id else gasto.usuario_id
    return redirect(url_for('chat', amigo_id=volver_amigo_id))

@app.post('/gasto/<int:gasto_id>/restaurar')
@login_required
def restaurar_gasto(gasto_id):
    usuario_actual = obtener_usuario_actual()
    gasto = Gasto.query.get_or_404(gasto_id)

    if gasto.usuario_id != usuario_actual.id:
        abort(403)

    if gasto.eliminado:
        gasto.eliminado = False
        gasto.eliminado_por_id = None
        gasto.eliminado_en = None
        db.session.commit()
        flash('Gasto restaurado.', 'success')

    volver_amigo_id = gasto.amigo_id if gasto.usuario_id == usuario_actual.id else gasto.usuario_id
    return redirect(url_for('chat', amigo_id=volver_amigo_id))

@app.template_filter('formato_fecha')
def formato_fecha(value):
    return value.strftime("%d/%m/%Y %H:%M")

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    usuario = obtener_usuario_actual()
    
    if request.method == 'POST':
        try:
            nuevo_nick = request.form.get('nick', '').strip()
            nuevo_email = request.form.get('email', '').strip()

            if not nuevo_nick or not nuevo_email:
                flash('Nick y email son campos obligatorios', 'error')
                return redirect(url_for('perfil'))

            if nuevo_nick != usuario.nick and Usuario.query.filter_by(nick=nuevo_nick).first():
                flash('El nick ya está en uso', 'error')
                return redirect(url_for('perfil'))

            if nuevo_email != usuario.email and Usuario.query.filter_by(email=nuevo_email).first():
                flash('El email ya está registrado', 'error')
                return redirect(url_for('perfil'))

            usuario.nick = nuevo_nick
            usuario.email = nuevo_email

            if 'imagen' in request.files:
                imagen = request.files['imagen']
                if imagen and imagen.filename:
                    try:
                        nuevo_filename = process_and_save_avatar(imagen, usuario.id)

                        if usuario.imagen and usuario.imagen != 'default.jpg':
                            old_path = os.path.join(app.config['UPLOAD_FOLDER'], usuario.imagen)
                            if os.path.exists(old_path):
                                try:
                                    os.remove(old_path)
                                except OSError as e:
                                    app.logger.warning(f"No se pudo borrar imagen anterior: {e}")

                        usuario.imagen = nuevo_filename

                    except ValueError as ve:
                        flash(str(ve), 'error')
                        db.session.rollback()
                        return redirect(url_for('perfil'))
                    except Exception as e:
                        app.logger.error(f"Error procesando imagen: {e}")
                        flash('Error al procesar la imagen. Inténtalo con otro archivo.', 'error')
                        db.session.rollback()
                        return redirect(url_for('perfil'))

            db.session.commit()
            flash('Perfil actualizado correctamente', 'success')
            return redirect(url_for('perfil'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error en perfil: {str(e)}")
            flash('Ocurrió un error al actualizar el perfil', 'error')
            return redirect(url_for('perfil'))
    
    return render_template('perfil.html', usuario=usuario)

@app.route('/admin/usuarios')
@admin_required
def admin_listado_usuarios():
    usuarios = Usuario.query.order_by(Usuario.id.asc()).all()
    return render_template('admin_usuarios.html', usuarios=usuarios)

@app.post('/admin/usuarios/<int:user_id>/aprobar')
@admin_required
def admin_aprobar_usuario(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    usuario.aprobado = True
    db.session.commit()
    flash(f'Usuario {usuario.nick} aprobado.', 'success')
    return redirect(url_for('admin_listado_usuarios'))

@app.post('/admin/usuarios/<int:user_id>/aprobar_reset')
@admin_required
def admin_aprobar_reset(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    if not usuario.reset_password_hash:
        flash('No hay una solicitud de cambio de contraseña para este usuario.', 'info')
        return redirect(url_for('admin_listado_usuarios'))

    usuario.password_hash = usuario.reset_password_hash
    usuario.reset_password_hash = None
    usuario.reset_requested_at = None
    db.session.commit()
    flash(f'Cambio de contraseña aplicado para {usuario.nick}.', 'success')
    return redirect(url_for('admin_listado_usuarios'))

@app.post('/admin/usuarios/<int:user_id>/rechazar_reset')
@admin_required
def admin_rechazar_reset(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    usuario.reset_password_hash = None
    usuario.reset_requested_at = None
    db.session.commit()
    flash(f'Solicitud de cambio de contraseña rechazada para {usuario.nick}.', 'info')
    return redirect(url_for('admin_listado_usuarios'))

@app.post('/admin/usuarios/<int:user_id>/rol')
@admin_required
def admin_cambiar_rol(user_id):
    nuevo_rol = request.form.get('rol', 'user')
    if nuevo_rol not in ('user', 'admin'):
        flash('Rol inválido', 'error')
        return redirect(url_for('admin_listado_usuarios'))

    yo = obtener_usuario_actual()
    usuario = Usuario.query.get_or_404(user_id)

    if usuario.id == yo.id and nuevo_rol != 'admin':
        hay_otro_admin = Usuario.query.filter(Usuario.role == 'admin', Usuario.id != yo.id).first()
        if not hay_otro_admin:
            flash('No puedes quitarte el rol admin si eres el único admin.', 'error')
            return redirect(url_for('admin_listado_usuarios'))

    usuario.role = nuevo_rol
    db.session.commit()
    flash('Rol actualizado', 'success')
    return redirect(url_for('admin_listado_usuarios'))

@app.post('/admin/usuarios/<int:user_id>/eliminar')
@admin_required
def admin_eliminar_usuario(user_id):
    yo = obtener_usuario_actual()
    usuario = Usuario.query.get_or_404(user_id)

    if usuario.id == yo.id:
        flash('No puedes eliminar tu propio usuario admin.', 'error')
        return redirect(url_for('admin_listado_usuarios'))

    if usuario.role == 'admin':
        otros_admins = Usuario.query.filter(Usuario.role == 'admin', Usuario.id != usuario.id).count()
        if otros_admins == 0:
            flash('No puedes eliminar al único admin del sistema.', 'error')
            return redirect(url_for('admin_listado_usuarios'))

    db.session.delete(usuario)
    db.session.commit()
    flash('Usuario eliminado', 'success')
    return redirect(url_for('admin_listado_usuarios'))

@app.context_processor
def inyectar_usuario_contexto():
    u = obtener_usuario_actual()
    return {
        'usuario_actual': u,
        'es_admin': (u is not None and u.role == 'admin')
    }

# --------------  SEMILLA ADMIN (con pbkdf2:sha256)  --------------

def seed_admin():
    """
    Crea un admin con pbkdf2:sha256 SI no existe.
    Si existe y su hash es legacy (pbkdf2:sha1) y hay ADMIN_PASSWORD en entorno,
    lo migra a pbkdf2:sha256 usando esa contraseña.
    """
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
    admin_nick = os.getenv('ADMIN_NICK', 'admin')
    admin_pass = os.getenv('ADMIN_PASSWORD', 'cambia-esto-ya')

    existente = Usuario.query.filter(
        (Usuario.email == admin_email) | (Usuario.nick == admin_nick)
    ).first()

    if not existente:
        admin = Usuario(
            nick=admin_nick,
            email=admin_email,
            # Fuerzo método moderno explícitamente:
            password_hash=generate_password_hash(admin_pass, method='pbkdf2:sha256'),
            role='admin',
            aprobado=True
        )
        db.session.add(admin)
        db.session.commit()
        app.logger.info(f"[seed] Admin creado con pbkdf2:sha256 -> {admin_email} / {admin_nick}")
    else:
        # Migración opcional, solo si el hash es legacy y hay ADMIN_PASSWORD definido
        if hash_es_sha1(existente.password_hash):
            if os.getenv('ADMIN_PASSWORD'):
                try:
                    existente.password_hash = generate_password_hash(admin_pass, method='pbkdf2:sha256')
                    db.session.commit()
                    app.logger.info(f"[seed] Admin existente migrado a pbkdf2:sha256")
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"[seed] No se pudo migrar hash admin: {e}")
            else:
                app.logger.warning(
                    "[seed] Admin existente usa pbkdf2:sha1. Define ADMIN_PASSWORD para migrarlo automáticamente "
                    "o usa el flujo de Recuperar cuenta."
                )

# --------------  MAIN  --------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_admin()
    app.run(debug=True)
