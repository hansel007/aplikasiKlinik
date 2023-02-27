from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import InputRequired
from flask_bootstrap import Bootstrap
from functools import wraps
from sqlalchemy.sql import func

app = Flask(__name__)
app.app_context().push()

app.config['SECRET_KEY'] = '$FHenfge24'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/dbklinik'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
bootstrap = Bootstrap(app)

class Login(FlaskForm):
    username = StringField('', validators=[InputRequired()], render_kw={'autofocus':True, 'placeholder':'Username'})
    password = PasswordField('', validators=[InputRequired()], render_kw={'autofocus':True, 'placeholder':'Password'})
    level = SelectField('', validators=[InputRequired()], choices=[('Admin','Admin'),('Dokter','Dokter'),('Administrasi','Administrasi')])

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.Text, nullable=False)
    level = db.Column(db.String(100), nullable=False)
    usernya = db.relationship('Pasien', backref=db.backref('user', lazy=True))

    def __init__(self,username,password,level):
        self.username = username
        if password !='':
            self.password = bcrypt.generate_password_hash(password).decode('UTF-8')
        self.level = level
        super().__init__()

class Dokter(db.Model):
    __tablename__ = 'dokter'
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(150), nullable=False)
    jadwal = db.Column(db.Text, nullable=False)

    def __init__(self,nama,jadwal):
        super().__init__()
        self.nama = nama
        self.jadwal = jadwal

class Suplier(db.Model):
    __tablename__ ='suplier'
    id = db.Column(db.Integer, primary_key=True)
    perusahaan = db.Column(db.String(200), nullable=False)
    kontak = db.Column(db.String(200), nullable=False)
    alamat = db.Column(db.Text, nullable=False)
    supliernya = db.relationship('Obat', backref=db.backref('suplier', lazy=True))

    def __init__(self,perusahaan,kontak,alamat):
        super().__init__()
        self.perusahaan = perusahaan
        self.kontak = kontak
        self.alamat = alamat

class Obat(db.Model):
    __tablename__ = 'obat'
    id = db.Column(db.Integer, primary_key=True)
    namaObat = db.Column(db.String(150), nullable=False)
    jenisObat = db.Column(db.String(150), nullable=False)
    harga_beli = db.Column(db.Integer, nullable=False)
    harga_jual = db.Column(db.Integer, nullable=False)
    suplier_id = db.Column(db.Integer, db.ForeignKey('suplier.id'), nullable=False)

    def __init__(self,namaObat,jenisObat,harga_beli,harga_jual,suplier_id):
        super().__init__()
        self.namaObat = namaObat
        self.jenisObat = jenisObat
        self.harga_beli = harga_beli
        self.harga_jual = harga_jual
        self.suplier_id = suplier_id

class Pendaftaran(db.Model):
    __tablename__ = 'pendaftaran'
    id = db.Column(db.BigInteger, primary_key=True)
    nama = db.Column(db.String(150), nullable=False)
    tl = db.Column(db.String(100), nullable=False)
    tg_lahir = db.Column(db.String(100), nullable=False)
    jk = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(100), nullable=False)
    profesi = db.Column(db.String(100), nullable=False)
    alamat = db.Column(db.Text, nullable=False)
    keterangan = db.Column(db.String(100), nullable=False)
    pendaftarannya = db.relationship('Pasien', backref=db.backref('pendaftaran', lazy=True))

    def __init__(self,nama,tl,tg_lahir,jk,status,profesi,alamat,keterangan):
        super().__init__()
        self.nama = nama
        self.tl = tl
        self.tg_lahir = tg_lahir
        self.jk = jk
        self.status = status
        self.profesi = profesi
        self.alamat = alamat
        self.keterangan = keterangan

class Pasien(db.Model):
    id = db.Column(db.BigInteger, primary_key=True)
    nama = db.Column(db.String(150), nullable=False)
    keluhan = db.Column(db.Text, nullable=False)
    diagnosa = db.Column(db.String(100), nullable=False)
    resep = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pendaftaran_id = db.Column(db.BigInteger, db.ForeignKey('pendaftaran.id'), nullable=False)
    tanggal = db.Column(db.String(100), nullable=False)

    def __init__(self,nama,keluhan,diagnosa,resep,user_id,pendaftaran_id,tanggal):
        super().__init__()
        self.nama = nama
        self.keluhan = keluhan
        self.diagnosa = diagnosa
        self.resep = resep
        self.user_id = user_id
        self.pendaftaran_id = pendaftaran_id
        self.tanggal = tanggal

db.create_all()

def login_dulu(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'login' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return wrap

@app.route('/')
def index():
    if not session.get('login') == True:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('login') == True:
        return redirect(url_for('dashboard'))
    form = Login()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data) and user.level == form.level.data:
                session['login'] =True
                session['id'] = user.id
                session['level'] = user.level
                return redirect(url_for('dashboard'))
            pesan = "Username atau Password anda salah"
            return render_template("login.html", pesan=pesan, form=form)
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_dulu
def dashboard():
    return render_template('dashboard.html')

@app.route('/kelola_user')
@login_dulu
def kelola_user():
    data = User.query.all()
    return render_template('user.html', data=data)

@app.route('/tambahuser', methods=['GET','POST'])
@login_dulu
def tambahuser():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        level = request.form['level']
        db.session.add(User(username,password,level))
        db.session.commit()
        return redirect(url_for('kelola_user'))

@app.route('/edituser/<id>', methods=['GET','POST'])
@login_dulu
def edituser(id):
    data = User.query.filter_by(id=id).first()
    if request.method == "POST":
        try:
            data.username = request.form['username']
            if data.password != '':
                data.password = bcrypt.generate_password_hash(request.form['password']).decode('UTF-8')
            data.level = request.form['level']
            db.session.add(data)
            db.session.commit()
            return redirect(url_for('kelola_user'))
        except:
            flash("Ada trouble")
            return redirect(request.referrer)

@app.route('/hapususer/<id>', methods=['GET','POST'])
@login_dulu
def hapususer(id):
    data = User.query.filter_by(id=id).first()
    db.session.delete(data)
    db.session.commit()
    return redirect(url_for('kelola_user'))

@app.route('/pendaftaran')
@login_dulu
def pendaftaran():
    data = Pendaftaran.query.all()
    return render_template('pendaftaran.html', data=data)

@app.route('/apotik')
@login_dulu
def apotik():
    data = Obat.query.all()
    return render_template('apotik.html', data=data)

@app.route('/dokter')
@login_dulu
def dokter():
    data = Dokter.query.all()
    return render_template('dokter.html', data=data)

@app.route('/tambahdokter', methods=['GET','POST'])
@login_dulu
def tambahdokter():
    if request.method == 'POST':
        nama = request.form['nama']
        jadwal = request.form['jadwal']
        db.session.add(Dokter(nama,jadwal))
        db.session.commit()
        return jsonify({'success':True})
    else:
        return redirect(request.referrer)

@app.route('/editdokter/<id>', methods=['GET','POST'])
@login_dulu
def editdokter(id):
    data = Dokter.query.filter_by(id=id).first()
    if request.method == 'POST':
        data.nama = request.form['nama']
        data.jadwal = request.form['jadwal']
        db.session.add(data)
        db.session.commit()
        return redirect(request.referrer)
    #     return jsonify({'success':True})
    # else:
    #     return redirect(request.referrer)

@app.route('/hapusdokter/<id>', methods = ['GET','POST'])
@login_dulu
def hapusdokter(id):
    data = Dokter.query.filter_by(id=id).first()
    db.session.delete(data)
    db.session.commit()
    return redirect(request.referrer)

@app.route('/suplier')
@login_dulu
def suplier():
    data = Suplier.query.all()
    return render_template('suplier.html', data=data)

@app.route('/logout')
@login_dulu
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)