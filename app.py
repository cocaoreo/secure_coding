import sqlite3
import uuid
import os
import re
import collections
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash #비밀번호 변경 시 보안을 위한
from functools import wraps # 모든 관리작 권한을 실시할 때에 관리자인지 검증하기 위해 추가
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
from markupsafe import escape

app = Flask(__name__)
csrf = CSRFProtect(app)#토큰 설정으로 CSRF 방지
app.jinja_env.autoescape = True # 자동 escape 설정
app.config.update(
    SECRET_KEY=os.urandom(24), #비밀키 랜덤
    SESSION_COOKIE_SECURE=True, # 세션 쿠키
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30) # 세션 만료 시간
)
app.config['WTF_CSRF_ENABLED'] = True
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf.init_app(app)
message_timestamps = collections.defaultdict(list)

@app.before_request
def make_session_permanent():
    session.permanent = True

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))

        db = get_db()
        cursor = db.cursor()

        try:
            # 현재 사용자 권한 확인
            cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
            
            if not user or not user['is_admin']:
                flash('관리자 권한이 필요합니다.')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        
        except Exception as e:
            flash('오류가 발생했습니다.')
            return redirect(url_for('dashboard'))
        
    return decorated_function

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_dormant INTEGER DEFAULT 0,
            login_attemp INTEGER DEFAULT 0
        )
    """)

        # 사용자 계좌 생성, FOREIGN으로 데이터 무결성 확보
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS account (
                user_id TEXT PRIMARY KEY,
                balance REAL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES user(id)
            )
        """)
        #채팅 대화내용 저장 db
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS private_chat (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                FOREIGN KEY(seller_id) REFERENCES user(id)
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        #거래 내역 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payment (
                id TEXT PRIMARY KEY,
                seller_id TEXT NOT NULL,
                buyer_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                amount REAL NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (seller_id) REFERENCES user(id),
                FOREIGN KEY (buyer_id) REFERENCES user(id),
                FOREIGN KEY (product_id) REFERENCES product(id)
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입(보안성 수정)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = escape(request.form['password'])
        
        # 아이디 유효성 검사
        if len(username) > 20:
            flash('아이디는 최대 20자까지 가능합니다.')
            return redirect(url_for('register'))
        
        # 비밀번호 유효성 검사
        if len(password) < 8 or len(password) > 20:
            flash('비밀번호는 8자에서 20자 사이여야 합니다.')
            return redirect(url_for('register'))
        
        # 비밀번호 특수문자 검사
        if not re.match(r'^[A-Za-z0-9@#$%&*!]+$', password):
            flash('비밀번호에 허용되지 않는 특수문자가 포함되어 있습니다.(@, #, $, %, &, *, ! 만 허용)')
            return redirect(url_for('register'))
        
        # XSS 방지를 위한 이스케이프 처리
        username = escape(username)
        
        password_hash = generate_password_hash(password)
        user_id = str(uuid.uuid4())

        db = get_db()
        cursor = db.cursor()

        try:
            cursor.execute(
                "INSERT INTO user (id, username, password_hash) VALUES (?, ?, ?)",
                (user_id, username, password_hash)
            )
            cursor.execute(
                "INSERT INTO account (user_id, balance) VALUES (?, 0)",
                (user_id,)
            )
            db.commit()
            flash('회원가입이 완료되었습니다!')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            db.rollback()
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        except Exception as e:
            db.rollback()
            flash('회원가입 중 오류가 발생했습니다.')
            print(f"Error: {e}")
            return redirect(url_for('register'))

    return render_template('register.html')

# 로그인(보안성 수정)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = escape(request.form['password'])

        db = get_db()
        cursor = db.cursor()

        # 사용자 정보 조회
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            # 휴면 계정 확인
            if user['is_dormant'] == 1:
                flash('휴면 계정입니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))

            # 로그인 시도 횟수 확인 및 업데이트
            login_attempts = user['login_attempts']

            if check_password_hash(user['password_hash'], password):
                # 비밀번호 일치: 로그인 성공
                session['user_id'] = user['id']
                session.permanent = True
                
                # 로그인 시도 횟수 초기화
                cursor.execute("UPDATE user SET login_attempts = 0 WHERE id = ?", (user['id'],))
                db.commit()

                if user['is_admin']:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('dashboard'))
            else:
                # 비밀번호 불일치: 로그인 시도 횟수 증가
                login_attempts += 1
                cursor.execute("UPDATE user SET login_attempts = ? WHERE id = ?", (login_attempts, user['id']))
                db.commit()

                if login_attempts >= 5:
                    # 5회 이상 실패 시 휴면 계정으로 전환
                    cursor.execute("UPDATE user SET is_dormant = 1, login_attempts = 0 WHERE id = ?", (user['id'],))
                    db.commit()
                    flash('비밀번호 5회 이상 오류로 휴면 계정으로 전환되었습니다. 관리자에게 문의하세요.')
                else:
                    flash(f'아이디 또는 비밀번호가 올바르지 않습니다. (시도 횟수: {login_attempts}/5)')
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')

        return redirect(url_for('login'))

    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 모든 상품 조회 (판매자 정보 포함)
    cursor.execute("""
        SELECT p.*, u.username AS seller_name, u.id AS seller_id
        FROM product p
        JOIN user u ON p.seller_id = u.id
    """)
    all_products = cursor.fetchall()

    return render_template('dashboard.html', products=all_products, user=current_user)

#user 프로필 보기
@app.route('/user/<user_id>', methods=['GET'])
def view_user_profile(user_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 판매자가 등록한 상품 조회
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (user_id,))
    products = cursor.fetchall()

    return render_template('user_profile.html', user=user, products=products)


@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        keyword = escape(request.form['keyword'])
        search_type = request.form.get('type', 'product')  # 기본값은 'product'
        db = get_db()
        cursor = db.cursor()

        if search_type == 'product':
            # 상품명 검색
            cursor.execute("""
            SELECT p.*, u.username AS seller_name, u.id AS seller_id
            FROM product p
            JOIN user u ON p.seller_id = u.id
            WHERE p.title LIKE ?
        """, ('%' + keyword + '%',))
            results = cursor.fetchall()
        elif search_type == 'user':
            # 사용자명 검색 -> 해당 사용자가 올린 상품 조회
            cursor.execute("SELECT id FROM user WHERE username LIKE ?", ('%' + keyword + '%',))
            user = cursor.fetchone()
            if user:
                cursor.execute("""
            SELECT p.*, u.username AS seller_name, u.id AS seller_id
            FROM product p
            JOIN user u ON p.seller_id = u.id
            WHERE p.title LIKE ?
        """, ('%' + keyword + '%',))
                results = cursor.fetchall()
            else:
                results = []  # 사용자를 찾지 못한 경우 빈 결과 반환
        return render_template('search_results.html', results=results, type=search_type)

    return render_template('search.html')

# 채팅 목록
@app.route('/chats', methods=['GET'])
def view_all_chats():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자와 관련된 모든 대화 상대 조회
    cursor.execute("""
        SELECT DISTINCT
            CASE
                WHEN sender_id = ? THEN receiver_id
                ELSE sender_id
            END AS other_user_id
        FROM private_chat
        WHERE sender_id = ? OR receiver_id = ?
    """, (session['user_id'], session['user_id'], session['user_id']))
    
    chat_partners = cursor.fetchall()

    # 각 대화 상대의 사용자 정보 가져오기
    partners_info = []
    for partner in chat_partners:
        cursor.execute("SELECT * FROM user WHERE id = ?", (partner['other_user_id'],))
        user_info = cursor.fetchone()
        if user_info:
            partners_info.append(user_info)

    return render_template('all_chats.html', partners=partners_info)

# 프로필 페이지: bio 업데이트 가능, 비밀번호 및 내가 올린 상품 확인 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    # 현재 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 사용자가 등록한 상품 목록 조회
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    products = cursor.fetchall()

    # 거래 내역 조회
    cursor.execute("""
        SELECT p.*, pr.title AS product_title
        FROM payment p
        JOIN product pr ON p.product_id = pr.id
        WHERE p.buyer_id = ? OR p.seller_id = ?
    """, (session['user_id'], session['user_id']))
    payments = cursor.fetchall()

        # 사용자 잔고 조회
    cursor.execute("SELECT balance FROM account WHERE user_id = ?", (session['user_id'],))
    account_info = cursor.fetchone()
    balance = account_info['balance'] if account_info else 0  # 잔고가 없으면 기본값 0

    return render_template('profile.html', user=current_user, products=products, payments=payments, balance=balance)

#비밀번호 변경
@app.route('/profile/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        current_password = escape(request.form['current_password'])
        new_password = escape(request.form['new_password'])
        confirm_new_password = escape(request.form['confirm_new_password'])

        # 현재 사용자 정보 가져오기
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()

        if not user:
            flash('사용자를 찾을 수 없습니다.')
            return redirect(url_for('profile'))

        # 현재 비밀번호 확인
        if not check_password_hash(user['password_hash'], current_password):
            flash('현재 비밀번호가 일치하지 않습니다.')
            return redirect(url_for('change_password'))

        # 새 비밀번호 확인
        if new_password != confirm_new_password:
            flash('새 비밀번호가 일치하지 않습니다.')
            return redirect(url_for('change_password'))

        # 새 비밀번호 업데이트
        new_password_hash = generate_password_hash(new_password)
        cursor.execute("UPDATE user SET password_hash = ? WHERE id = ?", (new_password_hash, session['user_id']))
        db.commit()

        flash('비밀번호가 성공적으로 변경되었습니다.')
        return redirect(url_for('profile'))

    return render_template('change_password.html')

@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 정보 조회 및 판매자 확인
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('profile'))

    # 현재 사용자가 해당 상품의 판매자인지 확인
    if product['seller_id'] != session['user_id']:
        flash('해당 상품을 수정할 권한이 없습니다.')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        title = escape(request.form['title'])
        price = escape(request.form['price'])

        # 상품 업데이트
        cursor.execute("UPDATE product SET title = ?, price = ? WHERE id = ?", (title, price, product_id))
        db.commit()

        flash('상품이 성공적으로 수정되었습니다.')
        return redirect(url_for('profile'))

    return render_template('edit_product.html', product=product)


@app.route('/product/delete/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 정보 조회 및 판매자 확인
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('profile'))

    # 현재 사용자가 해당 상품의 판매자인지 확인
    if product['seller_id'] != session['user_id']:
        flash('해당 상품을 삭제할 권한이 없습니다.')
        return redirect(url_for('profile'))

    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()

    flash('상품이 성공적으로 삭제되었습니다.')
    return redirect(url_for('profile'))

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = escape(request.form['title'].strip())
        description = request.form['description'].strip()
        price = request.form['price'].strip()
        
        # 입력값 검증
        if not title or len(title) > 100:
            flash('상품 제목은 1-100자 사이여야 합니다.')
            return redirect(url_for('new_product'))
        
        if not description or len(description) > 1000:
            flash('상품 설명은 1-1000자 사이여야 합니다.')
            return redirect(url_for('new_product'))
        
        try:
            price = float(price)
            if price <= 0 or price > 100000000000:  # 1000억원 상한선 설정
                raise ValueError
        except ValueError:
            flash('가격은 0보다 크고 1000억 이하의 숫자여야 합니다.')
            return redirect(url_for('new_product'))
        
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())

        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 성공적으로 등록되었습니다.')
        return redirect(url_for('dashboard'))
    
    return render_template('new_product.html')


# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 정보 조회 (판매자 정보 포함)
    cursor.execute("""
        SELECT p.*, u.username AS seller_name, u.id AS seller_id
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE p.id = ?
    """, (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    return render_template('view_product.html', product=product)


# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        target_type = escape(request.form.get('target_type', '').strip())
        target_id = escape(request.form.get('target_id', '').strip())
        reason = escape(request.form.get('reason', '').strip())

        # Server-side validation
        if target_type not in ['product', 'user']:
            flash('유효하지 않은 신고 대상입니다.')
            return redirect(url_for('report'))

        if len(reason) < 10 or len(reason) > 500:
            flash('신고 사유는 10자 이상 500자 이하여야 합니다.')
            return redirect(url_for('report'))

        # Verify target exists
        if target_type == 'product':
            cursor.execute("SELECT id FROM product WHERE title = ?", (target_id,))
        else:
            cursor.execute("SELECT id FROM user WHERE username = ?", (target_id,))
        
        if not cursor.fetchone():
            flash('존재하지 않는 대상입니다.')
            return redirect(url_for('report'))

        # 이미 신고한 적이 있는지 확인
        cursor.execute("""
            SELECT COUNT(*) FROM report 
            WHERE reporter_id = ? AND target_id = ? AND target_type = ?
        """, (session['user_id'], target_id, target_type))
        existing_report_count = cursor.fetchone()[0]

        if existing_report_count > 0:
            flash('이미 신고한 대상입니다.')
            return redirect(url_for('dashboard'))

        # 신고 등록
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, target_type, reason) VALUES (?, ?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, target_type, reason)
        )
        db.commit()

        # 신고 횟수 확인 및 처리
        cursor.execute("SELECT COUNT(*) FROM report WHERE target_id = ? AND target_type = ?", 
                      (target_id, target_type))
        report_count = cursor.fetchone()[0]

        # 처리 로직
        if report_count >= 5:
            if target_type == 'product':
                cursor.execute("DELETE FROM product WHERE title = ?", (target_id,))
                flash('해당 상품은 신고 누적으로 삭제되었습니다.')
            elif target_type == 'user':
                # 사용자를 휴면 상태로 전환
                cursor.execute("UPDATE user SET is_dormant = 1 WHERE username = ?", (target_id,))
                
                # 해당 사용자에 대한 모든 신고 기록 삭제 (신고 횟수 초기화)
                cursor.execute("DELETE FROM report WHERE target_id = ? AND target_type = 'user'", (target_id,))
                
                flash('해당 사용자는 신고 누적으로 휴면 계정 처리되었습니다.')
            
            db.commit()
            return redirect(url_for('dashboard'))

        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')


# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

#대화기록
@app.route('/chat/<user_id>', methods=['GET'])
def view_chat_history(user_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상대방 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    other_user = cursor.fetchone()

    if not other_user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 채팅 기록 조회
    cursor.execute("""
        SELECT * FROM private_chat
        WHERE (sender_id = ? AND receiver_id = ?)
        OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (session['user_id'], user_id, user_id, session['user_id']))
    
    chat_history = cursor.fetchall()

    # 채팅 기록이 없는 경우 새 채팅 방 생성
    if not chat_history:
        new_chat_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO private_chat (id, sender_id, receiver_id, message)
            VALUES (?, ?, ?, ?)
            """, (new_chat_id, session['user_id'], user_id, "채팅이 시작되었습니다."))
        db.commit()
        
        # 새로 생성된 채팅 기록 다시 조회
        cursor.execute("""
            SELECT * FROM private_chat
            WHERE (sender_id = ? AND receiver_id = ?)
            OR (sender_id = ? AND receiver_id = ?)
            ORDER BY timestamp ASC
            """, (session['user_id'], user_id, user_id, session['user_id']))
        chat_history = cursor.fetchall()

    return render_template('chat_history.html', 
                         chat_history=chat_history,
                         other_user=other_user)

# 연결 시 사용자 ID로 Room 가입
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        user_id = session['user_id']
        join_room(user_id)  # 사용자 ID를 Room 이름으로 사용
        print(f"User {user_id} connected to their personal room")

# 1대1 채팅
@socketio.on('private_message')
def handle_private_message(data):
    try:
        sender_id = session.get('user_id')
        if not sender_id:
            emit('error', {'message': '로그인이 필요합니다.'})
            return

        now = datetime.now()
        timestamps = message_timestamps[sender_id]

        # 10초보다 오래된 타임스탬프 제거
        message_timestamps[sender_id] = [ts for ts in timestamps if now - ts <= timedelta(seconds=10)]

        # 최근 10초 동안 5개 이상의 메시지를 보냈는지 확인
        if len(message_timestamps[sender_id]) >= 5:
            emit('error', {'message': '메시지 전송 속도 제한: 10초에 5개의 메시지만 보낼 수 있습니다.'})
            return

        # 현재 타임스탬프 추가
        message_timestamps[sender_id].append(now)

        receiver_id = data['receiver_id']
        message = escape(data['message'].strip())
        timestamp = now.isoformat()

        # 1. 데이터베이스 저장
        db = get_db()
        cursor = db.cursor()
        chat_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO private_chat 
            (id, sender_id, receiver_id, message, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (chat_id, sender_id, receiver_id, message, timestamp))
        db.commit()

        # 2. 메시지 데이터 구성
        message_data = {
            'message_id': chat_id,
            'sender_id': sender_id,
            'message': message,
            'timestamp': timestamp,
            'is_my_message': True  # 클라이언트 구분용
        }

        # 3. 실시간 전송 (발신자 + 수신자에게 동시 전송)
        emit('new_message', 
             {**message_data, 'is_my_message': True},  # 발신자용
             room=sender_id)  
        
        emit('new_message', 
             {**message_data, 'is_my_message': False},  # 수신자용
             room=receiver_id)

    except Exception as e:
        db.rollback()
        emit('error', {'message': str(e)})


#관리자 페이지
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()

    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    cursor.execute("SELECT * FROM report")
    reports = cursor.fetchall()

    return render_template(
        'admin_dashboard.html',
        users=users,
        products=products,
        reports=reports
    )

#유저 삭제
@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
    db.commit()
    flash(f'유저 {user_id}가 삭제되었습니다.')
    return redirect(url_for('admin_dashboard'))

#상품 삭제
@app.route('/admin/delete_product/<product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash(f'상품 {product_id}가 삭제되었습니다.')
    return redirect(url_for('admin_dashboard'))

#휴면유저 전환
@app.route('/admin/toggle_dormant/<user_id>', methods=['POST'])
@admin_required
def admin_toggle_dormant(user_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("UPDATE user SET is_dormant = NOT is_dormant WHERE id = ?", (user_id,))
    db.commit()
    flash(f'유저 {user_id}의 휴면 상태가 변경되었습니다.')
    return redirect(url_for('admin_dashboard'))

#거래 처리
@app.route('/payment/<product_id>', methods=['POST'])
def process_payment(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    try:
        # 상품 정보 조회
        cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
        product = cursor.fetchone()

        if not product:
            flash('상품을 찾을 수 없습니다.')
            return redirect(url_for('dashboard'))

        buyer_id = session['user_id']
        seller_id = product['seller_id']
        price = float(product['price'])

        # 구매자 잔액 확인
        cursor.execute("SELECT balance FROM account WHERE user_id = ?", (buyer_id,))
        buyer_balance = cursor.fetchone()

        if not buyer_balance or buyer_balance[0] < price:
            flash('잔액이 부족합니다.')
            return redirect(url_for('view_product', product_id=product_id))

        # 거래 처리
        cursor.execute("UPDATE account SET balance = balance - ? WHERE user_id = ?", (price, buyer_id))
        cursor.execute("UPDATE account SET balance = balance + ? WHERE user_id = ?", (price, seller_id))

        # 거래 내역 기록
        payment_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO payment (id, seller_id, buyer_id, product_id, amount)
            VALUES (?, ?, ?, ?, ?)
        """, (payment_id, seller_id, buyer_id, product_id, price))

        # 상품 삭제
        cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))

        db.commit()
        flash('거래가 성공적으로 완료되었으며, 상품이 삭제되었습니다.')
    except Exception as e:
        db.rollback()
        flash('거래 처리 중 오류가 발생했습니다.')
        print(f"Error: {e}")

    return redirect(url_for('dashboard'))



#계좌 충전
@app.route('/add_balance', methods=['GET', 'POST'])
def add_balance():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        amount = float(request.form['amount'])
        db = get_db()
        cursor = db.cursor()
        if(amount<0):
            flash('잘못된 금액 입력.')
            return redirect(url_for('dashboard'))
        cursor.execute("UPDATE account SET balance = balance + ? WHERE user_id = ?", (amount, session['user_id']))
        db.commit()

        flash(f'{amount}원이 성공적으로 충전되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('add_balance.html')

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app,debug=True)
