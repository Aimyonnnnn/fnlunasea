import logging
logging.basicConfig(level=logging.INFO)

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
from datetime import datetime, timedelta
import uuid
import os
import json
import base64
import bcrypt
from cryptography.fernet import Fernet
import firebase_admin
from firebase_admin import credentials, firestore, auth
from dotenv import load_dotenv

# 환경 변수 로드 (로컬 개발용)
load_dotenv()

# ✅ Firebase 초기화 - Cloudtype 환경변수 기반
cred_json = os.getenv('FIREBASE_CREDENTIALS')
if not cred_json:
    raise RuntimeError("❌ FIREBASE_CREDENTIALS 환경변수가 설정되지 않았습니다.")

# JSON 파싱 후 private_key의 \\n을 실제 개행문자로 변환
cred_dict = json.loads(cred_json)
cred_dict['private_key'] = cred_dict['private_key'].replace('\\n', '\n')

# Firebase 초기화
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)

# ✅ Fernet 키 초기화 - 환경변수 기반
fernet_key = os.getenv('FERNET_KEY')
if not fernet_key:
    # 최초 배포 시 개발자가 로그로 확인할 수 있게 출력만
    fernet_key = Fernet.generate_key().decode()
    logging.warning(f"🚨 FERNET_KEY가 설정되지 않았습니다. 자동 생성된 키 사용 중: {fernet_key}")
cipher = Fernet(fernet_key.encode())

# Flask 앱 초기화
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super_secret_key')

# Firestore 초기화
db = firestore.client()

# 관리자 계정 초기화 (Firestore)
admin_ref = db.collection('admins')
if not admin_ref.get():
    admin_data = [
        {
            'admin_id': str(uuid.uuid4()),
            'username': 'admin',
            'password': bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
        }
    ]
    encrypted_data = cipher.encrypt(json.dumps(admin_data).encode())
    admin_ref.document('init').set({'data': encrypted_data.decode()})

def delete_user_completely(user_id):
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        return False, "사용자 문서를 찾을 수 없습니다."

    user_data = user_doc.to_dict()
    user_uid = user_data.get('uid')

    try:
        db.collection('users').document(user_id).delete()
        logging.info(f"✅ Firestore 사용자 문서 삭제: {user_id}")
    except Exception as e:
        return False, f"Firestore 삭제 실패: {e}"

    try:
        if user_uid:
            auth.delete_user(user_uid)
            logging.info(f"✅ Firebase Auth 계정 삭제: {user_uid}")
    except auth.UserNotFoundError:
        logging.warning(f"⚠️ UID {user_uid} 계정 없음 (이미 삭제됐을 수 있음)")
    except Exception as e:
        return False, f"Firebase Auth 삭제 실패: {e}"

    return True, "사용자 완전 삭제 완료"

# 로그인 체크 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash("로그인이 필요합니다.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 관리자 계정 로드
def load_admins():
    doc = admin_ref.document('init').get()
    if not doc.exists:
        return []
    encrypted_data = doc.to_dict().get('data')
    decrypted_data = cipher.decrypt(encrypted_data.encode()).decode()
    return json.loads(decrypted_data)

# 관리자 계정 저장
def save_admins(admins):
    encrypted_data = cipher.encrypt(json.dumps(admins).encode())
    admin_ref.document('init').set({'data': encrypted_data.decode()})

# JSON 파싱 안전하게 처리
def safe_json_loads(data):
    if not data:
        return []
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return [data] if isinstance(data, str) else []

def get_real_ip(req):
    ip = req.headers.get('X-Forwarded-For', req.remote_addr)
    return ip.split(',')[0].strip() if ip else 'unknown'    

# 로그인 페이지
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admins = load_admins()
        for admin in admins:
            if admin['username'] == username and bcrypt.checkpw(password.encode(), admin['password'].encode()):
                session['admin_id'] = admin['admin_id']
                flash("로그인 성공!", "success")
                return redirect(url_for('home'))
        
        return render_template('login.html', error="아이디 또는 비밀번호가 잘못되었습니다.")
    
    return render_template('login.html', error=None)

# 사용자 로그인 페이지
@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_docs = db.collection('users').where('username', '==', username).limit(1).get()
        if not user_docs:
            return render_template('user_login.html', error="사용자를 찾을 수 없습니다.")

        user_doc = user_docs[0]
        user = user_doc.to_dict()

        if not user.get('is_active', True):
            return render_template('user_login.html', error="비활성화된 사용자입니다.")

        try:
            expiry_date = datetime.fromisoformat(user['expiry_date'])
            if expiry_date < datetime.now():
                return render_template('user_login.html', error="사용자 계정이 만료되었습니다.")
        except Exception:
            return render_template('user_login.html', error="만료일 형식 오류")

        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        ip_address = ip_address.split(',')[0].strip() if ip_address else 'unknown'
        logging.info(f"📡 현재 접속한 IP: {ip_address}")

        allowed_ip_list = safe_json_loads(user.get('allowed_ip'))
        logging.info(f"📄 등록된 허용 IP 목록: {allowed_ip_list}")

        if not allowed_ip_list or ip_address not in allowed_ip_list:
            logging.info(f"❌ 차단된 IP 접근 시도: {ip_address}")
            return render_template('user_login.html', error=f"허용되지 않은 IP: {ip_address}")

        try:
            stored_password = base64.b64decode(user['password'].encode())
            if bcrypt.checkpw(password.encode(), stored_password):
                logging.info("✅ 로그인 성공 (IP 허용됨)")
                db.collection('access_logs').add({
                    'user_id': user_doc.id,
                    'ip_address': ip_address,
                    'access_time': datetime.now().isoformat(),
                    'source': 'user_login'
                })
                return render_template('user_login.html', success="로그인 성공! 접속 기록이 저장되었습니다.")
            else:
                logging.info("❌ 비밀번호 불일치")
                return render_template('user_login.html', error="비밀번호가 잘못되었습니다.")
        except Exception as e:
            logging.info(f"❌ 비밀번호 처리 오류: {e}")
            return render_template('user_login.html', error="비밀번호 검증 중 오류가 발생했습니다.")

    return render_template('user_login.html', error=None, success=None)

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('admin_id', None)
    flash("로그아웃되었습니다.", "success")
    return redirect(url_for('login'))

# 관리자 설정 페이지
@app.route('/admin_settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    admins = load_admins()
    current_admin = next((admin for admin in admins if admin['admin_id'] == session['admin_id']), None)
    
    if not current_admin:
        flash("관리자 계정을 찾을 수 없습니다.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form['password']
        
        try:
            if not new_username:
                raise ValueError("아이디를 입력해야 합니다.")
            if not new_password:
                raise ValueError("비밀번호를 입력해야 합니다.")
            if len(new_password) < 8:
                raise ValueError("비밀번호는 최소 8자 이상이어야 합니다.")
            
            current_admin['username'] = new_username
            current_admin['password'] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            
            save_admins(admins)
            flash("관리자 계정 정보가 변경되었습니다. 다시 로그인해주세요.", "success")
            session.pop('admin_id', None)
            return redirect(url_for('login'))
        except ValueError as e:
            return render_template('admin_settings.html', error=str(e), username=current_admin['username'])
    
    return render_template('admin_settings.html', error=None, username=current_admin['username'])

# 그룹 관리 페이지
@app.route('/groups', methods=['GET', 'POST'])
@login_required
def manage_groups():
    if request.method == 'POST':
        if 'add' in request.form:
            group_name = request.form['group_name']
            if not group_name:
                flash("그룹 이름을 입력하세요.", "danger")
            else:
                try:
                    group_id = str(uuid.uuid4())
                    db.collection('groups').document(group_id).set({'group_name': group_name})
                    flash(f"그룹 '{group_name}' 추가 완료!", "success")
                except Exception:
                    flash("이미 존재하는 그룹 이름입니다.", "danger")
        
        elif 'delete' in request.form:
            group_id = request.form['group_id']
            group_doc = db.collection('groups').document(group_id).get()
            if not group_doc.exists:
                flash("그룹을 찾을 수 없습니다.", "danger")
            else:
                users = db.collection('users').where('group_id', '==', group_id).get()
                for user in users:
                    db.collection('users').document(user.id).update({'group_id': None})
                db.collection('groups').document(group_id).delete()
                flash(f"그룹 '{group_doc.to_dict()['group_name']}' 삭제 완료!", "success")
    
    groups = [(doc.id, doc.to_dict()['group_name']) for doc in db.collection('groups').get()]
    return render_template('groups.html', groups=groups)

# 홈 페이지
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    groups = [(doc.id, doc.to_dict()['group_name']) for doc in db.collection('groups').get()]
    selected_group_id = request.form.get('group_id', 'all') if request.method == 'POST' else 'all'
    search_term = request.form.get('search_term', '').strip()
    
    query = db.collection('users').where('is_active', '==', True)
    if search_term:
        query = query.where('username', '>=', search_term).where('username', '<=', search_term + '\uf8ff')
    if selected_group_id != 'all':
        query = query.where('group_id', '==', selected_group_id)
    
    users = []
    for doc in query.get():
        data = doc.to_dict()
        users.append((
            doc.id,
            data.get('username'),
            safe_json_loads(data.get('allowed_ip')),
            data.get('expiry_date'),
            data.get('is_active'),
            data.get('group_id'),
            data.get('name'),
            data.get('contact')
        ))
    
    return render_template('index.html', users=users, groups=groups, selected_group_id=selected_group_id, search_term=search_term)

# 사용자 추가 페이지
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_user():
    groups = [(doc.id, doc.to_dict()['group_name']) for doc in db.collection('groups').get()]
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        allowed_ip = request.form['allowed_ip'] or None
        days_valid = request.form['days_valid'] or 30
        group_id = request.form['group_id'] or None
        name = request.form['name'] or None
        contact = request.form['contact'] or None

        try:
            days_valid = int(days_valid)
            if days_valid <= 0:
                raise ValueError("유효 기간은 0보다 커야 합니다.")
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            hashed_base64 = base64.b64encode(hashed_password).decode()
            expiry_date = (datetime.now() + timedelta(days=days_valid)).isoformat()
            user_id = str(uuid.uuid4())
            
            allowed_ip_list = [ip.strip() for ip in allowed_ip.split(',')] if allowed_ip else []
            allowed_ip_json = json.dumps(allowed_ip_list)

            db.collection('users').document(user_id).set({
                'username': username,
                'password': hashed_base64,
                'allowed_ip': allowed_ip_json,
                'expiry_date': expiry_date,
                'is_active': True,
                'group_id': group_id,
                'name': name,
                'contact': contact
            })
            flash(f"사용자 '{username}' 추가 완료!", "success")
            return redirect(url_for('home'))
        except Exception as e:
            return render_template('add.html', error=str(e), groups=groups)
    
    return render_template('add.html', error=None, groups=groups)

# 사용자 삭제
@app.route('/delete/<user_id>')
@login_required
def delete_user(user_id):
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        flash("삭제 실패: 사용자를 찾을 수 없습니다.", "danger")
        return redirect(url_for('home'))

    user_data = user_doc.to_dict()
    user_uid = user_data.get('uid')

    try:
        db.collection('users').document(user_id).delete()
        logging.info(f"✅ Firestore 사용자 문서 삭제: {user_id}")

        if user_uid:
            try:
                auth.delete_user(user_uid)
                logging.info(f"✅ Firebase Auth 계정 삭제: UID={user_uid}")
            except auth.UserNotFoundError:
                logging.warning(f"⚠️ UID {user_uid} 계정 없음")
            except Exception as e:
                logging.error(f"❌ Firebase Auth 삭제 실패: {e}")
                flash(f"Firestore는 삭제했지만 Auth 삭제 실패: {e}", "warning")
        
        flash("사용자 완전 삭제 완료!", "success")
    except Exception as e:
        logging.error(f"❌ 삭제 실패: {e}")
        flash(f"삭제 중 오류 발생: {e}", "danger")

    return redirect(url_for('home'))

# 사용자 편집 페이지
@app.route('/edit/<user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        flash("사용자를 찾을 수 없습니다.", "danger")
        return redirect(url_for('home'))
    
    user = user_doc.to_dict()
    user_data = {
        'user_id': user_id,
        'username': user['username'],
        'allowed_ip': safe_json_loads(user['allowed_ip']),
        'expiry_date': user['expiry_date'],
        'is_active': user['is_active'],
        'group_id': user['group_id'],
        'name': user['name'],
        'contact': user['contact']
    }
    allowed_ip_str = ', '.join(user_data['allowed_ip'])
    groups = [(doc.id, doc.to_dict()['group_name']) for doc in db.collection('groups').get()]

    if request.method == 'POST':
        allowed_ip = request.form['allowed_ip'] or None
        expiry_date = request.form['expiry_date']
        password = request.form.get('password')
        group_id = request.form['group_id'] or None 
        name = request.form['name'] or None
        contact = request.form['contact'] or None

        try:
            expiry_dt = datetime.fromisoformat(expiry_date)
            if expiry_dt < datetime.now():
                raise ValueError("만료일은 현재 시간보다 미래여야 합니다.")
            
            allowed_ip_list = [ip.strip() for ip in allowed_ip.split(',')] if allowed_ip else []
            allowed_ip_json = json.dumps(allowed_ip_list)
            
            updates = {
                'allowed_ip': allowed_ip_json,
                'expiry_date': expiry_date,
                'group_id': group_id,
                'name': name,
                'contact': contact
            }
            if password:
                hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                updates['password'] = base64.b64encode(hashed_pw).decode()

            db.collection('users').document(user_id).update(updates)
            flash(f"사용자 '{user_data['username']}' 정보 수정 완료!", "success")
            return redirect(url_for('home'))
        except ValueError as e:
            return render_template('edit.html', user=user_data, allowed_ip=allowed_ip_str, groups=groups, error=str(e))
    
    return render_template('edit.html', user=user_data, allowed_ip=allowed_ip_str, groups=groups, error=None)

@app.route('/api/login', methods=['POST'])
def api_login():
    logging.info("🚀 [API LOGIN] JSON 요청 수신")

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    logging.info(f"입력된 ID: {username}")
    logging.info(f"입력된 PW: {password}")

    user_docs = db.collection('users').where('username', '==', username).limit(1).get()
    if not user_docs:
        logging.warning("❌ 사용자 존재하지 않음")
        return jsonify({'success': False, 'message': '사용자를 찾을 수 없습니다.'}), 401

    user_doc = user_docs[0]
    user = user_doc.to_dict()
    logging.info(f"✅ 사용자 정보 불러옴: {user}")

    if not user.get('is_active', True):
        logging.warning("❌ 계정 비활성화됨")
        return jsonify({'success': False, 'message': '비활성화된 사용자입니다.'}), 403

    try:
        expiry_date = datetime.fromisoformat(user['expiry_date'])
        logging.info(f"📅 계정 만료일: {expiry_date}")
        if expiry_date < datetime.now():
            logging.warning(f"❌ 계정 만료됨: {expiry_date}")
            return jsonify({'success': False, 'message': f'계정이 만료되었습니다. (만료일: {expiry_date.strftime("%Y-%m-%d %H:%M")})'}), 403
    except Exception as e:
        logging.error(f"❌ 날짜 파싱 오류: {e}")
        return jsonify({'success': False, 'message': '만료일 형식 오류'}), 500

    ip_address = get_real_ip(request)
    allowed_ip_list = safe_json_loads(user.get('allowed_ip'))
    logging.info(f"📡 현재 접속한 IP: {ip_address}")
    logging.info(f"📄 허용 IP 목록: {allowed_ip_list}")
    if allowed_ip_list and ip_address not in allowed_ip_list:
        logging.warning(f"❌ 차단된 IP: {ip_address}")
        return jsonify({'success': False, 'message': f'허용되지 않은 IP: {ip_address}'}), 403

    try:
        stored_password = base64.b64decode(user['password'].encode())
        if bcrypt.checkpw(password.encode(), stored_password):
            logging.info("✅ 비밀번호 일치 - 로그인 성공")
            
            # [동시 접속 체크]
            current_session = user.get('session_token')
            last_heartbeat = user.get('last_heartbeat')
            is_active = user.get('is_active_session', False)
            
            if current_session and is_active and last_heartbeat:
                try:
                    last_time = datetime.fromisoformat(last_heartbeat)
                    # 마지막 하트비트가 5분 이내면 활성 세션으로 간주
                    if datetime.now() - last_time < timedelta(minutes=5):
                        logging.warning(f"❌ 이미 활성 세션 존재: {user_doc.id}")
                        return jsonify({'success': False, 'message': '이미 다른 곳에서 로그인 중입니다.'}), 409
                except Exception:
                    pass  # 날짜 파싱 오류 시 계속 진행
            
            # [새 세션 생성]
            session_token = str(uuid.uuid4())
            db.collection('users').document(user_doc.id).update({
                'session_token': session_token,
                'last_heartbeat': datetime.now().isoformat(),
                'is_active_session': True
            })
            
            # [로그 기록 추가]
            db.collection('access_logs').add({
                'user_id': user_doc.id,
                'ip_address': ip_address,
                'access_time': datetime.now().isoformat(),
                'source': 'api_login'
            })
            
            return jsonify({
                'success': True, 
                'message': '로그인 성공',
                'session_token': session_token
            }), 200
        else:
            logging.warning("❌ 비밀번호 불일치")
            return jsonify({'success': False, 'message': '비밀번호가 틀렸습니다.'}), 401
    except Exception as e:
        logging.error(f"❌ 비밀번호 처리 오류: {e}")
        return jsonify({'success': False, 'message': '비밀번호 처리 오류'}), 500

@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    data = request.get_json()
    session_token = data.get('session_token')
    
    if not session_token:
        return jsonify({'success': False, 'message': '세션 토큰이 필요합니다.'}), 400
    
    # 세션 토큰으로 사용자 찾기
    user_docs = db.collection('users').where('session_token', '==', session_token).limit(1).get()
    if not user_docs:
        return jsonify({'success': False, 'message': '유효하지 않은 세션입니다.'}), 401
    
    user_doc = user_docs[0]
    user = user_doc.to_dict()
    
    # 계정 상태 체크
    if not user.get('is_active', True):
        return jsonify({'success': False, 'message': '비활성화된 계정입니다.'}), 403
    
    try:
        expiry_date = datetime.fromisoformat(user['expiry_date'])
        if expiry_date < datetime.now():
            return jsonify({'success': False, 'message': '계정이 만료되었습니다.'}), 403
    except Exception:
        return jsonify({'success': False, 'message': '계정 만료일 오류'}), 500
    
    # 마지막 하트비트 시간 업데이트
    try:
        db.collection('users').document(user_doc.id).update({
            'last_heartbeat': datetime.now().isoformat(),
            'is_active_session': True
        })
        return jsonify({'success': True, 'message': '하트비트 성공'}), 200
    except Exception as e:
        logging.error(f"하트비트 업데이트 실패: {e}")
        return jsonify({'success': False, 'message': '하트비트 업데이트 실패'}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    data = request.get_json()
    session_token = data.get('session_token')
    
    if not session_token:
        return jsonify({'success': False, 'message': '세션 토큰이 필요합니다.'}), 400
    
    # 세션 토큰으로 사용자 찾기
    user_docs = db.collection('users').where('session_token', '==', session_token).limit(1).get()
    if not user_docs:
        return jsonify({'success': False, 'message': '유효하지 않은 세션입니다.'}), 401
    
    user_doc = user_docs[0]
    
    # 세션 정보 삭제
    try:
        db.collection('users').document(user_doc.id).update({
            'session_token': None,
            'last_heartbeat': None,
            'is_active_session': False
        })
        logging.info(f"세션 종료: {user_doc.id}")
        return jsonify({'success': True, 'message': '로그아웃 성공'}), 200
    except Exception as e:
        logging.error(f"로그아웃 실패: {e}")
        return jsonify({'success': False, 'message': '로그아웃 실패'}), 500

@app.route('/api/expiry_by_ip', methods=['GET'])
def expiry_by_ip():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = ip.split(',')[0].strip() if ip else 'unknown'

    user_docs = db.collection('users').where('allowed_ip', '!=', None).get()

    for doc in user_docs:
        user = doc.to_dict()
        allowed_ip_list = json.loads(user.get('allowed_ip') or '[]')
        if ip in allowed_ip_list:
            expiry = user.get('expiry_date')
            return jsonify({'success': True, 'expiry_date': expiry, 'username': user.get('username')})

    return jsonify({'success': False, 'message': f'IP {ip}에 해당하는 사용자 없음'})


@app.route('/test_user_login', methods=['GET', 'POST'])
def test_user_login():
    logging.info("🚀 [test_user_login] 경로 진입")

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        logging.info(f"입력된 ID: {username}")
        logging.info(f"입력된 PW: {password}")

        user_docs = db.collection('users').where('username', '==', username).limit(1).get()
        if not user_docs:
            logging.warning("❌ 사용자 존재하지 않음")
            return render_template('test_user_login.html', error="사용자를 찾을 수 없습니다.")

        user_doc = list(user_docs)[0]
        user = user_doc.to_dict()
        logging.info(f"✅ 사용자 정보 불러옴: {user}")

        if not user.get('is_active', True):
            logging.warning("❌ 계정 비활성화됨")
            return render_template('test_user_login.html', error="비활성화된 사용자입니다.")

        try:
            expiry_date = datetime.fromisoformat(user['expiry_date'])
            logging.info(f"📅 계정 만료일: {expiry_date}")
            if expiry_date < datetime.now():
                logging.warning(f"❌ 계정 만료됨: {expiry_date}")
                return render_template('test_user_login.html', error=f"계정이 만료되었습니다. (만료일: {expiry_date.strftime('%Y-%m-%d %H:%M')})")
        except Exception as e:
            logging.error(f"❌ 날짜 파싱 오류: {e}")
            return render_template('test_user_login.html', error="만료일 형식이 잘못되었습니다.")

        ip_address = get_real_ip(request)
        allowed_ip_list = safe_json_loads(user.get('allowed_ip'))
        logging.info(f"📡 현재 접속한 IP: {ip_address}")
        logging.info(f"📄 등록된 허용 IP 목록: {allowed_ip_list}")

        if allowed_ip_list and ip_address not in allowed_ip_list:
            logging.warning(f"❌ 차단된 IP 접근 시도: {ip_address}")
            return render_template('test_user_login.html', error=f"허용되지 않은 IP: {ip_address}")

        try:
            stored_password = base64.b64decode(user['password'].encode())
            if bcrypt.checkpw(password.encode(), stored_password):
                logging.info("✅ 비밀번호 일치")
                # [로그 기록 추가]
                db.collection('access_logs').add({
                    'user_id': user_doc.id,
                    'ip_address': ip_address,
                    'access_time': datetime.now().isoformat(),
                    'source': 'test_user_login'
                })
                return render_template('test_user_login.html', success="✅ 로그인 성공!")
            else:
                logging.warning("❌ 비밀번호 불일치")
                return render_template('test_user_login.html', error="❌ 비밀번호가 잘못되었습니다.")
        except Exception as e:
            logging.error(f"❌ 비밀번호 처리 오류: {e}")
            return render_template('test_user_login.html', error="❌ 비밀번호 처리 오류")

    return render_template('test_user_login.html', error=None, success=None)

# 접속 테스트
@app.route('/test_access/<user_id>')
@login_required
def test_access(user_id):
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        flash("사용자를 찾을 수 없습니다.", "danger")
        return redirect(url_for('home'))
    
    user = user_doc.to_dict()
    ip_address = get_real_ip(request)
    allowed_ip_list = safe_json_loads(user['allowed_ip'])
    
    if not user['is_active']:
        flash("비활성화된 사용자입니다.", "danger")
        return redirect(url_for('home'))
    
    if datetime.fromisoformat(user['expiry_date']) < datetime.now():
        flash("사용자 계정이 만료되었습니다.", "danger")
        return redirect(url_for('home'))
    
    if allowed_ip_list and ip_address not in allowed_ip_list:
        flash(f"허용되지 않은 IP ({ip_address})입니다.", "danger")
        return redirect(url_for('home'))
    
    db.collection('access_logs').add({
        'user_id': user_id,
        'ip_address': ip_address,
        'access_time': datetime.now().isoformat(),
        'source': 'admin_test'
    })
    flash(f"'{user['username']}' 접속 기록 완료: {ip_address}", "success")
    return redirect(url_for('home'))

# 접속 로그 확인
@app.route('/logs/<user_id>', methods=['GET'])
@login_required
def view_logs(user_id):
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        flash("사용자를 찾을 수 없습니다.", "danger")
        return redirect(url_for('home'))
    
    username = user_doc.to_dict()['username']
    logs = [(doc.id, doc.to_dict()['access_time'], doc.to_dict()['ip_address']) 
            for doc in db.collection('access_logs').where('user_id', '==', user_id).order_by('access_time', direction=firestore.Query.DESCENDING).get()]
    return render_template('logs.html', username=username, logs=logs, user_id=user_id)

# 개별 로그 삭제
@app.route('/delete_log/<log_id>/<user_id>')
@login_required
def delete_log(log_id, user_id):
    log_doc = db.collection('access_logs').document(log_id).get()
    if not log_doc.exists:
        flash("로그를 찾을 수 없습니다.", "danger")
    else:
        db.collection('access_logs').document(log_id).delete()
        flash("로그 삭제 완료!", "success")
    return redirect(url_for('view_logs', user_id=user_id))

# 전체 로그 삭제
@app.route('/delete_all_logs/<user_id>')
@login_required
def delete_all_logs(user_id):
    logs = db.collection('access_logs').where('user_id', '==', user_id).get()
    for log in logs:
        db.collection('access_logs').document(log.id).delete()
    flash("모든 로그 삭제 완료!", "success")
    return redirect(url_for('view_logs', user_id=user_id))

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
