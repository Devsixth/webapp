from appwrite.client import Client
from appwrite.exception import AppwriteException
from flask import Flask, request, redirect, url_for, session, render_template, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from appwrite.services.users import Users
from appwrite.services.databases import Databases
from appwrite.id import ID
import requests
import os
from waitress import serve
from datetime import datetime, timedelta

project_id = "64e6e1bc184f94861801"

app = Flask(__name__, static_url_path='/static')
app.secret_key = 12345678
login_manager = LoginManager()
login_manager.init_app(app)

client = Client()
client.set_endpoint("https://cloud.appwrite.io/v1")
client.set_project(project_id)
client.set_key("8905a3d9dd7d7c37ab085c038a34eacfa900ad4fd4a5e9cc5c8a1313ec061e8d06d0a5e1a2529dc1c14a025005f0e90315c04df540e7c53d2016424246aa284f9d22af5f4ec32901f805b458173c9c7d3ba84b509ea0868a30dc452a2f85c63dcac55f23dbe6e485aa87b59b9c0b9619107a613c440972636afc902e1049039b")
databaseId = "64e6e238bd3d79bda710"
collectionId = "64e8839e35cdb1292a9d"


class User(UserMixin):
    def __init__(self, id):
        self.id = id

    def is_active(self):
        return True  # Return True if the user is active

    def is_authenticated(self):
        return True  # Return True if the user is authenticated


@login_manager.user_loader
def load_user(user_id):
    # Create and return a User object based on the user_id
    return User(user_id)


def create_new_user(name, email, password, phone):
    users = Users(client)
    print(users)
    created_user = users.create(
        user_id=ID.unique(),
        name=name,
        email=email,
        phone=phone,
        password=password
    )
    print(created_user)
    return created_user['$id']


def insert_user(username, email, phone, trading_exp, segment, date, assign_id):
    databases = Databases(client)
    data = {
        "id": assign_id,
        "username": username,
        "email": email,
        "phone": phone,
        "trading_exp": trading_exp,
        "segment": segment,
        "date": date,

    }
    result = databases.create_document(databaseId, collectionId, ID.unique(), data)
    return result['$id']


def get_account():
    url = "https://cloud.appwrite.io/v1/account"
    cookies = session['cookies']
    headers = {'X-Appwrite-Project': project_id }
    response = requests.get(url, headers=headers, cookies=cookies)
    data = response.json()
    print(data)
    return data['name']


def authenticate_user(email, password):
    url = "https://cloud.appwrite.io/v1/account/sessions/email"
    headers = {'X-Appwrite-Project': project_id}
    response = requests.post(url,
                             headers=headers,
                             json={'email': email, 'password': password})

    if response.status_code == 201:
        session_data = response.json()
        session_expire = session_data['expire']
        cookies = response.cookies.get_dict()
        session['session_id'] = session_data['$id']
        print(f"Authenticated with session ID: {session['session_id']}")
        print(f'Session expire: {session_expire}')
        return session_data['providerUid'], cookies
    else:
        print('Authentication failed')
        return None, None


def list_docs():
    databases = Databases(client)
    data = databases.list_documents(databaseId, '64e6e266b3c93226c01b')
    print(data)
    return data['documents']


def get_latest_id(signup_db_col_id):
    databases = Databases(client)
    data = databases.list_documents(databaseId, signup_db_col_id)
    # print(data)
    docs = data['documents']
    if len(docs) == 0:
        return "S0001"
    latest_id = docs[-1]['id']
    print("latest id",  latest_id)
    inc_by_1 = int(latest_id[1:]) + 1
    new_id = f"S{'0'* (5 - (len(str(inc_by_1)) + 1))}{inc_by_1}"
    print("new id",new_id)
    return new_id


def get_user_signup_date(signup_db_col_id, user_email):
    databases = Databases(client)
    data = databases.list_documents(databaseId, signup_db_col_id)
    # print(data)
    print(user_email)
    for item in data['documents']:
        if item['email'] == user_email:
            print(item['email'], user_email)
            print(item['date'])
            return item['date']
    return None


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        phone_number = request.form.get('phone_number')
        trading_experience = request.form.get('trading_exp')
        segment = request.form.get('segment')
        if password != confirm_password:
            error_message = "Passwords do not match"
            flash(error_message, category='danger')
            return render_template('signup.html')
        try:
            user = create_new_user(name, email, password, phone_number)
            latest_id = get_latest_id(collectionId)
            current_datetime = datetime.now()
            current_datetime_str = current_datetime.strftime("%d-%m-%YT%H:%M:%S")
            insert_user(name, email, phone_number, trading_experience, segment, current_datetime_str, latest_id)
        except AppwriteException as e:
            flash(e, category='danger')
            return render_template('signup.html', error=True, error_message=e)
        else:
            success_message = "A new user has been created"
            flash(f'{success_message}', category='success')
            return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/home')
@login_required
def home():
    user_id = session['user_email']
    user_name = get_account()
    user = load_user(user_id)
    signup_date = get_user_signup_date(collectionId, user_id)
    expiration_date = datetime.strptime(signup_date[:10], "%d-%m-%Y") + timedelta(days=7)
    expiration_date_str = expiration_date.strftime("%d/%m/%Y")
    signup_date_str = session.get('signup_date', '')
    return render_template('home.html', user_name=user_name, expiration_date=expiration_date_str, signup_date=signup_date_str)


@app.route('/cash')
@login_required
def cash():
    try:
        documents = list_docs()
        print(documents)
    except AppwriteException as e:
        flash(e.message, category='danger')
    return render_template('cash.html', documents=documents)


@app.route('/future')
@login_required
def future():
    return render_template('future.html')

@app.route('/index')
@login_required
def index():
    return render_template('index.html')

@app.route('/history')
@login_required
def history():
    return render_template('history.html')


@app.route('/options')
@login_required
def options():
    return render_template('options.html')


@app.route('/news')
@login_required
def news():
    return render_template('news.html')


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember_me = request.form.get('rememberMe')
        try:
            user_email, cookies = authenticate_user(email, password)
            if user_email:
                login_user(load_user(user_email))
                session['user_email'] = user_email
                session['cookies'] = cookies
                user_name = get_account()
                if remember_me:
                    session.permanent = True
                else:
                    session.permanent = False
                flash(f"Login successful! Welcome {user_name}", category='success')
                return redirect(url_for('home'))
            else:
                error_message = "Invalid email or password"
                flash(error_message, category='danger')
        except AppwriteException as e:
            error_message = e.message
            flash(error_message, category='danger')
    return render_template('login.html')


@app.route('/logout')
@login_required  # Protect this route, only logged-in users can log out
def logout():
    logout_user()  # Log out the user
    flash("You have been logged out!", category='info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=8000)



