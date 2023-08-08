from appwrite.client import Client
from appwrite.exception import AppwriteException
from flask import Flask, request, redirect, url_for, session, render_template, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from appwrite.services.users import Users
from appwrite.id import ID
import requests


app = Flask(__name__, static_url_path='/static')
app.secret_key = '0123456789'

login_manager = LoginManager()
login_manager.init_app(app)

client = Client()
client.set_endpoint("https://cloud.appwrite.io/v1")
client.set_project('64d1de4bc952004af83b')
client.set_key('b7d128a73e5c63bdefb139e034bf8216f4f16aa93cd008d5da6c4e225137fb8efb70ac7f83e24d841b731bef0be181062ad4c8d68ae3a456cf08a95a50641351491397183cb136531da261e44925b4889e53582a483e34a89141d6fbddbe3c9174af4b28ce39c0efb750498dfde4cc2256e7e46d366a45f8674db2b83d63f53b')
databaseId = '64d1e050081fac6a3356'
collectionId = '64d1e05de84b37097599'


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
    created_user = users.create(
        user_id=ID.unique(),
        name=name,
        email=email,
        phone=phone,
        password=password
    )
    return created_user


def get_session_cookies():
    cookies = request.cookies.get('session')
    print("cookies", cookies)
    return cookies


def delete_session():
    session_id = session['session_id']
    url = f"https://cloud.appwrite.io/v1/account/sessions/current"
    headers = {'X-Appwrite-Project': '64d1de4bc952004af83b'}
    response = requests.delete(url, headers=headers)
    return response.status_code


def get_account(cookie):
    url = "https://cloud.appwrite.io/v1/account"
    cookie = "a_session_"+'64d1de4bc952004af83b'+"="+str(cookie)
    print(cookie)
    headers1 = {'X-Appwrite-Project': '64d1de4bc952004af83b', 'Cookie': cookie}
    response = requests.get(url, headers=headers1)
    data = response.json()
    print(data)
    return data


def authenticate_user(email, password):
    url = "https://cloud.appwrite.io/v1/account/sessions/email"
    headers = {'X-Appwrite-Project': '64d1de4bc952004af83b'}
    response = requests.post(url,
                             headers=headers,
                             json={'email': email, 'password': password})
    cookie = request.cookies.get('session')
    print(cookie)
    print(response.json())
    if response.status_code == 201:
        session_data = response.json()
        # session_id = session_data['$id']
        session_expire = session_data['expire']
        session['session_id'] = session_data['$id']
        print(f"Authenticated with session ID: {session['session_id']}")
        print(f'Session expire: {session_expire}')
        return session_data['providerUid']
    else:
        print('Authentication failed')
        return None


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        phone_number = request.form.get('phone_number')
        if password != confirm_password:
            error_message = "Passwords do not match"
            flash(error_message, category='danger')
            return render_template('signup.html')
        try:
            user = create_new_user(name, email, password, phone_number)
        except AppwriteException as e:
            return render_template('signup.html', error=True, error_message=e)
        else:
            success_message = "A new user has been created"
            flash(f'Login successful! Welcome {success_message}', category='success')
            return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/home')
@login_required
def home():
    user_id = session['user_email']
    user = load_user(user_id)
    # print(f"Login successful for the user {user.id}")
    flash(f"Login successful! Welcome {user.id}", category='success')
    return render_template('home.html')
# def home():
#     # name = get_account()
#     # return f"Login successful for the user {current_user.id}"
#     return render_template('home.html')


@app.route('/cash')
@login_required
def cash():
    return render_template('cash.html')


@app.route('/derivatives')
@login_required
def derivatives():
    return render_template('derivatives.html')


@app.route('/history')
@login_required
def history():
    return render_template('history.html')


@app.route('/options')
@login_required
def options():
    return render_template('options.html')

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            user_email = authenticate_user(email, password)
            if user_email:
                login_user(load_user(user_email))
                session['user_email'] = user_email
                return redirect(url_for('home'))
            else:
                error_message = "Invalid email or password"
                flash(error_message, category='danger')
        except AppwriteException as e:
            error_message = e
        # flash(error_message, category='danger')
    return render_template('login.html')


@app.route('/logout')
@login_required  # Protect this route, only logged-in users can log out
def logout():
    delete_session()
    logout_user()  # Log out the user
    flash("You have been logged out!", category='info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)


# headers = {
#   'X-Appwrite-Project': '64d1de4bc952004af83b',
#   'Cookie': 'a_session_64cfa4194d98073dddde=eyJfZnJlc2giOmZhbHNlLCJ1c2VyX2VtYWlsIjoibXVubnVzaGVyaWZmQGdtYWlsLmNvbSJ9.ZM-4dA.fysxGOT9veU0Jck-C3kW6fflrUY'
# }
