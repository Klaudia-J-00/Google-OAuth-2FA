from flask import Flask, redirect, url_for, session, render_template, request
from authlib.integrations.flask_client import OAuth
import random
import os
import sendgrid
from sendgrid.helpers.mail import Mail

app = Flask(__name__)
app.secret_key = os.urandom(24)

SENDGRID_API_KEY="API_KEY"

# OAuth Configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID", "client_id"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", "secret"),
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile', 'prompt': 'consent',},
    server_metadata_url= 'https://accounts.google.com/.well-known/openid-configuration',
)

# Home Route
@app.route('/')
def home():
    if 'email' in session:
        name = session.get('name', 'User')
        picture = session.get('picture', None)
        return render_template('index.html', email=session['email'], name=name, picture=picture)
    return redirect(url_for('login'))


def send_otp_email(email):
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    message = Mail(
        from_email='jedryszczakklaudia@gmail.com',
        to_emails=email,
        subject='Two-Factor Code',
        plain_text_content=f'Your OTP code is {otp}'
    )

    sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
    response = sg.send(message)
    return response

# Login Route
@app.route('/login')
def login():
    return render_template('login.html')


# Google Login
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorized', _external=True)
    print(redirect_uri)
    return google.authorize_redirect(redirect_uri)


@app.route('/login/authorized')
def google_authorized():
    try:
        token = google.authorize_access_token()
        user_info = google.get('userinfo').json()
        print(f"User Info: {user_info}")  # Debugging
        session['email'] = user_info['email']
        session['name'] = user_info['name']
        session['picture'] = user_info['picture']

        return redirect(url_for('two_factor'))
    except Exception as e:
        print(f"Error during authorization: {e}")
        return "Authorization failed.", 500


# 2FA Route
@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        if entered_otp == str(session.get('otp')):
            return redirect(url_for('home'))
        else:
            return render_template('2fa.html', error="Invalid OTP. Try again.")

    send_otp_email(session['email'])

    return render_template('2fa.html', message="Session: " + str(session))



# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
