from loginapp import app
from loginapp import db
from flask import flash, redirect, render_template, request, send_from_directory, session, url_for
from flask_bcrypt import Bcrypt
import re
from PIL import Image, ExifTags
import os
import time

# Create upload folder constant
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
# Ensure the upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Create an instance of the Bcrypt class, which we'll be using to hash user
# passwords during login and registration.
flask_bcrypt = Bcrypt(app)

# Default role assigned to new users upon registration.
DEFAULT_USER_ROLE = 'visitor'

def user_home_url():
    role = session.get('role', None)

    if role == 'visitor':
        home_endpoint = 'visitor_home'
    elif role == 'helper':
        home_endpoint = 'helper_home'
    elif role == 'admin':
        home_endpoint = 'admin_home'
    else:
        home_endpoint = 'login'
    
    return url_for(home_endpoint)

@app.route('/')
def root():
    return redirect(user_home_url())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'loggedin' in session:
        return redirect(user_home_url())

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Get the login details submitted by the user.
        username = request.form['username']
        password = request.form['password']

        # Attempt to validate the login details against the database.
        with db.get_cursor() as cursor:
            # Try to retrieve the account details for the specified username.
            cursor.execute('''
                           SELECT user_id, username, password_hash, role, status
                           FROM users
                           WHERE username = %s;
                           ''', (username,))
            account = cursor.fetchone()
            
            if account is not None:
                # We found a matching account: now we need to check whether the
                # password they supplied matches the hash in our database.
                password_hash = account['password_hash']
                
                if flask_bcrypt.check_password_hash(password_hash, password):
                    if account['status'] == 'inactive':
                        return render_template('login.html',
                                           username=username,
                                           account_inactive=True)
                    # Password is correct. Save the user's ID, username, and role
                    # as session data, which we can access from other routes to
                    # determine who's currently logged in.
                    session['loggedin'] = True
                    session['user_id'] = account['user_id']
                    session['username'] = account['username']
                    session['role'] = account['role']

                    return redirect(user_home_url())
                else:
                    # Password is incorrect.
                    return render_template('login.html',
                                           username=username,
                                           password_invalid=True)
            else:
                # We didn't find an account in the database with this username.
                return render_template('login.html', 
                                       username=username,
                                       username_invalid=True)

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User signup endpoint."""
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        location = request.form.get('location')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Save form data for error display
        form_data = {
            'username': username,
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'location': location
        }
        
        # Validate first name length
        if len(first_name) < 2 or len(first_name) > 50:
            return render_template('signup.html',
                                 first_name_error='First name must be between 2 and 50 characters',
                                 **form_data)
        if len(last_name) < 2 or len(last_name) > 50:
            return render_template('signup.html',
                                 last_name_error='Last name must be between 2 and 50 characters',
                                 **form_data)

        # Email validation
        email_pattern = r'[a-zA-Z0-9][a-zA-Z0-9-_.]{1,}@[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}'
        if not re.match(email_pattern, email):
            return render_template('signup.html',
                                 confirm_password_error='Invalid email format',
                                 **form_data)

        # Validate email length
        if len(email) > 100:
            return render_template('signup.html',
                                 confirm_password_error='Email is too long (maximum 100 characters)',
                                 **form_data)
        
        if len(location) > 50:
            return render_template('signup.html',
                                 confirm_password_error='Location is too long (maximum 50 characters)',
                                 **form_data)
        
        # Validate password match
        if password != confirm_password:
            return render_template('signup.html',
                                 confirm_password_error='Passwords do not match',
                                 **form_data)
        
        # Validate password format
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', password):
            return render_template('signup.html',
                                 password_error='Password must be at least 8 characters long and contain both letters and numbers',
                                 **form_data)
        
        cursor = db.get_db().cursor()
        
        try:
            # Check if username already exists
            cursor.execute('SELECT 1 FROM users WHERE username = %s', (username,))
            if cursor.fetchone():
                return render_template('signup.html',
                                     username_error='Username already exists',
                                     **form_data)
            
            # Check if email already exists
            cursor.execute('SELECT 1 FROM users WHERE email = %s', (email,))
            if cursor.fetchone():
                return render_template('signup.html',
                                     email_error='Email already exists',
                                     **form_data)
            
            # Create new user
            cursor.execute(
                'INSERT INTO users (username, email, first_name, last_name, location, password_hash, role) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (username, email, first_name, last_name, location, flask_bcrypt.generate_password_hash(password), 'visitor')
            )
            db.get_db().commit()
            return render_template('signup.html', signup_successful=True)
            
        except Exception as e:
            print(e)
            return render_template('signup.html',
                                 error='An error occurred during registration',
                                 **form_data)
        finally:
            # Ensure all results are read
            while cursor.nextset():
                pass
            cursor.close()
    
    return render_template('signup.html')

@app.route('/profile')
def profile():
    """User Profile page endpoint.

    Methods:
    - get: Renders the user profile page for the current user.

    If the user is not logged in, requests will redirect to the login page.
    """
    show_password_tab = request.args.get('show_password_tab', 'false').lower() == 'true'

    if 'loggedin' not in session:
        return redirect(url_for('login'))

    with db.get_cursor() as cursor:
        cursor.execute('''
            SELECT username, email, first_name, last_name, location, 
                   role, status, profile_image 
            FROM users 
            WHERE user_id = %s;
        ''', (session['user_id'],))
        profile = cursor.fetchone()

    return render_template('profile.html', profile=profile, show_password_tab=show_password_tab)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Update user profile information."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # Get form data
    email = request.form.get('email', '').strip()
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    location = request.form.get('location', '').strip()

    # Initialize error variables
    errors = {}

    # Check if all required fields are present
    if not all([email, first_name, last_name, location]):
        if not email:
            errors['email_error'] = 'Email is required.'
        if not first_name:
            errors['first_name_error'] = 'First name is required.'
        if not last_name:
            errors['last_name_error'] = 'Last name is required.'
        if not location:
            errors['location_error'] = 'Location is required.'
    else:
        # Validate fields
        email_pattern = r'[a-zA-Z0-9][a-zA-Z0-9-_.]{1,}@[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}'
        if len(email) > 100:
            errors['email_error'] = 'Email address cannot exceed 100 characters.'
        elif not re.match(email_pattern, email):
            errors['email_error'] = 'Invalid email address.'

        if len(first_name) > 50 or len(first_name) < 2:
            errors['first_name_error'] = 'First name must be between 2 and 50 characters.'

        if len(last_name) > 50 or len(last_name) < 2:
            errors['last_name_error'] = 'Last name must be between 2 and 50 characters.'

        if len(location) > 50:
            errors['location_error'] = 'Location cannot exceed 50 characters.'
    
    # If there are errors, re-fetch profile and return with errors
    with db.get_cursor() as cursor:
        cursor.execute('''
            SELECT username, email, first_name, last_name, location, 
                    role, status, profile_image 
            FROM users 
            WHERE user_id = %s;
        ''', (session['user_id'],))
        profile = cursor.fetchone()

    if profile["email"] != email:
        # Check if email already exists
        with db.get_cursor() as cursor:
            cursor.execute('SELECT 1 FROM users WHERE email = %s', (email,))
            if cursor.fetchone():
                errors['email_error'] = 'Email already exists.'
        profile["email"]=email

    # If there are errors, re-render the profile page with error messages
    if errors:
        return render_template('profile.html', profile=profile, **errors)

    # Update the user's profile in the database
    with db.get_cursor() as cursor:
        cursor.execute('''
            UPDATE users 
            SET email = %s, first_name = %s, last_name = %s, location = %s 
            WHERE user_id = %s
        ''', (email, first_name, last_name, location, session['user_id']))
        db.get_db().commit()

    flash('Profile updated successfully', 'success')
    return redirect(url_for('profile'))

def fix_image_orientation(image):
    try:
        # 获取EXIF数据
        for orientation in ExifTags.TAGS.keys():
            if ExifTags.TAGS[orientation] == 'Orientation':
                break
        
        exif = dict(image._getexif().items())

        if orientation in exif:
            if exif[orientation] == 3:
                image = image.rotate(180, expand=True)
            elif exif[orientation] == 6:
                image = image.rotate(270, expand=True)
            elif exif[orientation] == 8:
                image = image.rotate(90, expand=True)
                
    except (AttributeError, KeyError, IndexError):
        # 某些图片可能没有EXIF信息，直接跳过
        pass
    
    return image

@app.route('/update_profile_image', methods=['POST'])
def update_profile_image():
    """Update user profile image."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # Handle image deletion
    if 'delete_image' in request.form:
        with db.get_cursor() as cursor:
            # Get current image filename
            cursor.execute('SELECT profile_image FROM users WHERE user_id = %s;', 
                         (session['user_id'],))
            result = cursor.fetchone()
            if result and result['profile_image']:
                # Delete the file
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER, result['profile_image']))
                except OSError:
                    pass  # File might not exist
                
                # Update database
                cursor.execute('UPDATE users SET profile_image = NULL WHERE user_id = %s;',
                             (session['user_id'],))
        
        return redirect(url_for('profile'))

    # Handle image upload
    if 'profile_image' not in request.files:
        flash('No file uploaded', 'danger')
        return redirect(url_for('profile'))
    
    file = request.files['profile_image']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))

    if file and allowed_file(file.filename):
        try:
            # 读取图片并修复方向
            image = Image.open(file)
            image = fix_image_orientation(image)
            
            # 获取原始文件扩展名
            original_extension = os.path.splitext(file.filename)[1].lower()
            if original_extension.startswith('.'):
                original_extension = original_extension[1:]
            
            # 生成文件名
            filename = f"profile_{session['user_id']}_{int(time.time() * 1000)}.{original_extension}"
            
            # 保存处理后的图片
            image.save(os.path.join(UPLOAD_FOLDER, filename))
            
            # 更新数据库
            with db.get_cursor() as cursor:
                # Delete old image if exists
                cursor.execute('SELECT profile_image FROM users WHERE user_id = %s;',
                             (session['user_id'],))
                result = cursor.fetchone()
                if result and result['profile_image']:
                    try:
                        os.remove(os.path.join(UPLOAD_FOLDER, result['profile_image']))
                    except OSError:
                        pass

                # Update with new image
                cursor.execute('UPDATE users SET profile_image = %s WHERE user_id = %s;',
                             (filename, session['user_id']))

            flash('Profile image updated successfully', 'success')
            
        except Exception as e:
            flash('Error processing image', 'danger')
            print(f"Error: {str(e)}")
            
        return redirect(url_for('profile'))
    else:
        flash('Invalid file format. Please upload a valid image file.', 'danger')

    return redirect(url_for('profile'))

@app.route('/profile/image/<filename>')
def get_profile_image(filename):
    """Serve profile images."""
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # 验证表单数据完整性
    if not all([current_password, new_password, confirm_password]):
        flash('All fields are required', 'danger')
        return redirect(url_for('profile', show_password_tab=True))
    
    cursor = db.get_db().cursor()
    
    try:
        # 验证当前密码
        cursor.execute('SELECT password_hash FROM users WHERE user_id = %s', (session['user_id'],))
        user = cursor.fetchone()
        if not user or not flask_bcrypt.check_password_hash(user[0], current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('profile', show_password_tab=True))
        
        # 验证新密码
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('profile', show_password_tab=True))
        
        # 验证新密码格式
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', new_password):
            flash('Password must be at least 8 characters long and contain both letters and numbers', 'danger')
            return redirect(url_for('profile', show_password_tab=True))
        
        # 验证新密码不能与当前密码相同
        if flask_bcrypt.check_password_hash(user[0], new_password):
            flash('New password cannot be the same as current password', 'danger')
            return redirect(url_for('profile', show_password_tab=True))
        
        # 更新密码
        cursor.execute(
            'UPDATE users SET password_hash = %s WHERE user_id = %s',
            (flask_bcrypt.generate_password_hash(new_password), session['user_id'])
        )
        db.get_db().commit()
        
        flash('Password has been updated successfully', 'success')
        return redirect(url_for('profile', show_password_tab=True))
    
    finally:
        cursor.close()

@app.route('/logout')
def logout():
    """Logout endpoint.

    Methods:
    - get: Logs the current user out (if they were logged in to begin with),
        and redirects them to the login page.
    """
    # Note that nothing actually happens on the server when a user logs out: we
    # just remove the cookie from their web browser. They could technically log
    # back in by manually restoring the cookie we've just deleted. In a high-
    # security web app, you may need additional protections against this (e.g.
    # keeping a record of active sessions on the server side).
    session.pop('loggedin', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    
    return redirect(url_for('login'))