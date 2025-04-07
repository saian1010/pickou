from loginapp import app
from loginapp import db
from flask import flash, redirect, render_template, request, send_from_directory, session, url_for
from flask_bcrypt import Bcrypt
import re
from PIL import Image, ExifTags, ImageDraw, ImageFont
import os
import time
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import jsonify
from authlib.integrations.flask_client import OAuth
import random
import json

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



# 配置应用密钥
app.secret_key = os.urandom(24)

# 配置 OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID", ""),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}
)

# 处理 Google 回调
@app.route('/callback')
def callback():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    
    # 提取Google用户信息
    google_email = user_info.get('email')
    google_name = user_info.get('name', '')
    google_picture = user_info.get('picture', '')
    
    if not google_email:
        flash('无法获取Google账号信息', 'danger')
        return redirect(url_for('login'))
    
    # 检查该Google邮箱是否已经关联本地账号
    with db.get_cursor() as cursor:
        cursor.execute('SELECT user_id, username, role, status FROM users WHERE email = %s', (google_email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            # 如果用户存在且状态为非活跃，拒绝登录
            if existing_user['status'] == 'inactive':
                flash('您的账号已被禁用，请联系管理员', 'danger')
                return redirect(url_for('login'))
            
            # 用户存在，直接登录
            session['loggedin'] = True
            session['user_id'] = existing_user['user_id']
            session['username'] = existing_user['username']
            session['role'] = existing_user['role']
            flash('Google登录成功', 'success')
        else:
            # 用户不存在，创建新用户
            # 从名字创建用户名（保证唯一性）
            if google_name:
                base_username = google_name.split()[0].lower()  # 使用名字的第一部分作为用户名基础
            else:
                base_username = google_email.split('@')[0]  # 使用邮箱前缀作为用户名基础
            
            # 确保用户名唯一
            username = base_username
            suffix = 1
            while True:
                cursor.execute('SELECT 1 FROM users WHERE username = %s', (username,))
                if not cursor.fetchone():
                    break
                username = f"{base_username}{suffix}"
                suffix += 1
            
            # 创建随机密码（用户之后可以更改）
            import secrets
            random_password = secrets.token_urlsafe(12)
            
            # 名字处理
            name_parts = google_name.split()
            first_name = name_parts[0] if name_parts else ''
            last_name = name_parts[-1] if len(name_parts) > 1 else ''
            
            # 插入新用户
            cursor.execute(
                '''INSERT INTO users 
                   (username, email, first_name, last_name, password_hash, role, profile_image, google_id) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
                (username, google_email, first_name, last_name, 
                 flask_bcrypt.generate_password_hash(random_password),
                 DEFAULT_USER_ROLE, google_picture, user_info.get('id'))
            )
            db.get_db().commit()
            
            # 获取新创建用户的ID
            cursor.execute('SELECT user_id, username, role FROM users WHERE email = %s', (google_email,))
            new_user = cursor.fetchone()
            
            # 设置会话
            session['loggedin'] = True
            session['user_id'] = new_user['user_id']
            session['username'] = new_user['username']
            session['role'] = new_user['role']
            flash('Google账号注册成功并已登录', 'success')
    
    # 重定向到用户首页
    return redirect(user_home_url())

# 登录路由
@app.route('/google_login')
def google_login():
    return google.authorize_redirect(url_for('callback', _external=True))


def user_home_url():
    role = session.get('role', None)

    if role == 'visitor':
        home_endpoint = 'visitor_home'
    elif role == 'helper':
        home_endpoint = 'helper_home'
    elif role == 'admin':
        home_endpoint = 'admin_home'
    else:
        home_endpoint = 'visitor_home'
    
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
            
    signup_successful = request.args.get('signup_successful', 'false')
    print(signup_successful)
    return render_template('login.html', signup_successful=signup_successful)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User signup endpoint."""
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        # email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        dob_month = request.form.get('dob-month')
        dob_year = request.form.get('dob-year')
        gender = request.form.get('gender')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Save form data for error display
        form_data = {
            'username': username,
            'dob-month': dob_month,
            'dob-year': dob_year,
            'gender': gender,
            'first_name': first_name,
            'last_name': last_name
        }
        print(form_data)
        # Validate first name length
        # if len(first_name) < 2 or len(first_name) > 50:
        #     return render_template('signup.html',
        #                          first_name_error='First name must be between 2 and 50 characters',
        #                          **form_data)
        # if len(last_name) < 2 or len(last_name) > 50:
        #     return render_template('signup.html',
        #                          last_name_error='Last name must be between 2 and 50 characters',
        #                          **form_data)

        # # Email validation
        # email_pattern = r'[a-zA-Z0-9][a-zA-Z0-9-_.]{1,}@[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}'
        # if not re.match(email_pattern, email):
        #     return render_template('signup.html',
        #                          confirm_password_error='Invalid email format',
        #                          **form_data)

        # # Validate email length
        # if len(email) > 100:
        #     return render_template('signup.html',
        #                          confirm_password_error='Email is too long (maximum 100 characters)',
        #                          **form_data)
        
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
            
            # # Check if email already exists
            # cursor.execute('SELECT 1 FROM users WHERE email = %s', (email,))
            # if cursor.fetchone():
            #     return render_template('signup.html',
            #                          email_error='Email already exists',
            #                          **form_data)
            
            # Create new user
            cursor.execute(
                'INSERT INTO users (username, dob_month, dob_year, gender, first_name, last_name, password_hash) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (username, dob_month, dob_year, gender , first_name, last_name, flask_bcrypt.generate_password_hash(password))
            )
            db.get_db().commit()
            return redirect(url_for('login', signup_successful=True))
            #return render_template('login.html', signup_successful=True)
            
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
            SELECT username, email, first_name, last_name, 
                   role, status, profile_image, user_id
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

    # Initialize error variables
    errors = {}

    # Check if all required fields are present
    if not all([email, first_name, last_name]):
        if not email:
            errors['email_error'] = 'Email is required.'
        if not first_name:
            errors['first_name_error'] = 'First name is required.'
        if not last_name:
            errors['last_name_error'] = 'Last name is required.'
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
    
    # If there are errors, re-fetch profile and return with errors
    with db.get_cursor() as cursor:
        cursor.execute('''
            SELECT username, email, first_name, last_name, 
                   role, status, profile_image, user_id
            FROM users 
            WHERE user_id = %s;
        ''', (session['user_id'],))
        profile = cursor.fetchone()

    if profile.get("email") and email and profile["email"] != email:
        # Check if email already exists
        with db.get_cursor() as cursor:
            cursor.execute('SELECT 1 FROM users WHERE email = %s AND user_id != %s', (email, session['user_id']))
            if cursor.fetchone():
                errors['email_error'] = 'Email already exists.'
        profile["email"] = email

    # If there are errors, re-render the profile page with error messages
    if errors:
        return render_template('profile.html', profile=profile, **errors)

    # Update the user's profile in the database
    with db.get_cursor() as cursor:
        cursor.execute('''
            UPDATE users 
            SET email = %s, first_name = %s, last_name = %s 
            WHERE user_id = %s
        ''', (email, first_name, last_name, session['user_id']))
        db.get_db().commit()

    flash('Profile updated successfully', 'success')
    return redirect(url_for('profile'))

def fix_image_orientation(image):
    try:
        # Get EXIF data
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
        # Some images may not have EXIF information, skip those
        pass
    
    return image

@app.route('/update_profile_image', methods=['POST'])
def update_profile_image():
    """Update user profile image."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # Specify upload folder
    PROFILE_UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads', 'profiles')
    # Ensure directory exists
    os.makedirs(PROFILE_UPLOAD_FOLDER, exist_ok=True)

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
                    os.remove(os.path.join(PROFILE_UPLOAD_FOLDER, result['profile_image']))
                except OSError:
                    pass  # File might not exist
                
                # Update database
                cursor.execute('UPDATE users SET profile_image = NULL WHERE user_id = %s;',
                             (session['user_id'],))
                db.get_db().commit()
        
        flash('Avatar deleted', 'success')
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
            # Read image and fix orientation
            image = Image.open(file)
            image = fix_image_orientation(image)
            
            # Get original file extension
            original_extension = os.path.splitext(file.filename)[1].lower()
            if original_extension.startswith('.'):
                original_extension = original_extension[1:]
            
            # Generate filename
            filename = f"profile_{session['user_id']}_{int(time.time() * 1000)}.{original_extension}"
            
            # Save processed image
            image.save(os.path.join(PROFILE_UPLOAD_FOLDER, filename))
            
            # Update database
            with db.get_cursor() as cursor:
                # Delete old image if exists
                cursor.execute('SELECT profile_image FROM users WHERE user_id = %s;',
                             (session['user_id'],))
                result = cursor.fetchone()
                if result and result['profile_image']:
                    try:
                        os.remove(os.path.join(PROFILE_UPLOAD_FOLDER, result['profile_image']))
                    except OSError:
                        pass

                # Update with new image
                cursor.execute('UPDATE users SET profile_image = %s WHERE user_id = %s;',
                             (filename, session['user_id']))
                db.get_db().commit()

            flash('Avatar uploaded successfully', 'success')
            
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
    profile_upload_folder = os.path.join(app.static_folder, 'uploads', 'profiles')
    return send_from_directory(profile_upload_folder, filename)

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validate form data completeness
    if not all([current_password, new_password, confirm_password]):
        flash('All fields are required', 'danger')
        return redirect(url_for('profile', show_password_tab=True))
    
    cursor = db.get_db().cursor()
    
    try:
        # Verify current password
        cursor.execute('SELECT password_hash FROM users WHERE user_id = %s', (session['user_id'],))
        user = cursor.fetchone()
        if not user or not flask_bcrypt.check_password_hash(user[0], current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('profile', show_password_tab=True))
        
        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('profile', show_password_tab=True))
        
        # Validate new password format
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', new_password):
            flash('Password must be at least 8 characters long and contain both letters and numbers', 'danger')
            return redirect(url_for('profile', show_password_tab=True))
        
        # Validate new password is different from current password
        if flask_bcrypt.check_password_hash(user[0], new_password):
            flash('New password cannot be the same as current password', 'danger')
            return redirect(url_for('profile', show_password_tab=True))
        
        # Update password
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


@app.route('/messages')
def messages():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    return render_template('messages.html')


@app.route('/me')
def me():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    with db.get_cursor() as cursor:
        # Get user profile information
        cursor.execute('''
            SELECT username, email, first_name, last_name, 
                   role, status, profile_image, user_id
            FROM users 
            WHERE user_id = %s;
        ''', (user_id,))
        profile = cursor.fetchone()
        
        # Get following count (people the user follows)
        cursor.execute('''
            SELECT COUNT(*) as following_count
            FROM follows
            WHERE follower_id = %s;
        ''', (user_id,))
        following_result = cursor.fetchone()
        following_count = following_result['following_count'] if following_result else 0
        
        # Get followers count (people who follow the user)
        cursor.execute('''
            SELECT COUNT(*) as followers_count
            FROM follows
            WHERE user_id = %s;
        ''', (user_id,))
        followers_result = cursor.fetchone()
        followers_count = followers_result['followers_count'] if followers_result else 0
        
        # Get likes received count (likes on user's posts)
        cursor.execute('''
            SELECT COUNT(*) as likes_count
            FROM likes l
            JOIN posts p ON l.post_id = p.post_id
            WHERE p.user_id = %s;
        ''', (user_id,))
        likes_result = cursor.fetchone()
        likes_received = likes_result['likes_count'] if likes_result else 0
        
        # Get likes given count (posts the user has liked)
        cursor.execute('''
            SELECT COUNT(*) as likes_given_count
            FROM likes
            WHERE user_id = %s;
        ''', (user_id,))
        likes_given_result = cursor.fetchone()
        likes_given = likes_given_result['likes_given_count'] if likes_given_result else 0
        
        # Total likes count (both given and received)
        total_likes = likes_given
        
        # Create stats dictionary
        user_stats = {
            'following_count': following_count,
            'followers_count': followers_count,
            'likes_count': total_likes
        }

    return render_template('me.html', profile=profile, user_stats=user_stats)


@app.route('/subscription')
def subscription():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    return render_template('subscription.html')


@app.route('/list_posts')
def list_posts():
    """List all posts endpoint.
    
    This endpoint is used to retrieve a paginated list of all posts. It supports
    pagination via query parameters 'page' and 'per_page'.
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    
    # Calculate offset for pagination
    offset = (page - 1) * per_page
    
    with db.get_cursor() as cursor:
        # Get current user ID if logged in
        current_user_id = session.get('user_id', None)
        
        # Query to get posts with user info, image info, and likes count
        query = '''
        SELECT p.post_id, p.title, p.content, p.created_at, p.updated_at,
               u.user_id, u.username, u.profile_image,
               (SELECT image_path FROM post_images WHERE post_id = p.post_id ORDER BY created_at LIMIT 1) as image_url,
               (SELECT COUNT(*) FROM likes uv WHERE uv.post_id = p.post_id) as likes,
               (SELECT COUNT(*) > 0 FROM likes ul WHERE ul.post_id = p.post_id AND ul.user_id = %s) as user_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        ORDER BY p.created_at DESC
        LIMIT %s OFFSET %s;
        '''
        
        # Execute the query with current user ID (or NULL), limit, and offset
        cursor.execute(query, (current_user_id or 0, per_page, offset))
        posts = cursor.fetchall()
        
        # Get total post count to determine if there are more posts
        cursor.execute('SELECT COUNT(*) as total FROM posts')
        total_count = cursor.fetchone()['total']
        
        # Calculate if there are more posts based on total count
        has_more = (page * per_page) < total_count
        
        # Process posts for output
        for post in posts:
            # Convert datetime objects to strings for JSON serialization
            post['created_at'] = post['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            post['updated_at'] = post['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
            
            # Convert image URL to full path if it exists
            if post['image_url']:
                post['image_url'] = url_for('get_post_image', filename=post['image_url'])
            
            # Ensure profile image has a URL
            if post['profile_image']:
                post['profile_image'] = url_for('static', filename='uploads/profiles/' + post['profile_image'])
            else:
                post['profile_image'] = url_for('static', filename='img/default-avatar.jpg')
            
            # Convert user_liked to boolean
            post['user_liked'] = bool(post['user_liked'])
            
            # Ensure likes field is not None
            if post['likes'] is None:
                post['likes'] = 0
    
    # Return the posts as JSON
    return jsonify({
        'posts': posts,
        'page': page,
        'per_page': per_page,
        'has_more': has_more
    })


@app.route('/sub_list_posts')
def sub_list_posts():
    """Subscription list posts endpoint.
    
    This endpoint is used to retrieve a paginated list of posts from users that
    the current user follows. It supports pagination via query parameters 'page'
    and 'per_page'.
    """
    # Check if user is logged in
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'You must be logged in to view your subscription feed.'
        }), 401
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    
    # Calculate offset for pagination
    offset = (page - 1) * per_page
    
    # Get current user ID
    current_user_id = session.get('user_id')
    
    with db.get_cursor() as cursor:
        # Query to get posts with user info, image info, and likes count, filtering by followed users
        query = '''
        SELECT p.post_id, p.title, p.content, p.created_at, p.updated_at,
               u.user_id, u.username, u.profile_image,
               (SELECT image_path FROM post_images WHERE post_id = p.post_id ORDER BY created_at LIMIT 1) as image_url,
               (SELECT COUNT(*) FROM likes uv WHERE uv.post_id = p.post_id) as likes,
               (SELECT COUNT(*) > 0 FROM likes ul WHERE ul.post_id = p.post_id AND ul.user_id = %s) as user_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        JOIN follows f ON p.user_id = f.user_id AND f.follower_id = %s
        ORDER BY p.created_at DESC
        LIMIT %s OFFSET %s;
        '''
        
        # Execute the query with current user ID, limit, and offset
        cursor.execute(query, (current_user_id, current_user_id, per_page, offset))
        posts = cursor.fetchall()
        
        # Get total posts count from followed users to determine if there are more posts
        cursor.execute('''
            SELECT COUNT(*) as total 
            FROM posts p 
            JOIN follows f ON p.user_id = f.user_id AND f.follower_id = %s
        ''', (current_user_id,))
        total_count = cursor.fetchone()['total']
        
        # Calculate if there are more posts based on total count
        has_more = (page * per_page) < total_count
        
        # Process posts for output
        for post in posts:
            # Convert datetime objects to strings for JSON serialization
            post['created_at'] = post['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            post['updated_at'] = post['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
            
            # Convert image URL to full path if it exists
            if post['image_url']:
                post['image_url'] = url_for('get_post_image', filename=post['image_url'])
            
            # Ensure profile image has a URL
            if post['profile_image']:
                post['profile_image'] = url_for('static', filename='uploads/profiles/' + post['profile_image'])
            else:
                post['profile_image'] = url_for('static', filename='img/default-avatar.jpg')
            
            # Convert user_liked to boolean
            post['user_liked'] = bool(post['user_liked'])
            
            # Ensure likes field is not None
            if post['likes'] is None:
                post['likes'] = 0
    
    # Return the posts as JSON
    return jsonify({
        'posts': posts,
        'page': page,
        'per_page': per_page,
        'has_more': has_more
    })

@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    """Post detail page."""
    with db.get_cursor() as cursor:
        # Get basic post information and author information
        cursor.execute('''
            SELECT 
                p.post_id, p.title, p.content, p.created_at, p.vote_id,
                u.user_id as author_id, u.username, u.profile_image
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.post_id = %s
        ''', (post_id,))
        post = cursor.fetchone()
        
        if not post:
            flash('Post does not exist', 'danger')
            return redirect(url_for('list_posts'))
        
        # Check if current user is following the author
        is_following = False
        is_author = False
        if 'loggedin' in session:
            current_user_id = session['user_id']
            is_author = (current_user_id == post['author_id'])
            
            if not is_author:
                cursor.execute('''
                    SELECT 1 FROM follows 
                    WHERE follower_id = %s AND user_id = %s
                ''', (current_user_id, post['author_id']))
                is_following = cursor.fetchone() is not None
        
        # Get other necessary data (images, polls, comments, etc.)
        cursor.execute('''
            SELECT image_id, image_path
            FROM post_images
            WHERE post_id = %s
            ORDER BY created_at
        ''', (post_id,))
        images = cursor.fetchall()
        
        # 3. Get poll information
        vote_data = None
        if post.get('vote_id'):
            cursor.execute('''
                SELECT vote_id, title as vote_title, vote_type
                FROM votes
                WHERE vote_id = %s
            ''', (post['vote_id'],))
            vote = cursor.fetchone()
            
            if vote:
                # Get poll options
                cursor.execute('''
                    SELECT vote_option_id, title
                    FROM vote_options
                    WHERE vote_id = %s
                    ORDER BY created_at
                ''', (vote['vote_id'],))
                options = cursor.fetchall()
                
                # Get votes count for each option
                for option in options:
                    cursor.execute('''
                        SELECT COUNT(*) as vote_count
                        FROM user_votes
                        WHERE vote_option_id = %s
                    ''', (option['vote_option_id'],))
                    count_result = cursor.fetchone()
                    option['vote_count'] = count_result['vote_count'] if count_result else 0
                
                # Calculate total votes
                total_votes = sum(option['vote_count'] for option in options)
                
                # Check if current user has voted
                user_voted_options = []
                has_voted = False
                if 'loggedin' in session:
                    cursor.execute('''
                        SELECT vote_option_id
                        FROM user_votes
                        WHERE user_id = %s AND vote_id = %s
                    ''', (session['user_id'], vote['vote_id']))
                    voted_results = cursor.fetchall()
                    if voted_results:
                        has_voted = True
                        user_voted_options = [v['vote_option_id'] for v in voted_results]
                
                vote_data = {
                    'vote': vote,
                    'options': options,
                    'total_votes': total_votes,
                    'has_voted': has_voted,
                    'user_voted_options': user_voted_options
                }
        
        # 4. Get comments list
        cursor.execute('''
            SELECT 
                c.comment_id, c.content, c.created_at,
                u.user_id, u.username, u.profile_image
            FROM comments c
            JOIN users u ON c.user_id = u.user_id
            WHERE c.post_id = %s
            ORDER BY c.created_at DESC
        ''', (post_id,))
        comments = cursor.fetchall()
        
        # 5. Add likes count for each comment
        # for comment in comments:
        #     cursor.execute('''
        #         SELECT COUNT(*) as like_count
        #         FROM likes
        #         WHERE comment_id = %s
        #     ''', (comment['comment_id'],))
        #     like_result = cursor.fetchone()
        #     comment['likes'] = like_result['like_count'] if like_result else 0
        
        # 6. Get current user information (for comment section display)
        current_user = None
        if 'loggedin' in session:
            cursor.execute('''
                SELECT user_id, username, profile_image
                FROM users
                WHERE user_id = %s
            ''', (session['user_id'],))
            current_user = cursor.fetchone()
            
            # Check if current user is the post author
            is_author = (current_user['user_id'] == post['author_id']) if current_user else False
        else:
            is_author = False
    
    return render_template('post_detail.html',
                          post=post,
                          images=images,
                          vote_data=vote_data,
                          comments=comments,
                          current_user=current_user,
                          is_author=is_author,
                          is_following=is_following)

@app.route('/posts/image/<filename>')
def get_post_image(filename):
    """Serve post images."""
    upload_folder = os.path.join(app.static_folder, 'uploads', 'posts')
    return send_from_directory(upload_folder, filename)

@app.route('/create_posts', methods=['GET', 'POST'])
def create_posts():
    """Create new post page and functionality."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        poll_data_str = request.form.get('pollData')
        
        # Validate input
        if not title or not content:
            flash('Please fill in all required fields')
            
        if len(title) > 100:
            flash('Title cannot exceed 100 characters')
            return render_template('create.html')
            
        if len(title) < 1:
            flash('Title must be at least 1 characters')
            return render_template('create.html')
            
        if len(content) < 0:
            flash('Content must be at least 1 characters')
            return render_template('create.html')
            
        if len(content) > 5000:
            flash('Content cannot exceed 5000 characters')
            return render_template('create.html')
            
        try:
            cursor = db.get_db().cursor()
            
            # Default vote ID is 0 (no poll)
            vote_id = 0
            
            # Process poll data
            if poll_data_str and poll_data_str != 'null':
                print(f"Received poll data string: {poll_data_str}")
                
                try:
                    poll_data = json.loads(poll_data_str)
                    
                    if poll_data and isinstance(poll_data, dict):
                        print(f"Parsed poll data: {poll_data}")
                        
                        # Create poll
                        vote_title = poll_data.get('question', 'default').strip()
                        allow_multiple = 2 if poll_data.get('allowMultiple', False) else 1
                        options = poll_data.get('options', [])
                        
                        # Validate poll data
                        if not vote_title:
                            print("Poll title is empty, skipping poll creation")
                        elif len(options) < 2:
                            print(f"Insufficient poll options, current count: {len(options)}, skipping poll creation")
                        else:
                            print(f"Poll title: {vote_title}")
                            print(f"Allow multiple: {allow_multiple}")
                            print(f"Poll options: {options}")
                            
                            # 1. Insert poll main record
                            cursor.execute(
                                "INSERT INTO votes (title, vote_type, created_at, updated_at) VALUES (%s, %s, NOW(), NOW())",
                                (vote_title, allow_multiple)  # No longer using vote_option_id
                            )
                            vote_id = cursor.lastrowid
                            print(f"Created poll ID: {vote_id}")
                            
                            # Record option IDs for later update
                            option_ids = []
                            
                            # 2. Insert poll options
                            for option in options:
                                # Insert options with vote_id directly using the new table structure
                                if option.strip():  # Ensure option is not empty
                                    cursor.execute(
                                        "INSERT INTO vote_options (title, vote_id, created_at, updated_at) VALUES (%s, %s, NOW(), NOW())",
                                        (option.strip(), vote_id)
                                    )
                                    option_id = cursor.lastrowid
                                    option_ids.append(option_id)
                                    print(f"Added option '{option}', ID: {option_id}, linked to poll ID: {vote_id}")
                    else:
                        print("Poll data is empty or in incorrect format, skipping poll creation")
                except Exception as e:
                    print(f"Error processing poll data: {str(e)}")
                    # Continue processing, don't affect post creation
            
            # Ensure vote_id always has a value
            if vote_id is None:
                vote_id = 0
            
            # Insert post content
            sql = """INSERT INTO posts 
                    (user_id, vote_id, title, content, created_at, updated_at) 
                    VALUES (%s, %s, %s, %s, NOW(), NOW())"""
            values = (session['user_id'], vote_id, title, content)
            cursor.execute(sql, values)
            post_id = cursor.lastrowid
            
            # Process image uploads
            images = request.files.getlist('images[]')
            has_uploaded_images = images and images[0].filename
            
            # Ensure upload directory exists
            upload_folder = os.path.join(app.static_folder, 'uploads', 'posts')
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            # Store image paths for later database storage
            image_paths = []
            
            # Image compression settings
            MAX_SIZE = (1200, 1200)  # Maximum dimensions
            QUALITY = 85  # JPEG compression quality (0-100)
            
            # 如果用户没有上传图片，并且有投票数据，则自动生成图片
            if not has_uploaded_images and poll_data_str and poll_data_str != 'null':
                try:
                    # 直接从用户提交的数据中提取投票选项
                    poll_data = json.loads(poll_data_str)
                    if poll_data and isinstance(poll_data, dict):
                        options_text = poll_data.get('options', [])
                        if options_text:
                            print(f"直接从表单提取的选项: {options_text}")
                            
                            # 设置图片尺寸和背景颜色
                            width, height = 600, 800
                            bg_colors = [
                                (240, 248, 255),  # 爱丽丝蓝 Alice Blue
                                (245, 245, 245),  # 惠特烟 White Smoke
                                (255, 240, 245),  # 薰衣草红 Lavender Blush
                                (240, 255, 240),  # 蜜瓜 Honeydew
                                (255, 250, 240),  # 花卉白 Floral White
                                (240, 255, 255),  # 天蓝 Azure
                                (250, 235, 215),  # 古董白 Antique White
                                (245, 255, 250),  # 薄荷奶油 Mint Cream
                                (255, 245, 238),  # 海贝壳 Seashell
                                (248, 248, 255)   # 幽灵白 Ghost White
                            ]
                            bg_color = random.choice(bg_colors)
                            
                            # 创建图片和绘图对象
                            img = Image.new('RGB', (width, height), color=bg_color)
                            draw = ImageDraw.Draw(img)
                            
                            # 尝试加载字体，如果失败则使用默认字体
                            try:
                                # 尝试使用常见字体，如果不存在则使用默认
                                font_path = None
                                for path in [
                                    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',  # Linux
                                    '/usr/share/fonts/TTF/DejaVuSans.ttf',              # Linux
                                    'C:/Windows/Fonts/Arial.ttf',                       # Windows
                                    '/Library/Fonts/Arial.ttf'                          # Mac
                                ]:
                                    if os.path.exists(path):
                                        font_path = path
                                        break
                                        
                                # 如果找到字体，使用它；否则使用默认
                                title_font = ImageFont.truetype(font_path, 55) if font_path else ImageFont.load_default()
                                option_font = ImageFont.truetype(font_path, 38) if font_path else ImageFont.load_default()
                            except Exception as font_err:
                                print(f"加载字体出错: {str(font_err)}")
                                # 如果加载字体失败，使用默认字体
                                title_font = ImageFont.load_default()
                                option_font = ImageFont.load_default()
                            
                            # 文本自动换行函数
                            def wrap_text(text, font, max_width):
                                """将文本拆分成多行，确保每行宽度不超过max_width"""
                                # 先基于空格分词
                                words = text.split()
                                
                                # 如果文本没有空格或只有一个词但可能很长
                                if len(words) <= 1:
                                    # 处理没有空格的长文本（如连续数字）
                                    if not words:
                                        return []  # 空文本返回空列表
                                        
                                    word = words[0] if words else text
                                    return force_wrap_text(word, font, max_width)
                                
                                lines = []
                                current_line = words[0] if words else ""
                                
                                for word in words[1:]:
                                    # 如果单词特别长，先强制换行该单词
                                    try:
                                        word_width = draw.textlength(word, font=font)
                                    except AttributeError:
                                        word_width, _ = draw.textsize(word, font=font)
                                        
                                    # 如果单词宽度超过最大宽度，对单词进行强制换行处理
                                    if word_width > max_width:
                                        # 先添加当前行
                                        if current_line:
                                            lines.append(current_line)
                                            
                                        # 对超长单词进行强制换行
                                        wrapped_word_lines = force_wrap_text(word, font, max_width)
                                        lines.extend(wrapped_word_lines)
                                        current_line = ""
                                        continue
                                    
                                    # 尝试添加一个单词，检查是否超出宽度
                                    test_line = current_line + " " + word if current_line else word
                                    
                                    # 获取文本宽度
                                    try:
                                        # 新版PIL
                                        line_width = draw.textlength(test_line, font=font)
                                    except AttributeError:
                                        # 旧版PIL
                                        line_width, _ = draw.textsize(test_line, font=font)
                                        
                                    if line_width <= max_width:
                                        current_line = test_line
                                    else:
                                        lines.append(current_line)
                                        current_line = word
                                
                                if current_line:
                                    lines.append(current_line)  # 添加最后一行
                                return lines
                            
                            # 强制文本换行函数 - 处理无空格的长文本
                            def force_wrap_text(text, font, max_width):
                                """将无空格的长文本强制换行"""
                                lines = []
                                current_line = ""
                                
                                for char in text:
                                    test_line = current_line + char
                                    
                                    # 获取测试行的宽度
                                    try:
                                        line_width = draw.textlength(test_line, font=font)
                                    except AttributeError:
                                        line_width, _ = draw.textsize(test_line, font=font)
                                    
                                    if line_width <= max_width:
                                        current_line = test_line
                                    else:
                                        lines.append(current_line)
                                        current_line = char
                                
                                if current_line:
                                    lines.append(current_line)
                                
                                return lines
                                
                            # 选项截断函数
                            def truncate_text(text, font, max_width):
                                """截断文本，超出指定宽度时添加省略号"""
                                ellipsis = "..."
                                # 如果原始文本已经在最大宽度内，直接返回
                                try:
                                    text_width = draw.textlength(text, font=font)
                                except AttributeError:
                                    text_width, _ = draw.textsize(text, font=font)
                                    
                                if text_width <= max_width:
                                    return text
                                    
                                # 获取省略号宽度
                                try:
                                    ellipsis_width = draw.textlength(ellipsis, font=font)
                                except AttributeError:
                                    ellipsis_width, _ = draw.textsize(ellipsis, font=font)
                                
                                # 截断文本，保留一定的边界以添加省略号
                                result = ""
                                for char in text:
                                    result += char
                                    try:
                                        result_width = draw.textlength(result + ellipsis, font=font)
                                    except AttributeError:
                                        result_width, _ = draw.textsize(result + ellipsis, font=font)
                                        
                                    if result_width > max_width:
                                        # 回退一个字符，确保不超出
                                        result = result[:-1]
                                        break
                                
                                return result + ellipsis
                            
                            # 绘制多行文本函数
                            def draw_multiline_text(draw, text, font, fill, max_width, x, y):
                                """绘制自动换行的多行文本"""
                                lines = wrap_text(text, font, max_width)
                                line_height = font.getbbox("Ay")[3] * 1.2  # 估计行高
                                
                                current_y = y
                                for line in lines:
                                    # 计算每行的水平居中位置
                                    try:
                                        line_width = draw.textlength(line, font=font)
                                    except AttributeError:
                                        line_width, _ = draw.textsize(line, font=font)
                                    
                                    line_x = x + (max_width - line_width) / 2
                                    draw.text((line_x, current_y), line, fill=fill, font=font)
                                    current_y += line_height
                                
                                return current_y  # 返回绘制完成后的Y位置，用于后续内容定位
                            
                            # 绘制标题（自动换行）
                            title_text = title
                            title_margin = 60  # 标题两侧留白
                            title_max_width = width - 2 * title_margin
                            next_y = draw_multiline_text(draw, title_text, title_font, (0, 0, 0), 
                                              title_max_width, title_margin, 50)
                            
                            # 绘制投票选项（截断长文本）
                            option_margin = 50  # 选项两侧留白
                            option_max_width = width - 2 * option_margin
                            y_position = next_y + 30  # 选项起始Y位置（标题下方留空）
                            
                            for i, option in enumerate(options_text):
                                # 在选项前添加序号
                                option_text = f"{i+1}. {option}"
                                # 截断太长的选项文本
                                truncated_option = truncate_text(option_text, option_font, option_max_width)
                                # 获取文本宽度
                                try:
                                    option_width = draw.textlength(truncated_option, font=option_font)
                                except AttributeError:
                                    option_width, _ = draw.textsize(truncated_option, font=option_font)
                                    
                                option_x = (width - option_width) / 2
                                draw.text((option_x, y_position), truncated_option, fill=(50, 50, 50), font=option_font)
                                y_position += option_font.getbbox("Ay")[3] * 1.5  # 选项间距为1.5倍行高
                            
                            # 在底部添加网站信息
                            site_info = "My voice should be heard"
                            site_font = option_font
                            try:
                                site_width = draw.textlength(site_info, font=site_font)
                            except AttributeError:
                                site_width, _ = draw.textsize(site_info, font=site_font)
                                
                            site_x = (width - site_width) / 2
                            draw.text((site_x, height - 50), site_info, fill=(100, 100, 100), font=site_font)
                            
                            # 保存图片
                            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                            unique_filename = f"{timestamp}_generated_poll.jpg"
                            file_path = os.path.join(upload_folder, unique_filename)
                            img.save(file_path, format='JPEG', quality=QUALITY, optimize=True)
                            
                            # 添加到图片路径列表
                            image_paths.append(unique_filename)
                            print(f"成功生成投票图片: {unique_filename}")
                except Exception as gen_img_err:
                    print(f"生成投票图片出错: {str(gen_img_err)}")
                    # 继续执行，不阻止发布
            
            # 处理用户上传的图片
            if has_uploaded_images:
                for image in images:
                    if image and allowed_file(image.filename):
                        # Safely get filename and create unique filename
                        filename = secure_filename(image.filename)
                        # Add timestamp to prevent filename conflicts
                        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                        unique_filename = f"{timestamp}_{filename}"
                        
                        # Open the image using PIL
                        img = Image.open(image)
                        
                        # Fix orientation if needed
                        img = fix_image_orientation(img)
                        
                        # Compress the image
                        # Resize if larger than MAX_SIZE while maintaining aspect ratio
                        if img.width > MAX_SIZE[0] or img.height > MAX_SIZE[1]:
                            img.thumbnail(MAX_SIZE, Image.LANCZOS)
                        
                        # Convert to RGB if RGBA (remove alpha channel)
                        if img.mode == 'RGBA':
                            img = img.convert('RGB')
                        
                        # Determine format based on original file extension
                        original_extension = os.path.splitext(filename)[1].lower()
                        save_format = original_extension.replace('.', '').upper()
                        
                        # Default to JPEG for unknown formats
                        if save_format not in ['JPEG', 'JPG', 'PNG', 'GIF']:
                            save_format = 'JPEG'
                            unique_filename = f"{timestamp}_{os.path.splitext(filename)[0]}.jpg"
                        
                        # Save the compressed image
                        file_path = os.path.join(upload_folder, unique_filename)
                        
                        # Save with appropriate quality settings
                        if save_format in ['JPEG', 'JPG']:
                            # 把JPG统一处理为JPEG，避免格式识别问题
                            img.save(file_path, format='JPEG', quality=QUALITY, optimize=True)
                        elif save_format == 'PNG':
                            img.save(file_path, format=save_format, optimize=True)
                        else:
                            img.save(file_path, format=save_format)
                        
                        # Add path to list
                        image_paths.append(unique_filename)
            
            # 保存所有图片信息到数据库
            for unique_filename in image_paths:
                try:
                    cursor.execute(
                        "INSERT INTO post_images (post_id, image_path, created_at, updated_at) VALUES (%s, %s, NOW(), NOW())",
                        (post_id, unique_filename)
                    )
                    print(f"Saved image '{unique_filename}' to database, linked to post ID: {post_id}")
                except Exception as img_err:
                    print(f"Error saving image data: {str(img_err)}")
                    # Continue processing other images, don't break the flow
            
            db.get_db().commit()
            cursor.close()
            flash('Published successfully', 'success')
            
            # Redirect to home page or post detail page
            if session['role'] == 'visitor':
                return redirect(url_for('visitor_home'))
            elif session['role'] == 'helper':
                return redirect(url_for('helper_home'))
            else:
                return redirect(url_for('admin_home'))
            
        except Exception as e:
            print(f"Error creating post: {str(e)}")
            flash('Publication failed, please try again later')
            return render_template('create.html')
    
    return render_template('create.html')

@app.route('/vote/<int:post_id>', methods=['POST'])
def vote(post_id):
    """Process user votes."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    # Check if post and poll exist
    with db.get_cursor() as cursor:
        cursor.execute('SELECT vote_id FROM posts WHERE post_id = %s', (post_id,))
        post = cursor.fetchone()
        
        if not post or post['vote_id'] == 0:
            flash('Poll does not exist', 'danger')
            return redirect(url_for('view_post', post_id=post_id))
        
        vote_id = post['vote_id']
        
        # Check poll type (single or multiple choice)
        cursor.execute('SELECT vote_type FROM votes WHERE vote_id = %s', (vote_id,))
        vote = cursor.fetchone()
        
        if not vote:
            flash('Poll does not exist', 'danger')
            return redirect(url_for('view_post', post_id=post_id))
        
        # Get user-selected options
        if vote['vote_type'] == 2:  # Multiple choice
            options = request.form.getlist('options[]')
            if not options:
                flash('Please select at least one option', 'warning')
                return redirect(url_for('view_post', post_id=post_id))
            
            # Check if user has already voted
            cursor.execute(
                'SELECT 1 FROM user_votes WHERE user_id = %s AND vote_id = %s',
                (session['user_id'], vote_id)
            )
            if cursor.fetchone():
                # Delete user's previous votes
                cursor.execute(
                    'DELETE FROM user_votes WHERE user_id = %s AND vote_id = %s',
                    (session['user_id'], vote_id)
                )
            
            # Save user's multiple choice votes
            for option_id in options:
                cursor.execute(
                    'INSERT INTO user_votes (user_id, vote_id, option_id, created_at) VALUES (%s, %s, %s, NOW())',
                    (session['user_id'], vote_id, option_id)
                )
        else:  # Single choice
            option_id = request.form.get('option')
            if not option_id:
                flash('Please select an option', 'warning')
                return redirect(url_for('view_post', post_id=post_id))
            
            # Check if user has already voted
            cursor.execute(
                'SELECT 1 FROM user_votes WHERE user_id = %s AND vote_id = %s',
                (session['user_id'], vote_id)
            )
            if cursor.fetchone():
                # Update user's vote
                cursor.execute(
                    'UPDATE user_votes SET option_id = %s, created_at = NOW() WHERE user_id = %s AND vote_id = %s',
                    (option_id, session['user_id'], vote_id)
                )
            else:
                # Add new vote
                cursor.execute(
                    'INSERT INTO user_votes (user_id, vote_id, option_id, created_at) VALUES (%s, %s, %s, NOW())',
                    (session['user_id'], vote_id, option_id)
                )
        
        db.get_db().commit()
        flash('Vote successful', 'success')
        
    return redirect(url_for('view_post', post_id=post_id))

# Poll API
@app.route('/api/vote', methods=['POST'])
def api_vote():
    """API endpoint for handling vote requests, returns JSON data"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'Please log in first',
            'redirect': url_for('login')
        }), 401
    
    post_id = request.form.get('post_id')
    # Try different ways to get multiple poll data
    vote_options = request.form.getlist('options[]')
    if not vote_options:
        # If the above method fails, try other possible names
        vote_options = request.form.getlist('options')
    
    # Print form data for debugging
    print("Vote form data:", request.form)
    print("Multiple options:", vote_options)
    
    vote_option = request.form.get('option')  # Single poll vote
    
    if not post_id:
        return jsonify({'success': False, 'message': 'Parameter error'}), 400
    
    try:
        with db.get_cursor() as cursor:
            # 1. Get poll information
            cursor.execute('''
                SELECT v.vote_id, v.vote_type
                FROM posts p
                JOIN votes v ON p.vote_id = v.vote_id
                WHERE p.post_id = %s
            ''', (post_id,))
            vote_info = cursor.fetchone()
            
            if not vote_info:
                return jsonify({'success': False, 'message': 'Poll does not exist'}), 404
            
            vote_id = vote_info['vote_id']
            vote_type = vote_info['vote_type']
            
            # 2. Clear user's previous votes (in case of re-voting)
            cursor.execute('''
                DELETE FROM user_votes
                WHERE user_id = %s AND vote_id = %s
            ''', (session['user_id'], vote_id))
            
            # 3. Save new votes
            if vote_type == 2:  # Multiple choice
                if not vote_options:
                    return jsonify({'success': False, 'message': 'Please select at least one option'}), 400
                
                for option_id in vote_options:
                    cursor.execute('''
                        INSERT INTO user_votes (user_id, post_id, vote_id, vote_option_id, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, NOW(), NOW())
                    ''', (session['user_id'], post_id, vote_id, option_id))
            else:  # Single choice
                if not vote_option:
                    return jsonify({'success': False, 'message': 'Please select an option'}), 400
                
                cursor.execute('''
                    INSERT INTO user_votes (user_id, post_id, vote_id, vote_option_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, NOW(), NOW())
                ''', (session['user_id'], post_id, vote_id, vote_option))
            
            db.get_db().commit()
            
            # 4. Get latest poll results
            cursor.execute('''
                SELECT vo.vote_option_id, vo.title,
                      (SELECT COUNT(*) FROM user_votes uv WHERE uv.vote_option_id = vo.vote_option_id) as vote_count
                FROM vote_options vo
                WHERE vo.vote_id = %s
                ORDER BY vo.created_at
            ''', (vote_id,))
            options = cursor.fetchall()
            
            # Calculate total votes
            total_votes = sum(option['vote_count'] for option in options)
            
            # Get user's vote options
            cursor.execute('''
                SELECT vote_option_id
                FROM user_votes
                WHERE user_id = %s AND vote_id = %s
            ''', (session['user_id'], vote_id))
            user_votes = cursor.fetchall()
            user_voted_options = [vote['vote_option_id'] for vote in user_votes]
            
            # Calculate percentage for each option
            for option in options:
                option['percent'] = int((option['vote_count'] / total_votes * 100) if total_votes > 0 else 0)
            
            return jsonify({
                'success': True,
                'message': 'Vote successful',
                'data': {
                    'options': options,
                    'total_votes': total_votes,
                    'user_voted_options': user_voted_options
                }
            })
            
    except Exception as e:
        print(f"Vote failed: {str(e)}")
        return jsonify({'success': False, 'message': 'Vote failed, please try again later'}), 500

# Add comment API
@app.route('/api/comments', methods=['POST'])
def add_comment():
    """Add comment API endpoint, returns JSON data"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'Please log in first',
            'redirect': url_for('login')
        }), 401
    
    post_id = request.form.get('post_id')
    content = request.form.get('content', '').strip()
    
    if not post_id or not content:
        return jsonify({'success': False, 'message': 'Parameter error'}), 400
    
    try:
        with db.get_cursor() as cursor:
            # 1. Insert comment
            cursor.execute('''
                INSERT INTO comments (post_id, user_id, content, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
            ''', (post_id, session['user_id'], content))
            db.get_db().commit()
            
            # 2. Get new comment ID
            comment_id = cursor.lastrowid
            
            # 3. Get comment details
            cursor.execute('''
                SELECT 
                    c.comment_id, c.content, c.created_at, c.user_id,
                    u.user_id, u.username, u.profile_image
                FROM comments c
                JOIN users u ON c.user_id = u.user_id
                WHERE c.comment_id = %s
            ''', (comment_id,))
            comment = cursor.fetchone()
            
            if comment:
                # Format date time
                comment['created_at_formatted'] = comment['created_at'].strftime('%Y-%m-%d %H:%M')
                comment['likes'] = 0  # Default likes for new comment is 0
            
            return jsonify({
                'success': True,
                'message': 'Comment successful',
                'data': comment
            })
            
    except Exception as e:
        print(f"Comment failed: {str(e)}")
        return jsonify({'success': False, 'message': 'Comment failed, please try again later'}), 500

# Comment like API
@app.route('/api/comments/like', methods=['POST'])
def like_comment():
    """Comment like API endpoint, returns JSON data"""
    return jsonify({
        'success': False,
        'message': 'Comment like function not yet implemented, the current likes table only supports post likes'
    }), 501

# Delete comment API
@app.route('/api/comments/delete', methods=['POST'])
def delete_comment():
    """Delete comment API endpoint, returns JSON data"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'Please log in first',
            'redirect': url_for('login')
        }), 401
    
    comment_id = request.form.get('comment_id')
    
    if not comment_id:
        return jsonify({'success': False, 'message': 'Parameter error'}), 400
    
    try:
        with db.get_cursor() as cursor:
            # Verify comment ownership
            cursor.execute('''
                SELECT user_id FROM comments
                WHERE comment_id = %s
            ''', (comment_id,))
            comment = cursor.fetchone()
            
            if not comment:
                return jsonify({'success': False, 'message': 'Comment does not exist'}), 404
                
            if comment['user_id'] != session['user_id']:
                return jsonify({'success': False, 'message': 'No permission to delete this comment'}), 403
            
            # Delete comment
            cursor.execute('''
                DELETE FROM comments
                WHERE comment_id = %s
            ''', (comment_id,))
            
            db.get_db().commit()
            
            return jsonify({
                'success': True,
                'message': 'Comment deleted'
            })
            
    except Exception as e:
        print(f"Delete comment failed: {str(e)}")
        return jsonify({'success': False, 'message': 'Delete failed, please try again later'}), 500

# Follow/unfollow API
@app.route('/api/follow', methods=['POST'])
def api_follow():
    """API endpoint for handling follow/unfollow, returns JSON data"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'Please log in first',
            'redirect': url_for('login')
        }), 401
    
    follower_id = session['user_id']  # Current logged-in user ID (follower)
    user_id = request.form.get('user_id')  # Target user ID to follow
    
    if not user_id:
        return jsonify({'success': False, 'message': 'Parameter error'}), 400
    
    # Cannot follow yourself
    if str(follower_id) == str(user_id):
        return jsonify({'success': False, 'message': 'Cannot follow yourself'}), 400
    
    try:
        with db.get_cursor() as cursor:
            # Check if already following
            cursor.execute('''
                SELECT 1 FROM follows
                WHERE follower_id = %s AND user_id = %s
            ''', (follower_id, user_id))
            already_followed = cursor.fetchone() is not None
            
            if already_followed:
                # If already following, unfollow
                cursor.execute('''
                    DELETE FROM follows
                    WHERE follower_id = %s AND user_id = %s
                ''', (follower_id, user_id))
                is_following = False
                message = 'Unfollowed'
            else:
                # If not following, add follow
                cursor.execute('''
                    INSERT INTO follows (user_id, follower_id, created_at, updated_at)
                    VALUES (%s, %s, NOW(), NOW())
                ''', (user_id, follower_id))
                is_following = True
                message = 'Follow successful'
            
            db.get_db().commit()
            
            # Get follower count for target user
            cursor.execute('''
                SELECT COUNT(*) as followers_count 
                FROM follows 
                WHERE user_id = %s
            ''', (user_id,))
            result = cursor.fetchone()
            followers_count = result['followers_count'] if result else 0
            
            return jsonify({
                'success': True,
                'message': message,
                'data': {
                    'is_following': is_following,
                    'followers_count': followers_count,
                    'user_id': user_id
                }
            })
            
    except Exception as e:
        print(f"Follow operation failed: {str(e)}")
        return jsonify({'success': False, 'message': 'Operation failed, please try again later'}), 500

# Get following users list API
@app.route('/api/following', methods=['GET'])
def api_get_following():
    """API endpoint to get current user's following list, returns JSON data"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'Please log in first',
            'redirect': url_for('login')
        }), 401
    
    follower_id = session['user_id']
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    offset = (page - 1) * per_page
    
    try:
        with db.get_cursor() as cursor:
            # Get total following count
            cursor.execute('''
                SELECT COUNT(*) as total_count
                FROM follows
                WHERE follower_id = %s
            ''', (follower_id,))
            result = cursor.fetchone()
            total_count = result['total_count'] if result else 0
            
            # Get following users list
            cursor.execute('''
                SELECT u.user_id, u.username, u.profile_image, f.created_at as followed_at
                FROM follows f
                JOIN users u ON f.user_id = u.user_id
                WHERE f.follower_id = %s
                ORDER BY f.created_at DESC
                LIMIT %s OFFSET %s
            ''', (follower_id, per_page, offset))
            following = cursor.fetchall()
            
            # Format data
            following_list = []
            for follow in following:
                following_list.append({
                    'user_id': follow['user_id'],
                    'username': follow['username'],
                    'profile_image': follow['profile_image'],
                    'followed_at': follow['followed_at'].strftime('%Y-%m-%d %H:%M')
                })
            
            return jsonify({
                'success': True,
                'data': {
                    'following': following_list,
                    'total_count': total_count,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': (total_count + per_page - 1) // per_page
                }
            })
            
    except Exception as e:
        print(f"Get following list failed: {str(e)}")
        return jsonify({'success': False, 'message': 'Data retrieval failed, please try again later'}), 500

# Get followers list API
@app.route('/api/followers', methods=['GET'])
def api_get_followers():
    """API endpoint to get current user's followers list, returns JSON data"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'Please log in first',
            'redirect': url_for('login')
        }), 401
    
    user_id = session['user_id']
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    offset = (page - 1) * per_page
    
    try:
        with db.get_cursor() as cursor:
            # Get total followers count
            cursor.execute('''
                SELECT COUNT(*) as total_count
                FROM follows
                WHERE user_id = %s
            ''', (user_id,))
            result = cursor.fetchone()
            total_count = result['total_count'] if result else 0
            
            # Get followers list and check if current user follows them back
            cursor.execute('''
                SELECT 
                    u.user_id, u.username, u.profile_image, f.created_at as followed_at,
                    (SELECT 1 FROM follows WHERE follower_id = %s AND user_id = u.user_id) as is_following_back
                FROM follows f
                JOIN users u ON f.follower_id = u.user_id
                WHERE f.user_id = %s
                ORDER BY f.created_at DESC
                LIMIT %s OFFSET %s
            ''', (user_id, user_id, per_page, offset))
            followers = cursor.fetchall()
            
            # Format data
            followers_list = []
            for follower in followers:
                followers_list.append({
                    'user_id': follower['user_id'],
                    'username': follower['username'],
                    'profile_image': follower['profile_image'],
                    'followed_at': follower['followed_at'].strftime('%Y-%m-%d %H:%M'),
                    'is_following_back': follower['is_following_back'] is not None
                })
            
            return jsonify({
                'success': True,
                'data': {
                    'followers': followers_list,
                    'total_count': total_count,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': (total_count + per_page - 1) // per_page
                }
            })
            
    except Exception as e:
        print(f"Get followers list failed: {str(e)}")
        return jsonify({'success': False, 'message': 'Data retrieval failed, please try again later'}), 500

# Check follow status API
@app.route('/api/check_follow/<int:target_user_id>', methods=['GET'])
def api_check_follow(target_user_id):
    """API endpoint to check if current user follows specific user, returns JSON data"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'Please log in first',
            'redirect': url_for('login')
        }), 401
    
    follower_id = session['user_id']
    
    try:
        with db.get_cursor() as cursor:
            # Check if following
            cursor.execute('''
                SELECT 1 FROM follows
                WHERE follower_id = %s AND user_id = %s
            ''', (follower_id, target_user_id))
            is_following = cursor.fetchone() is not None
            
            # Get follower count for target user
            cursor.execute('''
                SELECT COUNT(*) as followers_count 
                FROM follows 
                WHERE user_id = %s
            ''', (target_user_id,))
            result = cursor.fetchone()
            followers_count = result['followers_count'] if result else 0
            
            # Get following count for target user
            cursor.execute('''
                SELECT COUNT(*) as following_count 
                FROM follows 
                WHERE follower_id = %s
            ''', (target_user_id,))
            result = cursor.fetchone()
            following_count = result['following_count'] if result else 0
            
            return jsonify({
                'success': True,
                'data': {
                    'is_following': is_following,
                    'followers_count': followers_count,
                    'following_count': following_count,
                    'user_id': target_user_id
                }
            })
            
    except Exception as e:
        print(f"Check follow status failed: {str(e)}")
        return jsonify({'success': False, 'message': 'Data retrieval failed, please try again later'}), 500

@app.route('/api/like/<int:post_id>', methods=['POST'])
def like_post(post_id):
    """Like a post.
    
    Args:
        post_id: The ID of the post to like.
        
    Returns:
        JSON response indicating success or failure.
    """
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'You must be logged in to like posts.'
        }), 401
    
    user_id = session.get('user_id')
    
    with db.get_cursor() as cursor:
        # Check if the post exists
        cursor.execute('SELECT 1 FROM posts WHERE post_id = %s', (post_id,))
        if not cursor.fetchone():
            return jsonify({
                'success': False,
                'message': 'Post not found.'
            }), 404
        
        # Check if the user has already liked this post
        cursor.execute(
            'SELECT 1 FROM likes WHERE post_id = %s AND user_id = %s',
            (post_id, user_id)
        )
        if cursor.fetchone():
            return jsonify({
                'success': True,
                'message': 'You have already liked this post.'
            })
        
        # Add the like
        cursor.execute(
            'INSERT INTO likes (post_id, user_id) VALUES (%s, %s)',
            (post_id, user_id)
        )
        db.get_db().commit()
        
        # Get the updated like count
        cursor.execute('SELECT COUNT(*) as count FROM likes WHERE post_id = %s', (post_id,))
        like_count = cursor.fetchone()['count']
        
        return jsonify({
            'success': True,
            'message': 'Post liked successfully.',
            'likes': like_count
        })

@app.route('/api/unlike/<int:post_id>', methods=['POST'])
def unlike_post(post_id):
    """Unlike a post.
    
    Args:
        post_id: The ID of the post to unlike.
        
    Returns:
        JSON response indicating success or failure.
    """
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'You must be logged in to unlike posts.'
        }), 401
    
    user_id = session.get('user_id')
    
    with db.get_cursor() as cursor:
        # Check if the post exists
        cursor.execute('SELECT 1 FROM posts WHERE post_id = %s', (post_id,))
        if not cursor.fetchone():
            return jsonify({
                'success': False,
                'message': 'Post not found.'
            }), 404
        
        # Check if the user has liked this post
        cursor.execute(
            'SELECT 1 FROM likes WHERE post_id = %s AND user_id = %s',
            (post_id, user_id)
        )
        if not cursor.fetchone():
            return jsonify({
                'success': True,
                'message': 'You have not liked this post.'
            })
        
        # Remove the like
        cursor.execute(
            'DELETE FROM likes WHERE post_id = %s AND user_id = %s',
            (post_id, user_id)
        )
        db.get_db().commit()
        
        # Get the updated like count
        cursor.execute('SELECT COUNT(*) as count FROM likes WHERE post_id = %s', (post_id,))
        like_count = cursor.fetchone()['count']
        
        return jsonify({
            'success': True,
            'message': 'Post unliked successfully.',
            'likes': like_count
        })