from loginapp import app
from loginapp import db
from flask import flash, redirect, render_template, request, send_from_directory, session, url_for
from flask_bcrypt import Bcrypt
import re
from PIL import Image, ExifTags
import os
import time
from datetime import datetime
from werkzeug.utils import secure_filename

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
        home_endpoint = 'list_posts'
    
    return url_for(home_endpoint)

@app.route('/')
def root():
    if 'loggedin' in session:
        return redirect(user_home_url())
    else:
        return redirect(url_for('list_posts'))

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


@app.route('/messages')
def messages():

    return render_template('messages.html')


@app.route('/me')
def me():

    return render_template('me.html')


@app.route('/subscription')
def subscription():

    return render_template('subscription.html')


@app.route('/posts')
def list_posts():
    """帖子列表页面 - 小红书风格。"""
    # 获取第一页数据
    page = 1
    per_page = 12  # 每页显示12条帖子
    
    with db.get_cursor() as cursor:
        # 查询帖子基本信息、作者信息和图片数量，修复vote_id可能为NULL的问题
        cursor.execute('''
            SELECT 
                p.post_id, 
                p.title, 
                p.content, 
                p.created_at, 
                IFNULL(p.vote_id, 0) as vote_id,
                u.username,
                u.profile_image,
                (SELECT COUNT(*) FROM post_images pi WHERE pi.post_id = p.post_id) as image_count,
                (SELECT image_path FROM post_images pi WHERE pi.post_id = p.post_id ORDER BY pi.created_at LIMIT 1) as first_image,
                (SELECT COUNT(*) FROM user_votes uv WHERE uv.vote_id = p.vote_id) as likes
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            ORDER BY p.created_at DESC
            LIMIT %s OFFSET %s
        ''', (per_page, (page - 1) * per_page))
        posts = cursor.fetchall()
        
        # 打印帖子数量和第一个帖子的信息，用于调试
        print(f"获取到 {len(posts)} 条帖子")
        if posts:
            print(f"第一个帖子: {posts[0]['title']}, ID: {posts[0]['post_id']}")
        
        # 获取总帖子数
        cursor.execute('SELECT COUNT(*) AS total FROM posts')
        total_posts = cursor.fetchone()['total']
        print(f"数据库中共有 {total_posts} 条帖子")
        
        # 添加has_vote标志，用于在UI上显示投票标记
        for post in posts:
            post['has_vote'] = post['vote_id'] > 0
            # 确保likes字段不为None
            if post['likes'] is None:
                post['likes'] = 0
    
    return render_template('list.html', posts=posts, total_posts=total_posts)

@app.route('/api/posts')
def api_posts():
    """API接口 - 用于滑动加载更多帖子"""
    # 获取页码参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    
    # 限制每页最大数量为24
    if per_page > 24:
        per_page = 24
    
    with db.get_cursor() as cursor:
        # 查询帖子
        cursor.execute('''
            SELECT 
                p.post_id, 
                p.title, 
                p.content, 
                p.created_at, 
                IFNULL(p.vote_id, 0) as vote_id,
                u.username,
                u.profile_image,
                (SELECT COUNT(*) FROM post_images pi WHERE pi.post_id = p.post_id) as image_count,
                (SELECT image_path FROM post_images pi WHERE pi.post_id = p.post_id ORDER BY pi.created_at LIMIT 1) as first_image,
                (SELECT COUNT(*) FROM user_votes uv WHERE uv.vote_id = p.vote_id) as likes
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            ORDER BY p.created_at DESC
            LIMIT %s OFFSET %s
        ''', (per_page, (page - 1) * per_page))
        posts = cursor.fetchall()
        
        # 添加has_vote标志
        for post in posts:
            post['has_vote'] = post['vote_id'] > 0
            # 确保likes字段不为None
            if post['likes'] is None:
                post['likes'] = 0
            
            # 处理日期格式以便JSON序列化
            if 'created_at' in post and post['created_at']:
                post['created_at'] = post['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    
    # 返回JSON数据
    result = {
        'posts': list(posts),
        'page': page,
        'per_page': per_page,
        'has_more': len(posts) == per_page  # 如果返回的帖子数等于请求的数量，则可能还有更多
    }
    
    from flask import jsonify
    return jsonify(result)

@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    """帖子详情页面。"""
    # 不再需要登录验证，任何人都可以查看帖子详情
    
    with db.get_cursor() as cursor:
        # 获取帖子基本信息
        cursor.execute('''
            SELECT p.post_id, p.title, p.content, p.created_at, p.vote_id,
                   u.username, u.profile_image
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.post_id = %s
        ''', (post_id,))
        post = cursor.fetchone()
        
        if not post:
            flash('帖子不存在', 'danger')
            return redirect(url_for('list_posts'))
        
        # 获取帖子图片
        cursor.execute('''
            SELECT image_path
            FROM post_images
            WHERE post_id = %s
            ORDER BY created_at
        ''', (post_id,))
        images = cursor.fetchall()
        
        # 获取投票数据
        vote_data = None
        if post['vote_id'] > 0:
            cursor.execute('''
                SELECT v.vote_id, v.title as vote_title, v.vote_type
                FROM votes v
                WHERE v.vote_id = %s
            ''', (post['vote_id'],))
            vote = cursor.fetchone()
            
            if vote:
                # 获取投票选项，并计算每个选项的票数
                cursor.execute('''
                    SELECT vo.option_id, vo.title,
                           (SELECT COUNT(*) FROM user_votes uv WHERE uv.option_id = vo.option_id) as vote_count
                    FROM vote_options vo
                    WHERE vo.vote_id = %s
                    ORDER BY vo.created_at
                ''', (vote['vote_id'],))
                options = cursor.fetchall()
                
                # 计算总票数
                total_votes = 0
                for option in options:
                    total_votes += option['vote_count']
                
                # 检查当前用户是否已投票
                user_voted_options = []
                if 'loggedin' in session:
                    cursor.execute('''
                        SELECT option_id
                        FROM user_votes
                        WHERE user_id = %s AND vote_id = %s
                    ''', (session['user_id'], vote['vote_id']))
                    user_votes = cursor.fetchall()
                    user_voted_options = [vote['option_id'] for vote in user_votes] if user_votes else []
                
                vote_data = {
                    'vote': vote,
                    'options': options,
                    'total_votes': total_votes,
                    'user_voted_options': user_voted_options,
                    'has_voted': len(user_voted_options) > 0
                }
    
    return render_template('post_detail.html', post=post, images=images, vote_data=vote_data)

@app.route('/posts/image/<filename>')
def get_post_image(filename):
    """提供帖子图片。"""
    upload_folder = os.path.join(app.static_folder, 'uploads', 'posts')
    return send_from_directory(upload_folder, filename)

@app.route('/create_posts', methods=['GET', 'POST'])
def create_posts():
    """创建新帖子页面及功能。"""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        poll_data_str = request.form.get('pollData')
        
        # 验证输入
        if not title or not content:
            flash('请填写所有必填字段')
            return render_template('create.html')
            
        if len(title) > 100:
            flash('标题不能超过100个字符')
            return render_template('create.html')
            
        if len(title) < 2:
            flash('标题至少需要2个字符')
            return render_template('create.html')
            
        if len(content) < 10:
            flash('内容至少需要10个字符')
            return render_template('create.html')
            
        if len(content) > 5000:
            flash('内容不能超过5000个字符')
            return render_template('create.html')
            
        try:
            cursor = db.get_db().cursor()
            
            # 默认投票ID为0（没有投票）
            vote_id = 0
            
            # 处理投票数据
            if poll_data_str and poll_data_str != 'null':
                import json
                print(f"接收到的投票数据字符串: {poll_data_str}")
                
                try:
                    poll_data = json.loads(poll_data_str)
                    
                    if poll_data and isinstance(poll_data, dict):
                        print(f"解析后的投票数据: {poll_data}")
                        
                        # 创建投票
                        vote_title = poll_data.get('question', '').strip()
                        allow_multiple = 2 if poll_data.get('allowMultiple', False) else 1
                        options = poll_data.get('options', [])
                        
                        # 验证投票数据
                        if not vote_title:
                            print("投票标题为空，跳过投票创建")
                        elif len(options) < 2:
                            print(f"投票选项数量不足，当前数量: {len(options)}，跳过投票创建")
                        else:
                            print(f"投票标题: {vote_title}")
                            print(f"是否多选: {allow_multiple}")
                            print(f"投票选项: {options}")
                            
                            # 1. 插入投票主表记录
                            cursor.execute(
                                "INSERT INTO votes (title, vote_type, created_at, updated_at) VALUES (%s, %s, NOW(), NOW())",
                                (vote_title, allow_multiple)  # 不再使用vote_option_id
                            )
                            vote_id = cursor.lastrowid
                            print(f"已创建投票ID: {vote_id}")
                            
                            # 记录选项ID，用于后续更新
                            option_ids = []
                            
                            # 2. 插入投票选项
                            for option in options:
                                # 使用新的表结构直接插入带vote_id的选项
                                if option.strip():  # 确保选项不为空
                                    cursor.execute(
                                        "INSERT INTO vote_options (title, vote_id, created_at, updated_at) VALUES (%s, %s, NOW(), NOW())",
                                        (option.strip(), vote_id)
                                    )
                                    option_id = cursor.lastrowid
                                    option_ids.append(option_id)
                                    print(f"已添加选项 '{option}', ID: {option_id}, 关联投票ID: {vote_id}")
                            
                            # 不再需要更新投票表的vote_option_id字段
                            # if option_ids:
                            #     cursor.execute(
                            #         "UPDATE votes SET vote_option_id = %s WHERE vote_id = %s",
                            #         (option_ids[0], vote_id)
                            #     )
                            #     print(f"已更新投票表的vote_option_id为: {option_ids[0]}")
                    else:
                        print("投票数据为空或格式不正确，跳过投票创建")
                except Exception as e:
                    print(f"处理投票数据时出错: {str(e)}")
                    # 继续处理，不影响帖子的创建
            
            # 此处确保vote_id始终有值
            if vote_id is None:
                vote_id = 0
            
            # 插入文章内容
            sql = """INSERT INTO posts 
                    (user_id, vote_id, title, content, created_at, updated_at) 
                    VALUES (%s, %s, %s, %s, NOW(), NOW())"""
            values = (session['user_id'], vote_id, title, content)
            cursor.execute(sql, values)
            post_id = cursor.lastrowid
            
            # 处理图片上传
            images = request.files.getlist('images[]')
            if images and images[0].filename:
                # 确保上传目录存在
                upload_folder = os.path.join(app.static_folder, 'uploads', 'posts')
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)
                
                # 存储图片路径，用于后续保存到数据库
                image_paths = []
                
                for image in images:
                    if image and allowed_file(image.filename):
                        # 安全地获取文件名并创建唯一文件名
                        filename = secure_filename(image.filename)
                        # 添加时间戳防止文件名冲突
                        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                        unique_filename = f"{timestamp}_{filename}"
                        
                        # 保存图片
                        file_path = os.path.join(upload_folder, unique_filename)
                        image.save(file_path)
                        
                        # 将路径添加到列表
                        image_paths.append(unique_filename)
                        
                        # 将图片信息保存到数据库
                        try:
                            cursor.execute(
                                "INSERT INTO post_images (post_id, image_path, created_at, updated_at) VALUES (%s, %s, NOW(), NOW())",
                                (post_id, unique_filename)
                            )
                            print(f"已保存图片路径 '{unique_filename}' 到数据库，关联帖子ID: {post_id}")
                        except Exception as img_err:
                            print(f"保存图片数据时出错: {str(img_err)}")
                            # 继续处理其他图片，不中断流程
            
            db.get_db().commit()
            cursor.close()
            flash('发布成功', 'success')
            
            # 重定向到首页或文章详情页
            if session['role'] == 'visitor':
                return redirect(url_for('visitor_home'))
            elif session['role'] == 'helper':
                return redirect(url_for('helper_home'))
            else:
                return redirect(url_for('admin_home'))
            
        except Exception as e:
            print(f"创建帖子时出错: {str(e)}")
            flash('发布失败，请稍后重试')
            return render_template('create.html')
    
    return render_template('create.html')

@app.route('/vote/<int:post_id>', methods=['POST'])
def vote(post_id):
    """处理用户投票。"""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    # 检查帖子和投票是否存在
    with db.get_cursor() as cursor:
        cursor.execute('SELECT vote_id FROM posts WHERE post_id = %s', (post_id,))
        post = cursor.fetchone()
        
        if not post or post['vote_id'] == 0:
            flash('投票不存在', 'danger')
            return redirect(url_for('view_post', post_id=post_id))
        
        vote_id = post['vote_id']
        
        # 检查投票类型（单选或多选）
        cursor.execute('SELECT vote_type FROM votes WHERE vote_id = %s', (vote_id,))
        vote = cursor.fetchone()
        
        if not vote:
            flash('投票不存在', 'danger')
            return redirect(url_for('view_post', post_id=post_id))
        
        # 获取用户选择的选项
        if vote['vote_type'] == 2:  # 多选
            options = request.form.getlist('options[]')
            if not options:
                flash('请至少选择一个选项', 'warning')
                return redirect(url_for('view_post', post_id=post_id))
            
            # 检查用户是否已经投过票
            cursor.execute(
                'SELECT 1 FROM user_votes WHERE user_id = %s AND vote_id = %s',
                (session['user_id'], vote_id)
            )
            if cursor.fetchone():
                # 删除用户之前的投票
                cursor.execute(
                    'DELETE FROM user_votes WHERE user_id = %s AND vote_id = %s',
                    (session['user_id'], vote_id)
                )
            
            # 保存用户的多选投票
            for option_id in options:
                cursor.execute(
                    'INSERT INTO user_votes (user_id, vote_id, option_id, created_at) VALUES (%s, %s, %s, NOW())',
                    (session['user_id'], vote_id, option_id)
                )
        else:  # 单选
            option_id = request.form.get('option')
            if not option_id:
                flash('请选择一个选项', 'warning')
                return redirect(url_for('view_post', post_id=post_id))
            
            # 检查用户是否已经投过票
            cursor.execute(
                'SELECT 1 FROM user_votes WHERE user_id = %s AND vote_id = %s',
                (session['user_id'], vote_id)
            )
            if cursor.fetchone():
                # 更新用户的投票
                cursor.execute(
                    'UPDATE user_votes SET option_id = %s, created_at = NOW() WHERE user_id = %s AND vote_id = %s',
                    (option_id, session['user_id'], vote_id)
                )
            else:
                # 添加新的投票
                cursor.execute(
                    'INSERT INTO user_votes (user_id, vote_id, option_id, created_at) VALUES (%s, %s, %s, NOW())',
                    (session['user_id'], vote_id, option_id)
                )
        
        db.get_db().commit()
        flash('投票成功', 'success')
        
    return redirect(url_for('view_post', post_id=post_id))