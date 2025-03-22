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
from flask import jsonify

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

    # 指定上传文件夹
    PROFILE_UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads', 'profiles')
    # 确保目录存在
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
        
        flash('头像已删除', 'success')
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
            image.save(os.path.join(PROFILE_UPLOAD_FOLDER, filename))
            
            # 更新数据库
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

            flash('头像上传成功', 'success')
            
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

    return render_template('me.html', profile=profile)


@app.route('/subscription')
def subscription():

    return render_template('subscription.html')


@app.route('/list_posts')
def list_posts():
    """帖子列表API - 返回JSON格式的帖子数据，支持分页。"""
    # 获取页码和每页显示数量参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    
    # 限制每页最大数量为24
    if per_page > 24:
        per_page = 24
    
    with db.get_cursor() as cursor:
        # 查询帖子基本信息、作者信息和图片等
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
            LEFT JOIN users u ON p.user_id = u.user_id
            ORDER BY p.created_at DESC
            LIMIT %s OFFSET %s
        ''', (per_page, (page - 1) * per_page))
        posts = cursor.fetchall()
        
        # 打印帖子数量和第一个帖子的信息，用于调试
        print(f"获取到 {len(posts)} 条帖子")
        if posts:
            print(f"第一个帖子: {posts[0]['content']}, ID: {posts[0]['post_id']}")
        
        # 获取总帖子数
        cursor.execute('SELECT COUNT(*) AS total FROM posts')
        total_posts = cursor.fetchone()['total']
        print(f"数据库中共有 {total_posts} 条帖子")
        
        # 处理返回的数据，添加额外信息
        for post in posts:
            # 添加has_vote标志
            post['has_vote'] = post['vote_id'] > 0
            
            # 确保likes字段不为None
            if post['likes'] is None:
                post['likes'] = 0
                
            # 设置图片URL
            if post['first_image']:
                post['image_url'] = url_for('get_post_image', filename=post['first_image'])
            else:
                post['image_url'] = url_for('static', filename='img/default-post.jpg')
                
            # 设置用户头像URL
            if post['profile_image']:
                post['user_avatar'] = url_for('static', filename=f'uploads/profiles/{post["profile_image"]}')
            else:
                post['user_avatar'] = url_for('static', filename='img/default-avatar.jpg')
                
            # 处理日期格式以便JSON序列化
            if 'created_at' in post and post['created_at']:
                post['created_at'] = post['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    
    # 返回JSON格式响应
    result = {
        'posts': list(posts),
        'page': page,
        'per_page': per_page,
        'total': total_posts,
        'has_more': len(posts) == per_page  # 如果返回的帖子数等于请求的数量，则可能还有更多
    }
    
    return jsonify(result)

@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    """帖子详情页面。"""
    with db.get_cursor() as cursor:
        # 获取帖子基本信息和作者信息
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
            flash('帖子不存在', 'danger')
            return redirect(url_for('list_posts'))
        
        # 检查当前用户是否已关注作者
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
        
        # 获取其他必要数据（图片、投票、评论等）
        cursor.execute('''
            SELECT image_id, image_path
            FROM post_images
            WHERE post_id = %s
            ORDER BY created_at
        ''', (post_id,))
        images = cursor.fetchall()
        
        # 3. 获取投票信息
        vote_data = None
        if post.get('vote_id'):
            cursor.execute('''
                SELECT vote_id, title as vote_title, vote_type
                FROM votes
                WHERE vote_id = %s
            ''', (post['vote_id'],))
            vote = cursor.fetchone()
            
            if vote:
                # 获取投票选项
                cursor.execute('''
                    SELECT vote_option_id, title
                    FROM vote_options
                    WHERE vote_id = %s
                    ORDER BY created_at
                ''', (vote['vote_id'],))
                options = cursor.fetchall()
                
                # 获取每个选项的投票数
                for option in options:
                    cursor.execute('''
                        SELECT COUNT(*) as vote_count
                        FROM user_votes
                        WHERE vote_option_id = %s
                    ''', (option['vote_option_id'],))
                    count_result = cursor.fetchone()
                    option['vote_count'] = count_result['vote_count'] if count_result else 0
                
                # 计算总投票数
                total_votes = sum(option['vote_count'] for option in options)
                
                # 检查当前用户是否已投票
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
        
        # 4. 获取评论列表
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
        
        # 5. 为每条评论添加点赞数
        # for comment in comments:
        #     cursor.execute('''
        #         SELECT COUNT(*) as like_count
        #         FROM likes
        #         WHERE comment_id = %s
        #     ''', (comment['comment_id'],))
        #     like_result = cursor.fetchone()
        #     comment['likes'] = like_result['like_count'] if like_result else 0
        
        # 6. 获取当前用户信息（用于评论区显示）
        current_user = None
        if 'loggedin' in session:
            cursor.execute('''
                SELECT user_id, username, profile_image
                FROM users
                WHERE user_id = %s
            ''', (session['user_id'],))
            current_user = cursor.fetchone()
            
            # 检查当前用户是否是帖子作者
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

# 投票接口
@app.route('/api/vote', methods=['POST'])
def api_vote():
    """处理投票请求的API接口，返回JSON格式数据"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': '请先登录',
            'redirect': url_for('login')
        }), 401
    
    post_id = request.form.get('post_id')
    # 尝试多种方式获取多选投票数据
    vote_options = request.form.getlist('options[]')
    if not vote_options:
        # 如果上面的方式失败，尝试其他可能的名称
        vote_options = request.form.getlist('options')
    
    # 打印表单数据进行调试
    print("投票表单数据:", request.form)
    print("多选选项:", vote_options)
    
    vote_option = request.form.get('option')  # 单选投票
    
    if not post_id:
        return jsonify({'success': False, 'message': '参数错误'}), 400
    
    try:
        with db.get_cursor() as cursor:
            # 1. 获取投票信息
            cursor.execute('''
                SELECT v.vote_id, v.vote_type
                FROM posts p
                JOIN votes v ON p.vote_id = v.vote_id
                WHERE p.post_id = %s
            ''', (post_id,))
            vote_info = cursor.fetchone()
            
            if not vote_info:
                return jsonify({'success': False, 'message': '投票不存在'}), 404
            
            vote_id = vote_info['vote_id']
            vote_type = vote_info['vote_type']
            
            # 2. 清除用户之前的投票（重新投票的情况）
            cursor.execute('''
                DELETE FROM user_votes
                WHERE user_id = %s AND vote_id = %s
            ''', (session['user_id'], vote_id))
            
            # 3. 保存新的投票
            if vote_type == 2:  # 多选
                if not vote_options:
                    return jsonify({'success': False, 'message': '请至少选择一个选项'}), 400
                
                for option_id in vote_options:
                    cursor.execute('''
                        INSERT INTO user_votes (user_id, post_id, vote_id, vote_option_id, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, NOW(), NOW())
                    ''', (session['user_id'], post_id, vote_id, option_id))
            else:  # 单选
                if not vote_option:
                    return jsonify({'success': False, 'message': '请选择一个选项'}), 400
                
                cursor.execute('''
                    INSERT INTO user_votes (user_id, post_id, vote_id, vote_option_id, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, NOW(), NOW())
                ''', (session['user_id'], post_id, vote_id, vote_option))
            
            db.get_db().commit()
            
            # 4. 获取最新的投票结果
            cursor.execute('''
                SELECT vo.vote_option_id, vo.title,
                      (SELECT COUNT(*) FROM user_votes uv WHERE uv.vote_option_id = vo.vote_option_id) as vote_count
                FROM vote_options vo
                WHERE vo.vote_id = %s
                ORDER BY vo.created_at
            ''', (vote_id,))
            options = cursor.fetchall()
            
            # 计算总投票数
            total_votes = sum(option['vote_count'] for option in options)
            
            # 获取用户的投票选项
            cursor.execute('''
                SELECT vote_option_id
                FROM user_votes
                WHERE user_id = %s AND vote_id = %s
            ''', (session['user_id'], vote_id))
            user_votes = cursor.fetchall()
            user_voted_options = [vote['vote_option_id'] for vote in user_votes]
            
            # 计算每个选项的百分比
            for option in options:
                option['percent'] = int((option['vote_count'] / total_votes * 100) if total_votes > 0 else 0)
            
            return jsonify({
                'success': True,
                'message': '投票成功',
                'data': {
                    'options': options,
                    'total_votes': total_votes,
                    'user_voted_options': user_voted_options
                }
            })
            
    except Exception as e:
        print(f"投票失败: {str(e)}")
        return jsonify({'success': False, 'message': '投票失败，请稍后重试'}), 500

# 添加评论接口
@app.route('/api/comments', methods=['POST'])
def add_comment():
    """添加评论API接口，返回JSON格式数据"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': '请先登录',
            'redirect': url_for('login')
        }), 401
    
    post_id = request.form.get('post_id')
    content = request.form.get('content', '').strip()
    
    if not post_id or not content:
        return jsonify({'success': False, 'message': '参数错误'}), 400
    
    try:
        with db.get_cursor() as cursor:
            # 1. 插入评论
            cursor.execute('''
                INSERT INTO comments (post_id, user_id, content, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
            ''', (post_id, session['user_id'], content))
            db.get_db().commit()
            
            # 2. 获取新插入的评论ID
            comment_id = cursor.lastrowid
            
            # 3. 获取评论详情
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
                # 格式化日期时间
                comment['created_at_formatted'] = comment['created_at'].strftime('%Y-%m-%d %H:%M')
                comment['likes'] = 0  # 新评论默认点赞数为0
            
            return jsonify({
                'success': True,
                'message': '评论成功',
                'data': comment
            })
            
    except Exception as e:
        print(f"评论失败: {str(e)}")
        return jsonify({'success': False, 'message': '评论失败，请稍后重试'}), 500

# 评论点赞接口
@app.route('/api/comments/like', methods=['POST'])
def like_comment():
    """评论点赞API接口，返回JSON格式数据"""
    return jsonify({
        'success': False,
        'message': '评论点赞功能暂未实现，当前 likes 表仅支持对帖子点赞'
    }), 501

# 删除评论接口
@app.route('/api/comments/delete', methods=['POST'])
def delete_comment():
    """删除评论API接口，返回JSON格式数据"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': '请先登录',
            'redirect': url_for('login')
        }), 401
    
    comment_id = request.form.get('comment_id')
    
    if not comment_id:
        return jsonify({'success': False, 'message': '参数错误'}), 400
    
    try:
        with db.get_cursor() as cursor:
            # 验证评论所有权
            cursor.execute('''
                SELECT user_id FROM comments
                WHERE comment_id = %s
            ''', (comment_id,))
            comment = cursor.fetchone()
            
            if not comment:
                return jsonify({'success': False, 'message': '评论不存在'}), 404
                
            if comment['user_id'] != session['user_id']:
                return jsonify({'success': False, 'message': '无权删除该评论'}), 403
            
            # 删除评论
            cursor.execute('''
                DELETE FROM comments
                WHERE comment_id = %s
            ''', (comment_id,))
            
            db.get_db().commit()
            
            return jsonify({
                'success': True,
                'message': '评论已删除'
            })
            
    except Exception as e:
        print(f"删除评论失败: {str(e)}")
        return jsonify({'success': False, 'message': '删除失败，请稍后重试'}), 500

# 关注/取消关注接口
@app.route('/api/follow', methods=['POST'])
def api_follow():
    """处理关注/取消关注的API接口，返回JSON格式数据"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': '请先登录',
            'redirect': url_for('login')
        }), 401
    
    follower_id = session['user_id']  # 当前登录用户ID（关注者）
    user_id = request.form.get('user_id')  # 被关注用户ID
    
    if not user_id:
        return jsonify({'success': False, 'message': '参数错误'}), 400
    
    # 不能关注自己
    if str(follower_id) == str(user_id):
        return jsonify({'success': False, 'message': '不能关注自己'}), 400
    
    try:
        with db.get_cursor() as cursor:
            # 查询是否已关注
            cursor.execute('''
                SELECT 1 FROM follows
                WHERE follower_id = %s AND user_id = %s
            ''', (follower_id, user_id))
            already_followed = cursor.fetchone() is not None
            
            if already_followed:
                # 已关注则取消关注
                cursor.execute('''
                    DELETE FROM follows
                    WHERE follower_id = %s AND user_id = %s
                ''', (follower_id, user_id))
                is_following = False
                message = '已取消关注'
            else:
                # 未关注则添加关注
                cursor.execute('''
                    INSERT INTO follows (user_id, follower_id, created_at, updated_at)
                    VALUES (%s, %s, NOW(), NOW())
                ''', (user_id, follower_id))
                is_following = True
                message = '关注成功'
            
            db.get_db().commit()
            
            # 获取被关注用户的粉丝数
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
        print(f"关注操作失败: {str(e)}")
        return jsonify({'success': False, 'message': '操作失败，请稍后重试'}), 500

# 获取用户关注的人列表接口
@app.route('/api/following', methods=['GET'])
def api_get_following():
    """获取当前用户关注的人列表API接口，返回JSON格式数据"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': '请先登录',
            'redirect': url_for('login')
        }), 401
    
    follower_id = session['user_id']
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    offset = (page - 1) * per_page
    
    try:
        with db.get_cursor() as cursor:
            # 获取关注列表总数
            cursor.execute('''
                SELECT COUNT(*) as total_count
                FROM follows
                WHERE follower_id = %s
            ''', (follower_id,))
            result = cursor.fetchone()
            total_count = result['total_count'] if result else 0
            
            # 获取关注的用户列表
            cursor.execute('''
                SELECT u.user_id, u.username, u.profile_image, f.created_at as followed_at
                FROM follows f
                JOIN users u ON f.user_id = u.user_id
                WHERE f.follower_id = %s
                ORDER BY f.created_at DESC
                LIMIT %s OFFSET %s
            ''', (follower_id, per_page, offset))
            following = cursor.fetchall()
            
            # 格式化数据
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
        print(f"获取关注列表失败: {str(e)}")
        return jsonify({'success': False, 'message': '获取数据失败，请稍后重试'}), 500

# 获取粉丝列表接口
@app.route('/api/followers', methods=['GET'])
def api_get_followers():
    """获取当前用户的粉丝列表API接口，返回JSON格式数据"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': '请先登录',
            'redirect': url_for('login')
        }), 401
    
    user_id = session['user_id']
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    offset = (page - 1) * per_page
    
    try:
        with db.get_cursor() as cursor:
            # 获取粉丝列表总数
            cursor.execute('''
                SELECT COUNT(*) as total_count
                FROM follows
                WHERE user_id = %s
            ''', (user_id,))
            result = cursor.fetchone()
            total_count = result['total_count'] if result else 0
            
            # 获取粉丝用户列表，并检查当前用户是否也关注了这些粉丝
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
            
            # 格式化数据
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
        print(f"获取粉丝列表失败: {str(e)}")
        return jsonify({'success': False, 'message': '获取数据失败，请稍后重试'}), 500

# 检查是否关注接口
@app.route('/api/check_follow/<int:target_user_id>', methods=['GET'])
def api_check_follow(target_user_id):
    """检查当前用户是否关注指定用户的API接口，返回JSON格式数据"""
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': '请先登录',
            'redirect': url_for('login')
        }), 401
    
    follower_id = session['user_id']
    
    try:
        with db.get_cursor() as cursor:
            # 查询是否已关注
            cursor.execute('''
                SELECT 1 FROM follows
                WHERE follower_id = %s AND user_id = %s
            ''', (follower_id, target_user_id))
            is_following = cursor.fetchone() is not None
            
            # 获取目标用户的粉丝数
            cursor.execute('''
                SELECT COUNT(*) as followers_count 
                FROM follows 
                WHERE user_id = %s
            ''', (target_user_id,))
            result = cursor.fetchone()
            followers_count = result['followers_count'] if result else 0
            
            # 获取目标用户的关注数
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
        print(f"检查关注状态失败: {str(e)}")
        return jsonify({'success': False, 'message': '获取数据失败，请稍后重试'}), 500