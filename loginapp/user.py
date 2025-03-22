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
               pi.image_path as image_url,
               (SELECT COUNT(*) FROM likes uv WHERE uv.post_id = p.post_id) as likes,
               (SELECT COUNT(*) > 0 FROM likes ul WHERE ul.post_id = p.post_id AND ul.user_id = %s) as user_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        LEFT JOIN post_images pi ON p.post_id = pi.post_id
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
   
    if 'loggedin' not in session:
        return jsonify({
            'success': False,
            'message': 'Please log in first',
            'redirect': url_for('login')
        }), 401
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
               pi.image_path as image_url,
               (SELECT COUNT(*) FROM likes uv WHERE uv.post_id = p.post_id) as likes,
               (SELECT COUNT(*) > 0 FROM likes ul WHERE ul.post_id = p.post_id AND ul.user_id = %s) as user_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        LEFT JOIN post_images pi ON p.post_id = pi.post_id
        JOIN follows f ON p.user_id = f.follower_id AND f.user_id = %s
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
            JOIN follows f ON p.user_id = f.follower_id AND f.user_id = %s
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
            
        if len(content) < 1:
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
                import json
                print(f"Received poll data string: {poll_data_str}")
                
                try:
                    poll_data = json.loads(poll_data_str)
                    
                    if poll_data and isinstance(poll_data, dict):
                        print(f"Parsed poll data: {poll_data}")
                        
                        # Create poll
                        vote_title = poll_data.get('question', '').strip()
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
                            
                            # No longer need to update vote_option_id field in votes table
                            # if option_ids:
                            #     cursor.execute(
                            #         "UPDATE votes SET vote_option_id = %s WHERE vote_id = %s",
                            #         (option_ids[0], vote_id)
                            #     )
                            #     print(f"Updated vote_option_id in votes table to: {option_ids[0]}")
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
            if images and images[0].filename:
                # Ensure upload directory exists
                upload_folder = os.path.join(app.static_folder, 'uploads', 'posts')
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)
                
                # Store image paths for later database storage
                image_paths = []
                
                for image in images:
                    if image and allowed_file(image.filename):
                        # Safely get filename and create unique filename
                        filename = secure_filename(image.filename)
                        # Add timestamp to prevent filename conflicts
                        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                        unique_filename = f"{timestamp}_{filename}"
                        
                        # Save image
                        file_path = os.path.join(upload_folder, unique_filename)
                        image.save(file_path)
                        
                        # Add path to list
                        image_paths.append(unique_filename)
                        
                        # Save image info to database
                        try:
                            cursor.execute(
                                "INSERT INTO post_images (post_id, image_path, created_at, updated_at) VALUES (%s, %s, NOW(), NOW())",
                                (post_id, unique_filename)
                            )
                            print(f"Saved image path '{unique_filename}' to database, linked to post ID: {post_id}")
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