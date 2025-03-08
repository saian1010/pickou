from loginapp import app
from loginapp import db
from flask import redirect, render_template, session, url_for, request, jsonify

@app.route('/admin/home')
def admin_home():
    """visitor Homepage endpoint."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    elif session['role'] != 'admin':
        return render_template('access_denied.html'), 403

    cursor = db.get_db().cursor(dictionary=True)  # Use dictionary cursor for better readability
    try:
        # Get user issue statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_issues,
                SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) as new_issues,
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_issues,
                SUM(CASE WHEN status = 'stalled' THEN 1 ELSE 0 END) as stalled_issues,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_issues
            FROM issues
        ''')
        
        stats = cursor.fetchone()
        
        # Get the most recent 5 unresolved issues
        cursor.execute('''
            SELECT issues.issue_id, issues.summary, issues.status, issues.created_at, 
                       users.username as created_by
            FROM issues, users
            WHERE issues.user_id = users.user_id
            AND issues.status != 'resolved'
            ORDER BY issues.created_at DESC
            LIMIT 5
        ''')
        
        recent_issues = cursor.fetchall()
        
        return render_template('admin_home.html', stats=stats, recent_issues=recent_issues)
    
    finally:
        cursor.close()


@app.route('/users/manage')
def manage_users():
    """User management endpoint - handles user listing and filtering."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    elif session['role'] != 'admin':
        return render_template('access_denied.html'), 403
    
    # Get search parameters and pagination info
    username = request.args.get('username', '')
    first_name = request.args.get('first_name', '')
    last_name = request.args.get('last_name', '')
    role = request.args.get('role', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of items per page
    
    if role not in ['visitor', 'helper', 'admin']:
        role = ''

    # Build query conditions
    query = "SELECT * FROM users WHERE 1=1"
    count_query = "SELECT COUNT(*) as total FROM users WHERE 1=1"
    params = []
    
    # Add search filters if provided
    if username:
        query += " AND username LIKE %s"
        count_query += " AND username LIKE %s"
        params.append(f"%{username}%")
    if first_name:
        query += " AND first_name LIKE %s"
        count_query += " AND first_name LIKE %s"
        params.append(f"%{first_name}%")
    if last_name:
        query += " AND last_name LIKE %s"
        count_query += " AND last_name LIKE %s"
        params.append(f"%{last_name}%")
    if role:
        query += " AND role = %s"
        count_query += " AND role = %s"
        params.append(role)
    
    # Add pagination
    query += " LIMIT %s OFFSET %s"
    
    cursor = db.get_db().cursor(dictionary=True)
    try:
        # Get total record count
        cursor.execute(count_query, params)
        total = cursor.fetchone()['total']
        total_pages = (total + per_page - 1) // per_page
        
        if page > total_pages:
            page = 1

        offset = (page - 1) * per_page
        pagination_params = params.copy()
        pagination_params.extend([per_page, offset])

        # Get current page data
        cursor.execute(query, pagination_params)
        users = cursor.fetchall()
        return render_template('manage_users.html', 
                            users=users,
                            page=page,
                            total_pages=total_pages,
                            total=total)
    finally:
        cursor.close()

@app.route('/users/update_role', methods=['POST'])
def update_user_role():
    """Update user role endpoint."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    elif session['role'] != 'admin':
        return render_template('access_denied.html'), 403
    
    data = request.get_json()
    username = data.get('username')
    new_role = data.get('role')
    
    if not username or new_role not in ['visitor', 'helper', 'admin']:
        return jsonify({'success': False, 'message': 'Invalid parameters'}), 400
    
    try:
        conn = db.get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET role = %s WHERE username = %s', 
                      (new_role, username))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()

@app.route('/users/toggle_status', methods=['POST'])
def toggle_user_status():
    """Toggle user status between active and inactive."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    elif session['role'] != 'admin':
        return render_template('access_denied.html'), 403
    
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'success': False, 'message': 'Invalid parameters'}), 400
    
    try:
        conn = db.get_db()
        cursor = conn.cursor(dictionary=True)
        # First, get the current status
        cursor.execute(
            'SELECT status FROM users WHERE username = %s', 
            (username,)
        )
        current_status = cursor.fetchone()['status']
        
        # Update to the opposite status
        new_status = 'inactive' if current_status == 'active' else 'active'
        cursor.execute(
            'UPDATE users SET status = %s WHERE username = %s',
            (new_status, username)
        )
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()


@app.route('/users/view/<int:user_id>')
def view_user(user_id):
    """View user details."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    elif session['role'] != 'admin':
        return render_template('access_denied.html'), 403

    cursor = db.get_db().cursor(dictionary=True)  # Use dictionary cursor

    cursor.execute("""
        SELECT * From users where user_id = %s
    """, (user_id,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        return render_template('404.html'), 404
    
    user["profile_image"] = f'/loginapp/uploads/{user["profile_image"]}' if user["profile_image"] else '/static/default.png'

    return render_template('view_user.html', user=user)
