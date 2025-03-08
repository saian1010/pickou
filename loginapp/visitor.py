from loginapp import app
from loginapp import db
from flask import redirect, render_template, session, url_for

@app.route('/visitor/home')
def visitor_home():
    """visitor Homepage endpoint."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    elif session['role'] != 'visitor':
        return render_template('access_denied.html'), 403

    cursor = db.get_db().cursor(dictionary=True)  # Use dictionary cursor for better readability
    try:
        # Get user's issues statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_issues,
                SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) as new_issues,
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_issues,
                SUM(CASE WHEN status = 'stalled' THEN 1 ELSE 0 END) as stalled_issues,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_issues
            FROM issues 
            WHERE user_id = %s
        ''', (session['user_id'],))
        
        stats = cursor.fetchone()
        
        # Get the most recent 5 issues
        cursor.execute('''
            SELECT issues.issue_id, issues.summary, issues.status, issues.created_at, 
                       users.username as created_by
            FROM issues, users
            WHERE issues.user_id = users.user_id
            AND issues.user_id = %s
            ORDER BY issues.created_at DESC
            LIMIT 5
        ''', (session['user_id'],))
        
        recent_issues = cursor.fetchall()
        
        return render_template('visitor_home.html', stats=stats, recent_issues=recent_issues)
    
    finally:
        cursor.close()