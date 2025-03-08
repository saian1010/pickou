from loginapp import app
from loginapp import db
from flask import redirect, render_template, session, url_for, request, flash
from datetime import datetime

@app.route('/issues')
def list_issues():
    """List issues endpoint with pagination and filters."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
        
    page = request.args.get('page', 1, type=int)
    search_name = request.args.get('search_name', '')
    created_by = request.args.get('created_by', '')
    status_filter = request.args.get('status', '')
    
    # Validate status filter
    if status_filter not in ['new', 'stalled', 'open']:
        status_filter = ''
    
    is_resolved = request.args.get('resolved', '') == 'true'
    
    cursor = db.get_db().cursor()
    
    # Base query
    query = """
        SELECT i.*, u.username 
        FROM issues i 
        JOIN users u ON i.user_id = u.user_id 
        WHERE 1=1
    """
    params = []
    
    # Add filters based on user role
    if session['role'] == 'visitor':
        query += " AND i.user_id = %s"
        params.append(session['user_id'])
        
    if search_name:
        query += " AND i.summary LIKE %s"
        params.append(f"%{search_name}%")
    if created_by:
        query += " AND u.username = %s"
        params.append(created_by)
        
    # Add status condition based on resolution
    if is_resolved:
        query += " AND i.status = 'resolved'"
    else:
        query += " AND i.status != 'resolved'"
        if status_filter:
            query += " AND i.status = %s"
            params.append(status_filter)
    
    # Get total count for pagination
    per_page = 10
    count_query = f"SELECT COUNT(*) FROM ({query}) as t"
    cursor.execute(count_query, params)
    total_count = cursor.fetchone()[0]
    total_pages = (total_count + per_page - 1) // per_page
    
    # Ensure the page number is valid
    if page > total_pages:
        page = 1
    offset = (page - 1) * per_page  

    # Add sorting and pagination
    query += " ORDER BY i.created_at DESC LIMIT %s OFFSET %s"
    params.extend([per_page, offset])
    
    # Execute final query
    cursor.execute(query, params)
    issues = cursor.fetchall()
    cursor.close()
    
    return render_template('issues/list.html', 
                         issues=issues,
                         current_page=page,
                         total=total_count,
                         total_pages=total_pages,
                         search_name=search_name,
                         created_by=created_by,
                         status_filter=status_filter)

@app.route('/issues/new', methods=['GET', 'POST'])
def create_issue():
    """Create new issue endpoint."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        summary = request.form.get('summary', '').strip()
        description = request.form.get('description', '').strip()
        
        # Validate input
        if not summary or not description:
            flash('Please fill in all required fields')
            return render_template('issues/create.html')
            
        if len(summary) > 255:
            flash('Summary must not exceed 255 characters')
            return render_template('issues/create.html')
            
        if len(summary) < 3:
            flash('Summary must be at least 3 characters long')
            return render_template('issues/create.html')
            
        if len(description) < 10:
            flash('Description must be at least 50 characters long')
            return render_template('issues/create.html')
            
        if len(description) > 5000:
            flash('Description must not exceed 5000 characters')
            return render_template('issues/create.html')
            
        try:
            cursor = db.get_db().cursor()
            sql = """INSERT INTO issues 
                    (user_id, summary, description, created_at, status) 
                    VALUES (%s, %s, %s, %s, %s)"""
            values = (session['user_id'], summary, description, 
                     datetime.now(), 'new')
            cursor.execute(sql, values)
            db.get_db().commit()
            cursor.close()
            flash('Issue created successfully', 'success')
            return redirect(url_for('list_issues'))
            
        except Exception as e:
            print(f"Error creating issue: {str(e)}")
            flash('Failed to create issue. Please try again later')
            return render_template('issues/create.html')
            
    return render_template('issues/create.html')

@app.route('/issues/<int:issue_id>')
def view_issue(issue_id):
    """View issue details and comments."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
        
    cursor = db.get_db().cursor()
    
    # Get issue details with specific field order
    cursor.execute("""
        SELECT 
            i.issue_id,          -- 0
            i.user_id,           -- 1
            i.summary,           -- 2
            i.description,       -- 3
            i.status,            -- 4
            i.created_at,        -- 5
            u.username,          -- 6
            u.role,              -- 7
            u.profile_image      -- 8
        FROM issues i 
        JOIN users u ON i.user_id = u.user_id 
        WHERE i.issue_id = %s
    """, (issue_id,))
    issue = cursor.fetchone()
    
    if not issue:
        cursor.close()
        return render_template('404.html'), 404
    
    # Get pagination parameters for comments
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    # Get total count of comments
    cursor.execute("""
        SELECT COUNT(*) 
        FROM comments 
        WHERE issue_id = %s
    """, (issue_id,))
    total_count = cursor.fetchone()[0]
    total_pages = (total_count + per_page - 1) // per_page
    
    # Get comments with user info, ordered by created_at DESC with pagination
    cursor.execute("""
        SELECT 
            c.comment_id,        -- 0
            c.user_id,           -- 1
            c.content,           -- 2
            c.created_at,        -- 3
            c.issue_id,          -- 4
            u.username,          -- 5
            u.role,              -- 6
            u.profile_image      -- 7
        FROM comments c
        JOIN users u ON c.user_id = u.user_id
        WHERE c.issue_id = %s
        ORDER BY c.created_at DESC
        LIMIT %s OFFSET %s
    """, (issue_id, per_page, offset))
    comments = cursor.fetchall()
    cursor.close()
    
    # Create new issue tuple with updated image path
    issue = list(issue)
    issue[8] = get_image_path(issue[8])
    
    # Create new comments list with updated image paths
    comments = [list(comment) for comment in comments]
    for comment in comments:
        comment[7] = get_image_path(comment[7])
    
    return render_template('issues/view.html', 
                         issue=issue,
                         comments=comments,
                         current_page=page,
                         total_pages=total_pages,
                         total=total_count,
                         default_picture='/static/default.png')

# Convert profile_image filename to full path
def get_image_path(filename):
    return f'/loginapp/uploads/{filename}' if filename else '/static/default.png'

@app.route('/issues/<int:issue_id>/comment', methods=['POST'])
def add_comment(issue_id):
    """Add a comment to an issue."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    content = request.form.get('content')
    if not content:
        flash('Comment cannot be empty', 'danger')
        return redirect(url_for('view_issue', issue_id=issue_id))
    
    cursor = db.get_db().cursor()
    try:
        # Get current issue status
        cursor.execute('SELECT status FROM issues WHERE issue_id = %s', (issue_id,))
        issue = cursor.fetchone()
        if not issue:
            flash('Issue not found', 'danger')
            return redirect(url_for('list_issues'))
        
        # If helper or admin comments on stalled or resolved issue, change status to open
        if (session['role'] in ['helper', 'admin'] and 
            issue[0] in ['stalled', 'resolved', 'new']):
            
            cursor.execute(
                'UPDATE issues SET status = %s WHERE issue_id = %s',
                ('open', issue_id)
            )
            
            # Add status change record to comments
            status_comment = f"Issue reopened by {session['username']} due to new comment: {content}"
            cursor.execute(
                'INSERT INTO comments (issue_id, content, created_at, user_id) VALUES (%s, %s, NOW(), %s)',
                (issue_id, status_comment, session['user_id'])
            )
            if issue[0] == 'new':
                flash('Comment added and issue reopened', 'success')
            else:
                flash('Comment added and issue opened', 'success')
        else:
            # Add comment
            cursor.execute(
                'INSERT INTO comments (issue_id, content, created_at, user_id) VALUES (%s, %s, NOW(), %s)',
                (issue_id, content, session['user_id'])
            )
            flash('Comment added successfully', 'success')
            
        db.get_db().commit()
        
    except Exception as e:
        print(e)
        db.get_db().rollback()
        flash('An error occurred while adding the comment', 'danger')
    finally:
        cursor.close()
    
    return redirect(url_for('view_issue', issue_id=issue_id))

@app.route('/issues/<int:issue_id>/status/<new_status>', methods=['GET'])
def change_issue_status(issue_id, new_status):
    """Change the status of an issue."""
    # Check if user is logged in
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    # Check user role permissions
    if session['role'] not in ['helper', 'admin']:
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('list_issues'))
    
    # Get source page parameter
    is_from_view = request.args.get('from') == 'view'
    
    # Validate status transition legality
    valid_transitions = {
        'new': ['open'],
        'open': ['stalled', 'resolved'],
        'stalled': ['open', 'resolved'],
        'resolved': ['open']
    }
    
    cursor = db.get_db().cursor()
    
    try:
        # Get current issue status
        cursor.execute('SELECT status FROM issues WHERE issue_id = %s', (issue_id,))
        result = cursor.fetchone()
        
        if not result:
            flash('Issue not found', 'danger')
            return redirect(url_for('list_issues'))
        
        current_status = result[0]
        
        # Validate status transition legality
        if new_status not in valid_transitions.get(current_status, []):
            flash(f'Invalid status transition from {current_status} to {new_status}', 'danger')
            return redirect(url_for('view_issue', issue_id=issue_id) if is_from_view else url_for('list_issues'))
        
        # Update status
        cursor.execute(
            'UPDATE issues SET status = %s WHERE issue_id = %s',
            (new_status, issue_id)
        )
        
        # Add status change record to comments
        status_messages = {
            'open': 'opened',
            'stalled': 'marked as stalled',
            'resolved': 'resolved',
        }
        comment = f"Issue {status_messages[new_status]} by {session['username']}"
        
        cursor.execute(
            'INSERT INTO comments (issue_id, content, created_at, user_id) VALUES (%s, %s, NOW(), %s)',
            (issue_id, comment, session['user_id'])
        )
        
        db.get_db().commit()
        
        # Display different success messages based on status
        status_change_messages = {
            'open': 'Issue has been opened',
            'stalled': 'Issue has been marked as stalled',
            'resolved': 'Issue has been resolved',
        }
        flash(status_change_messages.get(new_status, 'Status updated successfully'), 'success')
        
    except Exception as e:
        print(e)
        db.get_db().rollback()
        flash('An error occurred while updating the issue status', 'danger')
    finally:
        cursor.close()
    
    # Redirect based on source parameter
    return redirect(url_for('view_issue', issue_id=issue_id) if is_from_view else url_for('list_issues'))