from loginapp import app
from loginapp import db
from flask import redirect, render_template, session, url_for, request

@app.route('/visitor/home')
def visitor_home():
    """visitor Homepage endpoint."""
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    elif session['role'] != 'visitor':
        return render_template('access_denied.html'), 403
    
    return render_template('list.html')