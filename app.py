from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from ldap3 import Connection, Server, ALL
from pymongo import MongoClient
from bson.objectid import ObjectId
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key

# MongoDB Configuration
client = MongoClient('mongodb://localhost:27017/')
db = client['announcement_db']
collection = db['announcements']
sticky_notes_collection = db['sticky_notes']

# LDAP Server Configuration
LDAP_SERVER = "ldap://10.30.1.50"
SEARCH_BASE = 'DC=sandhata,DC=local'
HR_GROUP_DN = "CN=HR,CN=Users,DC=sandhata,DC=local"
ATTRIBUTES = ['cn', 'mail', 'telephoneNumber', 'description', 'manager', 'directReports']

def is_hr_member(email, password):
    server = Server(LDAP_SERVER, get_info=ALL)
    con = Connection(server, user=email, password=password)

    if not con.bind():
        return False, 'Invalid credentials', None

    # Fetch user's CN
    search_filter = f"(mail={email})"
    con.search(SEARCH_BASE, search_filter, attributes=['cn'])
    if con.entries:
        user_cn = con.entries[0].cn.value
    else:
        con.unbind()
        return False, 'Invalid credentials', None

    # Check if the user is a member of the HR group
    con.search(HR_GROUP_DN, "(objectClass=group)", attributes=['member'])
    hr_emails = []
    for entry in con.entries:
        if 'member' in entry:
            members = entry.member.values
            for member_dn in members:
                con.search(member_dn, "(objectClass=person)", attributes=['mail'])
                if con.entries:
                    member_email = con.entries[0].mail.value
                    hr_emails.append(member_email)

    is_hr = email in hr_emails
    con.unbind()
    
    return is_hr, None, user_cn if is_hr else user_cn

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email and password:
            is_hr, error, user_cn = is_hr_member(email, password)
            if error:
                return render_template('login.html', error=error)
            session['user'] = email
            session['password'] = password  # Store the password for future LDAP queries
            session['is_hr'] = is_hr
            session['cn'] = user_cn
            return redirect(url_for('success'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/success')
def success():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    is_hr = session.get('is_hr', False)
    announcement_doc = collection.find_one()
    announcements = announcement_doc['announcement'] if announcement_doc else "No announcements yet."

    # Fetch sticky notes associated with the current user (session user)
    user_email = session['user']
    sticky_notes_cursor = sticky_notes_collection.find({'user': user_email})
    sticky_notes = [{'id': note['_id'], 'text': note['text']} for note in sticky_notes_cursor]

    return render_template('success.html', cn=session['cn'], is_hr=is_hr, announcements=announcements, sticky_notes=sticky_notes)

@app.route('/live_search', methods=['GET'])
def live_search():
    if 'user' not in session or 'password' not in session:
        return redirect(url_for('login'))

    search_term = request.args.get('term', '')
    if not search_term:
        return jsonify(suggestions=[])

    email = session['user']
    password = session['password']

    server = Server(LDAP_SERVER, get_info=ALL)
    try:
        con = Connection(server, user=email, password=password, auto_bind=True)
    except Exception as e:
        return jsonify(suggestions=[]), 403

    search_filter = f'(cn={search_term}*)'
    con.search(SEARCH_BASE, search_filter, attributes=['cn'])
    suggestions = [entry.cn.value for entry in con.entries if entry.cn.value.lower().startswith(search_term.lower())]
    con.unbind()

    return jsonify(suggestions=suggestions)

@app.route('/user_info', methods=['GET'])
def user_info():
    if 'user' not in session or 'password' not in session:
        return redirect(url_for('login'))

    cn_name = request.args.get('cn_name')
    if not cn_name:
        return jsonify({'error': 'No common name provided.'}), 400

    email = session['user']
    password = session['password']

    server = Server(LDAP_SERVER, get_info=ALL)
    try:
        con = Connection(server, user=email, password=password, auto_bind=True)
        search_filter = f'(cn={cn_name})'
        con.search(SEARCH_BASE, search_filter, attributes=ATTRIBUTES)
        user_entries = con.entries
        con.unbind()

        if not user_entries:
            return jsonify({'error': 'No entries found or incorrect search term.'}), 403

        user_info = user_entries[0]
        manager_info = None
        direct_reports = []

        if 'manager' in user_info:
            manager_dn = user_info.manager.value
            con = Connection(server, user=email, password=password, auto_bind=True)
            con.search(manager_dn, '(objectClass=*)', attributes=ATTRIBUTES)
            manager_entries = con.entries
            con.unbind()

            if manager_entries:
                manager_info = manager_entries[0]
                if 'directReports' in user_info:
                    direct_reports_dns = user_info.directReports
                    for report_dn in direct_reports_dns:
                        con = Connection(server, user=email, password=password, auto_bind=True)
                        con.search(report_dn, '(objectClass=*)', attributes=['cn'])
                        if con.entries:
                            direct_reports.append(con.entries[0].cn.value)
                        con.unbind()

        user_data = {
            'cn': user_info.cn.value,
            'mail': user_info.mail.value if 'mail' in user_info else '',
            'telephoneNumber': user_info.telephoneNumber.value if 'telephoneNumber' in user_info else '',
            'description': user_info.description.value if 'description' in user_info else '',
            'manager': manager_info.cn.value if manager_info else '',
            'directReports': direct_reports
        }

        return jsonify(user_data)
    except Exception as e:
        return jsonify({'error': f"Failed to bind to LDAP server: {e}"}), 403

@app.route('/add_sticky_note', methods=['POST'])
def add_sticky_note():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'}), 401

    user_email = session['user']
    new_note_text = request.form['sticky_note']
    note = {'user': user_email, 'text': new_note_text}
    result = sticky_notes_collection.insert_one(note)
    new_note = {'id': str(result.inserted_id), 'text': new_note_text}
    return jsonify({'success': True, 'new_note': new_note})

@app.route('/edit_sticky_note', methods=['POST'])
def edit_sticky_note():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'}), 401

    note_id = request.form['id']
    new_text = request.form['text']
    result = sticky_notes_collection.update_one({'_id': ObjectId(note_id), 'user': session['user']}, {'$set': {'text': new_text}})

    if result.matched_count == 0:
        return jsonify({'success': False, 'message': 'Note not found or not authorized.'}), 404

    return jsonify({'success': True})

@app.route('/delete_sticky_note', methods=['POST'])
def delete_sticky_note():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'}), 401

    note_id = request.form['id']
    try:
        result = sticky_notes_collection.delete_one({'_id': ObjectId(note_id), 'user': session['user']})

        if result.deleted_count == 0:
            return jsonify({'success': False, 'message': 'Note not found or not authorized.'}), 404

        return jsonify({'success': True})
    except Exception as e:
        print(f"Error deleting sticky note: {e}")
        return jsonify({'success': False, 'message': 'Error deleting sticky note.'}), 500


@app.route('/update_announcement', methods=['POST'])
def update_announcement():
    if request.method == 'POST':
        new_announcement = request.form.get('announcement')
        # Assuming MongoDB update logic here
        collection.update_one({}, {"$set": {"announcement": new_announcement}}, upsert=True)
        return jsonify({'success': True, 'new_announcement': new_announcement})
    return jsonify({'success': False})

if __name__ == '__main__':
    app.run(debug=True)
