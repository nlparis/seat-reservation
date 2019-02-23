import uuid
import hashlib
import os
import tempfile
import shutil
import flask
from flask import request
import arrow
import gmdp

def sha256sum(filename):
    """Return sha256 hash of file content, similar to UNIX sha256sum."""
    content = open(filename, 'rb').read()
    sha256_obj = hashlib.sha256(content)
    return sha256_obj.hexdigest()

@gmdp.app.route('/', methods=['POST', 'GET'])
def show_index():
    """Show the index page."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    connection = gmdp.model.get_db()
    cursor = connection.cursor()
    if request.method == 'POST':
        if 'like' in request.form:
            print("IN LIKES")
            query = "INSERT INTO likes(owner, postid) VALUES (\'" + \
                flask.session['username'] + "\', \'" + \
                    request.form['postid'] + "\')"
            print(query)
            cursor.execute(query)
        if 'unlike' in request.form:
            print("IN UNLIKES")
            query = "DELETE FROM likes WHERE owner = \'" + \
                flask.session['username'] + "\' AND postid = \'" + \
                    request.form['postid'] + "\'"
            print(query)
            cursor.execute(query)
        if 'comment' in request.form:
            cursor.execute("SELECT * FROM comments")
            commentid = (len(cursor.fetchall())) + 1
            query = "INSERT INTO comments(commentid, owner, postid, text)\
             VALUES (\'" + str(commentid) + "\', \'" + \
                flask.session['username'] + "\', \'"\
                + request.form['postid'] + \
                    "\', \'" + request.form['text'] + "\')"
            print(query)
            cursor.execute(query)

    # print("context\n\n")
    context = build_index_context_dict()
    # print(context)

    return flask.render_template("index.html", **context)


@gmdp.app.route('/accounts/login/', methods=['POST', 'GET'])
def show_login():
    """Display /accounts/login/ route."""
    # if already logged in send home
    if 'username' in flask.session:
        return flask.redirect(flask.url_for('show_index'))

    # if user enters login info
    if request.method == 'POST':
        connection = gmdp.model.get_db()
        cursor = connection.cursor()
        query = ("SELECT password FROM users WHERE username=\'" +
                 request.form['username'] + "\'")
        cursor.execute(query)
        data = cursor.fetchone()
        print(data)
        if data:
            print("user exists")
            # need to salt+hash the password
            algorithm = 'sha512'
            salt = data['password'].split("$")
            salt = salt[1]
            hash_obj = hashlib.new(algorithm)
            password_salted = salt + request.form['password']
            hash_obj.update(password_salted.encode('utf-8'))
            password_hash = hash_obj.hexdigest()
            password_db_string = "$".join([algorithm, salt, password_hash])
            print(password_db_string)
            if password_db_string == data['password']:
                print("login successful")
                flask.session['username'] = request.form['username']

                return flask.redirect(flask.url_for('show_index'))

    context = {}
    return flask.render_template("login.html", **context)

@gmdp.app.route('/accounts/logout/', methods=['GET'])
def show_logout():
    """Logout the user."""
    flask.session.clear()
    return flask.redirect(flask.url_for('show_login'))

@gmdp.app.route('/accounts/create/', methods=['POST', 'GET'])
def show_create_account():
    """Show the create account page."""
    if request.method == 'POST':
        # Save POST request's file object to a temp file
        cursor = gmdp.model.get_db().cursor()
        dummy, temp_filename = tempfile.mkstemp()
        file = flask.request.files["file"]
        file.save(temp_filename)

        # Compute filename
        hash_txt = sha256sum(temp_filename)
        dummy, suffix = os.path.splitext(file.filename)
        hash_filename_basename = hash_txt + suffix
        hash_filename = os.path.join(
            gmdp.app.config["UPLOAD_FOLDER"],
            hash_filename_basename
        )

        # Move temp file to permanent location
        shutil.move(temp_filename, hash_filename)
        gmdp.app.logger.debug("Saved %s", hash_filename_basename)

        cursor.execute("SELECT password FROM users WHERE username=\'" +
                       request.form['username'] + "\'")
        data = cursor.fetchone()
        if data:
            # todo: probably need an error message here, User already exists
            return show_create_account()

        # need to salt+hash the password
        salt = uuid.uuid4().hex
        hash_obj = hashlib.new('sha512')
        password_salted = salt + request.form['password']
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        password_db_string = "$".join(['sha512', salt, password_hash])

        cursor.execute("INSERT INTO\
                        users(username, fullname, email, filename, password)\
                        VALUES (\'" +
                       request.form['username'] + "\', \'" +
                       request.form['fullname'] +
                       "\', \'" + request.form['email'] + "\', \'" +
                       hash_filename_basename +
                       "\',\'" + password_db_string + "\')")

        flask.session['username'] = request.form['username']

        return flask.redirect(flask.url_for('show_index'))

    context = {}
    return flask.render_template("create.html", **context)


@gmdp.app.route('/accounts/password/', methods=['GET', 'POST'])
def show_password():
    """Show the change password page."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    # check entered password
    if request.method == 'POST':
        connection = gmdp.model.get_db()
        cursor = connection.cursor()
        query = ("SELECT password FROM users WHERE username=\'" +
                 flask.session['username'] + "\'")
        cursor.execute(query)
        data = cursor.fetchone()
        if data:
            # need to salt+hash the password
            algorithm = 'sha512'
            salt = data['password'].split("$")
            salt = salt[1]
            hash_obj = hashlib.new(algorithm)
            password_salted = salt + request.form['password']
            hash_obj.update(password_salted.encode('utf-8'))
            password_hash = hash_obj.hexdigest()
            password_db_string = "$".join([algorithm, salt, password_hash])

            if not password_db_string == data['password']:
                # incorrect password
                flask.abort(403)
            print("password match")
            # check the entered old and new password
            if request.form['new_password1'] == request.form['new_password2']:
                print("new passwords match")
                # change password in db
                salt = uuid.uuid4().hex
                hash_obj = hashlib.new(algorithm)
                password_salted = salt + request.form['new_password1']
                hash_obj.update(password_salted.encode('utf-8'))
                password_hash = hash_obj.hexdigest()
                password_db_string = "$".join([algorithm, salt, password_hash])

                query = ("UPDATE users SET password=\'" + password_db_string +
                         "\' WHERE username=\'" + flask.session['username'] +
                         "\'")
                cursor.execute(query)
                if cursor.rowcount == 0:
                    print("execution error")
                else:
                    print("update successful!!!!")

                    return flask.redirect(flask.url_for('show_edit'))
            else:
                print("New password mismatch")
                flask.abort(401)

        else:
            print("ERROR in password: user does not exist")

    return flask.render_template("password.html")
