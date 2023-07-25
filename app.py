from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_migrate import Migrate
from datetime import datetime
import os


app = Flask(__name__)

# SQLite database in the same directory as this script:
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://pzzufmrbybjwxi:b5084bbcdc6fe846e28d7e4fa71b95cdb977fb85f9cfbc20b3bec36576a7b404@ec2-54-211-177-159.compute-1.amazonaws.com:5432/db8cva5rpfnv07'

app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key')

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class Group(db.Model):
    __tablename__ = 'group'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)


class Technician(db.Model):
    __tablename__ = 'technician'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    signouts = db.relationship('Signout', backref='technician', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Tool(db.Model):
    __tablename__ = 'tool'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    is_signed_out = db.Column(db.Boolean, default=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    signouts = db.relationship('Signout', backref='tool', lazy=True)


class Key(db.Model):
    __tablename__ = 'key'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    is_signed_out = db.Column(db.Boolean, default=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    signouts = db.relationship('Signout', backref='key', lazy=True)


class Signout(db.Model):
    __tablename__ = 'signout'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    tool_id = db.Column(db.Integer, db.ForeignKey('tool.id'))
    technician_id = db.Column(db.Integer, db.ForeignKey('technician.id'))
    key_id = db.Column(db.Integer, db.ForeignKey('key.id'))
    date_out = db.Column(db.DateTime, nullable=False)
    date_returned = db.Column(db.DateTime)
    returned = db.Column(db.Boolean, default=False)


class ErrorLog(db.Model):
    __tablename__ = 'error_log'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)


@app.errorhandler(Exception)
def handle_exception(e):
    error_msg = str(e)
    error_log = ErrorLog(message=error_msg)
    db.session.add(error_log)
    db.session.commit()
    flash(error_msg)
    return redirect(url_for('error_page'))


@app.route('/error')
def error_page():
    errors = [flash_message for flash_message in session.get('_flashes', [])]
    return render_template('error.html', errors=errors)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'tech_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    tech_id = session.get('tech_id')
    tech = Technician.query.get(tech_id)

    if tech is None:
        flash('No tech found with the current tech_id')
        return redirect(url_for('error_page'))

    tech_signouts = tech.signouts
    tools = Tool.query.filter_by(is_signed_out=False).all()
    keys = Key.query.filter_by(is_signed_out=False).all()

    # Only get Signout records that haven't been returned
    signouts = Signout.query.filter_by(returned=False).all()

    return render_template('home.html', tech=tech, tools=tools, keys=keys, signouts=signouts, tech_signouts=tech_signouts)


@app.route('/equipment', methods=['GET', 'POST'])
@login_required
def equipment():
    tech_id = session.get('tech_id')
    tech = Technician.query.get(tech_id)

    if tech is None:
        flash('No tech found with the current tech_id')
        return redirect(url_for('error_page'))

    if request.method == 'POST':
        tool_id = request.form.get('tool_id')
        key_id = request.form.get('key_id')

        if tool_id is not None:
            tool = Tool.query.get(tool_id)
            if tool is None:
                flash('Invalid tool ID.')
                return redirect(url_for('error_page'))
            if tool.is_signed_out:
                flash('The tool is already signed out.')
                return redirect(url_for('error_page'))
            tool.is_signed_out = True

        if key_id is not None:
            key = Key.query.get(key_id)
            if key is None:
                flash('Invalid key ID.')
                return redirect(url_for('error_page'))
            if key.is_signed_out:
                flash('The key is already signed out.')
                return redirect(url_for('error_page'))
            key.is_signed_out = True

        # Check that at least one of tool_id and key_id is not None
        if tool_id is None and key_id is None:
            flash('You must sign out either a tool or a key.')
            return redirect(url_for('equipment'))

        signout = Signout(technician_id=tech_id, tool_id=tool_id, key_id=key_id, date_out=datetime.now())
        db.session.add(signout)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('There was an error processing your request.')
            return redirect(url_for('error_page'))

    tools = Tool.query.filter_by(is_signed_out=False).all()
    keys = Key.query.filter_by(is_signed_out=False).all()
    tech_signouts = Signout.query.filter_by(technician_id=tech_id, returned=False).all()
    return render_template('equipment.html', tech=tech, tools=tools, keys=keys, tech_signouts=tech_signouts)


@app.route('/get_equipment', methods=['GET'])
@login_required
def get_equipment():
    tools = Tool.query.filter_by(is_signed_out=False).all()
    keys = Key.query.filter_by(is_signed_out=False).all()
    equipment = [{'id': tool.id, 'name': tool.name, 'type': 'Tool'} for tool in tools]
    equipment.extend([{'id': key.id, 'name': key.name, 'type': 'Key'} for key in keys])
    return jsonify(equipment)


@app.route('/add_group', methods=['GET', 'POST'])
@login_required
def add_group():
    if request.method == 'POST':
        name = request.form.get('name')
        if Group.query.filter_by(name=name).first():
            flash('The group already exists.')
            return redirect(url_for('error_page'))
        new_group = Group(name=name)
        db.session.add(new_group)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('The group already exists.')
            return redirect(url_for('error_page'))
        return redirect(url_for('add_group'))
    return render_template('add_group.html')


@app.route('/add_tool', methods=['GET', 'POST'])
@login_required
def add_tool():
    if request.method == 'POST':
        name = request.form.get('name')
        group_id = request.form.get('group_id')
        group = Group.query.get(group_id)
        if not group:
            flash('The group does not exist.')
            return redirect(url_for('error_page'))
        if Tool.query.filter_by(name=name, group_id=group_id).first():
            flash('The tool already exists in this group.')
            return redirect(url_for('error_page'))
        new_tool = Tool(name=name, group_id=group_id)
        db.session.add(new_tool)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('The tool already exists.')
            return redirect(url_for('error_page'))
        return redirect(url_for('add_tool'))
    groups = Group.query.all()
    return render_template('add_tool.html', groups=groups)


@app.route('/add_key', methods=['GET', 'POST'])
@login_required
def add_key():
    if request.method == 'POST':
        name = request.form.get('name')
        group_id = request.form.get('group_id')
        if Key.query.filter_by(name=name).first():
            flash('The key already exists.')
            return redirect(url_for('error_page'))
        new_key = Key(name=name, group_id=group_id)
        db.session.add(new_key)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('The key already exists.')
            return redirect(url_for('error_page'))
        return redirect(url_for('add_key'))
    groups = Group.query.all()
    return render_template('add_key.html', groups=groups)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        tech = Technician.query.filter_by(name=name).first()
        if tech and tech.check_password(password):
            session['tech_id'] = tech.id
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('error_page'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('tech_id', None)
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        if Technician.query.filter_by(name=name).first():
            flash('A technician with that name already exists. Please use a different name.')
            return redirect(url_for('error_page'))
        tech = Technician(name=name)
        tech.set_password(password)
        db.session.add(tech)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('A technician with that name already exists. Please use a different name.')
            return redirect(url_for('error_page'))
        flash('Account created successfully. Please login with your new account.')
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/return_item', methods=['POST'])
@login_required
def return_item():
    tech_id = session.get('tech_id')
    signout_id = request.form.get('signout_id')
    signout = Signout.query.get(signout_id)

    if not signout or signout.technician_id != tech_id:
        flash("Invalid signout ID or you cannot return an item you didn't sign out.")
        return redirect(url_for('equipment'))

    if signout.returned:
        flash("This item has already been returned.")
        return redirect(url_for('equipment'))

    try:
        if signout.tool_id is not None:
            tool = Tool.query.get(signout.tool_id)
            if tool:
                tool.is_signed_out = False

        if signout.key_id is not None:
            key = Key.query.get(signout.key_id)
            if key:
                key.is_signed_out = False

        signout.returned = True
        signout.date_returned = datetime.now()

        db.session.commit()
        flash("Item returned successfully.")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred while returning the item: {str(e)}")

    return redirect(url_for('equipment'))


@app.route('/testing')
def ui():
    return render_template('testing.html')


@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        name = request.form.get('name')
        item_type = request.form.get('type')
        group_id = request.form.get('group_id')

        # Check if the item already exists in the specified group
        existing_item = None
        if item_type == 'tool':
            existing_item = Tool.query.filter_by(name=name, group_id=group_id).first()
        elif item_type == 'key':
            existing_item = Key.query.filter_by(name=name, group_id=group_id).first()

        if existing_item is not None:
            flash(f"The {item_type} '{name}' already exists in this group.")
            return redirect(url_for('error_page'))

        # Create and add the new item
        if item_type == 'tool':
            new_item = Tool(name=name, group_id=group_id)
        elif item_type == 'key':
            new_item = Key(name=name, group_id=group_id)

        db.session.add(new_item)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash(f"There was an error adding the {item_type}.")
            return redirect(url_for('error_page'))

        return redirect(url_for('add_item'))

    groups = Group.query.all()
    return render_template('add_item.html', groups=groups)


@app.route('/get_tools', methods=['GET'])
@login_required
def get_tools():
    tools = Tool.query.filter_by(is_signed_out=False).all()
    tool_list = [{'id': tool.id, 'name': tool.name} for tool in tools]
    return jsonify(tool_list)


@app.route('/get_keys', methods=['GET'])
@login_required
def get_keys():
    keys = Key.query.filter_by(is_signed_out=False).all()
    key_list = [{'id': key.id, 'name': key.name} for key in keys]
    return jsonify(key_list)


def add_default_tools_and_keys():
    default_tools = ['K400', 'Propress', 'Combustion Analyzer']
    default_keys = ['Canadian', 'Electra', 'OMA', 'Concordia', 'Vine']
    default_group = Group.query.filter_by(name="Default").first()

    if default_group is None:
        default_group = Group(name="Default")
        db.session.add(default_group)
        db.session.commit()

    for tool_name in default_tools:
        if not Tool.query.filter_by(name=tool_name).first():
            new_tool = Tool(name=tool_name, group_id=default_group.id)
            db.session.add(new_tool)

    for key_name in default_keys:
        if not Key.query.filter_by(name=key_name).first():
            new_key = Key(name=key_name, group_id=default_group.id)
            db.session.add(new_key)

    db.session.commit()


@app.route('/search/tools', methods=['GET'])
@login_required
def search_tools():
    search_term = request.args.get('q', '')
    tools = Tool.query.filter(Tool.name.contains(search_term), Tool.is_signed_out == False).all()
    tool_list = [{'id': tool.id, 'name': tool.name} for tool in tools]
    return jsonify(tool_list)


@app.route('/search/keys', methods=['GET'])
@login_required
def search_keys():
    search_term = request.args.get('q', '')
    keys = Key.query.filter(Key.name.contains(search_term), Key.is_signed_out == False).all()
    key_list = [{'id': key.id, 'name': key.name} for key in keys]
    return jsonify(key_list)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        add_default_tools_and_keys()
        app.run(debug=True)
