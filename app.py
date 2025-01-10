import bcrypt
from flask import Flask,render_template,request,url_for,redirect,flash,session
from flask_mysqldb import MySQL
app=Flask(__name__)

app.secret_key="your_secret_key"
app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']=''
app.config['MYSQL_DB']='authcheck'

mysql=MySQL(app)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        name=request.form["name"]
        password=request.form["password"]

        cur=mysql.connection.cursor()
        cur.execute("SELECT password FROM users WHERE name = %s ",(name,))
        user=cur.fetchone()
        cur.close()

        if user and bcrypt.checkpw(password,user[0].encode('utf-8')):
            session['name']=name
            flash('Login successfully','success')
            return redirect(url_for('main'))
        else:
            flash('Invalid username or password','danger')

    return render_template("login.html")

@app.route("/register",methods=["POST","GET"])
def register():
    if request.method=="POST":
        name=request.form["name"]
        password=request.form["password"]
        confirm_password=request.form["confirm_password"]

        if password != confirm_password:
            flash('password does not match','danger')
            return redirect(url_for("register"))
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cur=mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE name = %s ",(name,))
        existing_user=cur.fetchone()

        if existing_user:
            flash('username already exists','danger')
            cur.close()
            return redirect(url_for("register"))
        
        cur.execute("INSERT INTO users (name, password) VALUES (%s, %s)", (name, hashed_password.decode('utf-8')))
        mysql.connection.commit()
        cur.close()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template("register.html")

@app.route("/main")
def main():
    if 'name' not in session:
        flash('Please log in to access the dashboard.', 'info')
        return redirect(url_for('login'))
    return render_template("main.html", name=session['name'])
    
@app.route('/logout')
def logout():
    session.pop('name', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


if __name__=="__main__":
    app.run(debug=True)
    

