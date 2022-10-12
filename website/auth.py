from flask import Blueprint, render_template, request, flash

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    return render_template("login.html")


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if len(email) < 4:
            flash('Email inválido: tamanho deve ser maior de 4 caracteres', category='error')
        elif len(firstName) < 2:
            flash('Nome inválido: tamanho deve ser maior que 2 caracteres', category='error')
        elif password1 != password2:
            flash('Senhas diferentes', category='error')
        elif len(password1) < 8:
            flash('Senha pequena: a senha deve possuir mais de 8 caracteres', category='error')
        else:
            flash('Conta criada com sucesso!', category='success')

    return render_template("sign_up.html")


@auth.route('/logout')
def logout():
    return 'logout'
