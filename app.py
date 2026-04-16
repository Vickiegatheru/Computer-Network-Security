from flask import Flask, render_template, request, session
from crypto_logic import encrypt_m4, decrypt_m4

app = Flask(__name__)
app.secret_key = 'dev_key_secure'

@app.route('/', methods=['GET', 'POST'])
def home():
    enc_data = session.get('enc_data', {})
    dec_data = {}
    
    if request.method == 'POST':
        if 'msg' in request.form:
            ct, steps = encrypt_m4(request.form['msg'])
            enc_data = {'ct': ct, 'steps': steps}
            session['enc_data'] = enc_data
        elif 'cip' in request.form:
            msg, valid, steps = decrypt_m4(request.form['cip'])
            dec_data = {'msg': msg, 'valid': valid, 'steps': steps}
    
    return render_template('index.html', enc=enc_data, dec=dec_data)

if __name__ == '__main__':
    app.run(debug=True)