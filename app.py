from flask import Flask, render_template, request
from crypto_logic import encrypt_m4, decrypt_m4

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    res_enc, res_dec, valid = None, None, None
    if request.method == 'POST':
        if 'msg' in request.form: 
            res_enc = encrypt_m4(request.form['msg'])
        if 'cip' in request.form: 
            res_dec, valid = decrypt_m4(request.form['cip'])
    return render_template('index.html', enc=res_enc, dec=res_dec, status=valid)

if __name__ == '__main__':
    app.run(debug=True)