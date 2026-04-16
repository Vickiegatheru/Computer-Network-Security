from flask import Flask, render_template, request
from crypto_logic import encrypt_m4, decrypt_m4

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    enc_data = {}
    dec_data = {}
    
    if request.method == 'POST':
        if 'msg' in request.form:
            # Encryption request
            msg = request.form['msg']
            mode = request.form.get('mode', 'normal')
            ct, steps = encrypt_m4(msg, tamper=(mode == 'tampered'))
            enc_data = {'ct': ct, 'steps': steps, 'msg': msg}
        elif 'cip' in request.form:
            # Decryption request - also check if we have the original message to re-show encryption
            msg, valid, steps = decrypt_m4(request.form['cip'])
            dec_data = {'msg': msg, 'valid': valid, 'steps': steps}
            
            # If original message was sent via hidden field, re-encrypt to show sender pipeline
            if 'orig_msg' in request.form:
                tamper = request.form.get('orig_tamper', 'normal') == 'tampered'
                ct, enc_steps = encrypt_m4(request.form['orig_msg'], tamper=tamper)
                enc_data = {'ct': ct, 'steps': enc_steps, 'msg': request.form['orig_msg']}
    
    return render_template('index.html', enc=enc_data, dec=dec_data)

if __name__ == '__main__':
    app.run(debug=True)