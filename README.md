# Hashing and Message Authentication

This project is a functional implementation of **Authenticated Encryption** based on the logic from the Cryptography and Network Security curriculum. It demonstrates how to combine Hashing, Secret Salting, and Symmetric Encryption to ensure data **Confidentiality**, **Integrity**, and **Authenticity**.

## 🚀 Features
* **Logic:** Implements the $E(K, [M || H(M || S)])$ pipeline.
* **Cybersecurity Dashboard:** A clean, terminal-style web interface built with Flask.
* **Real-time Process Logs:** Displays the step-by-step mathematical transformations (Hashing -> Concatenation -> Encryption).
* **Tamper Detection:** Automatically detects if a single bit of the ciphertext has been altered and triggers a security alert.

## 🛠 How it Works
1.  **Authentication:** The message ($M$) is concatenated with a shared secret ($S$) and hashed ($H$) using SHA-256.
2.  **Encapsulation:** The resulting hash is appended to the original plaintext message.
3.  **Confidentiality:** The entire package is encrypted using **AES-128 (CBC Mode)** with a symmetric key ($K$).
4.  **Verification:** The receiver decrypts the package, re-calculates the hash using the shared secret, and compares it to the received hash to verify integrity.

## 💻 Tech Stack
* **Language:** Python 3.12
* **Web Framework:** Flask
* **Cryptography:** `cryptography` (Python library)
* **Styling:** Modern CSS (Neon-Green Terminal Theme)

## 🔧 Installation & Local Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Vickiegatheru/Computer-Network-Security.git](https://github.com/Vickiegatheru/Computer-Network-Security.git)
    cd Computer-Network-Security
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    .\venv\bin\Activate.ps1  # Windows PowerShell
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the application:**
    ```bash
    python app.py
    ```
5.  **Access the app:** Open `http://127.0.0.1:5000` in your browser.

## 🧪 Testing Integrity
To test the "Message Authentication" part of the project:
1.  Encrypt a message to get the ciphertext.
2.  Paste the ciphertext into the Receiver box.
3.  **Change one character** in the ciphertext string.
4.  Click "Execute Decrypt." The system will display a **"TAMPERED / INVALID"** security alert.

---
*Created as part of the Computer Network Security coursework.*
