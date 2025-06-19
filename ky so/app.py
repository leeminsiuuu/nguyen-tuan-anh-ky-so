from flask import Flask, request, send_file, jsonify, render_template_string, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import uuid
import base64

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

KEY_FILE = "private.pem"
if not os.path.exists(KEY_FILE):
    key = RSA.generate(2048)
    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem", "wb") as f:
        f.write(key.publickey().export_key())
else:
    key = RSA.import_key(open("private.pem").read())
public_key = key.publickey()

files_db = {}

# --------------------- Giao diện gửi ---------------------
SEND_HTML = """<!DOCTYPE html>
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>🔐 Ký Số Tập Tin</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <link href="https://fonts.googleapis.com/css2?family=Rubik:wght@400;600&display=swap" rel="stylesheet">
  <style>
    body {
      margin: 0;
      font-family: 'Rubik', sans-serif;
      background: url('https://images.unsplash.com/photo-1593642532973-d31b6557fa68?fit=crop&w=1920&q=80') no-repeat center center fixed;
      background-size: cover;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .glass-card {
      background: rgba(255, 255, 255, 0.15);
      backdrop-filter: blur(12px);
      border-radius: 20px;
      padding: 40px;
      width: 100%;
      max-width: 550px;
      color: #fff;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
    }
    .glass-card h2 {
      font-weight: 600;
      margin-bottom: 25px;
      text-align: center;
    }
    .btn-upload {
      width: 100%;
      padding: 12px;
      font-size: 1rem;
      border-radius: 10px;
      font-weight: bold;
    }
    .status-box {
      margin-top: 20px;
      background-color: rgba(255, 255, 255, 0.1);
      padding: 15px;
      border-radius: 12px;
      word-break: break-word;
      font-size: 0.95rem;
    }
    input[type="file"] {
      background-color: rgba(255, 255, 255, 0.9);
      border-radius: 8px;
      padding: 10px;
    }
    .nav-link {
      color: #fff;
      text-align: center;
      display: block;
      margin-top: 15px;
      text-decoration: underline;
    }
    textarea {
      width: 100%;
      border-radius: 8px;
      margin-top: 10px;
      background-color: #f8f9fa;
    }
  </style>
</head>
<body>

<div class="glass-card">
  <h2>📁 Tải Lên & Ký Số Tập Tin</h2>
  <form id="sendForm">
    <div class="mb-3">
      <input type="file" class="form-control" id="sendFile" required />
    </div>
    <button type="submit" class="btn btn-light btn-upload">🔐 Gửi & Ký Số</button>
  </form>

  <div id="sendStatus" class="status-box mt-3"></div>
  <a href="/receive" class="nav-link">📥 Xem & Kiểm Tra File Đã Gửi</a>
</div>

<script>
const sendForm = document.getElementById('sendForm');
const sendStatus = document.getElementById('sendStatus');

sendForm.addEventListener('submit', async e => {
  e.preventDefault();
  const fileInput = document.getElementById('sendFile');
  if (fileInput.files.length === 0) return alert("Vui lòng chọn file.");

  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append("file", file);

  sendStatus.innerHTML = `🕐 Đang xử lý file...`;

  const resp = await fetch('/api/upload', { method: 'POST', body: formData });
  const data = await resp.json();

  if (resp.ok) {
    sendStatus.innerHTML = `
      ✅ Gửi thành công!<br>
      <strong>🆔 ID:</strong> ${data.file_id}<br>
      <strong>✍️ Chữ ký:</strong>
      <textarea rows="3" readonly>${data.signature}</textarea>
      <button class="btn btn-sm btn-outline-light mt-2" onclick="navigator.clipboard.writeText('${data.signature}')">📋 Sao chép</button><br>
      <a class="btn btn-sm btn-outline-light mt-2" onclick="getPublicKey()">🔓 Xem khóa công khai</a>
      <pre id="pubkeyBox" style="display:none;" class="bg-light text-dark p-2 rounded mt-2"></pre>
    `;
  } else {
    sendStatus.innerHTML = "❌ Lỗi khi gửi file!";
  }
});

async function getPublicKey() {
  const resp = await fetch('/public_key');
  if (resp.ok) {
    const pubkey = await resp.text();
    const box = document.getElementById('pubkeyBox');
    box.style.display = 'block';
    box.textContent = pubkey;
  }
}
</script>
</body>
</html>


"""
# --------------------- Giao diện nhận ---------------------
RECEIVE_HTML = """
<!DOCTYPE html>
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>📥 Nhận File & Kiểm Tra</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    body {
      background-color: #0f2027;
      background-image: linear-gradient(to right, #2c5364, #203a43, #0f2027);
      color: #fff;
      font-family: 'Segoe UI', sans-serif;
      padding: 40px;
    }
    .file-list {
      max-width: 800px;
      margin: auto;
      background: #1a1a1a;
      padding: 30px;
      border-radius: 16px;
      box-shadow: 0 0 20px rgba(0,0,0,0.5);
    }
    .file-item {
      border-bottom: 1px solid #444;
      padding: 15px 0;
    }
    .file-item:last-child {
      border-bottom: none;
    }
    .file-item small {
      display: block;
      font-size: 0.85rem;
      color: #bbb;
    }
    .btn-sm {
      font-size: 0.8rem;
      margin-top: 5px;
      border-radius: 6px;
    }
  </style>
</head>
<body>
<div class="file-list">
  <h2 class="mb-4">📂 Danh Sách File Đã Gửi</h2>
  <a href="/send" class="btn btn-outline-light mb-4">🔼 Trở Lại Gửi File</a>
  <div id="fileList"></div>
  <div id="verifyStatus" class="mt-3"></div>
</div>

<script>
async function loadFileList() {
  const resp = await fetch('/api/files');
  const files = await resp.json();
  const fileList = document.getElementById('fileList');
  fileList.innerHTML = '';

  if (files.length === 0) {
    fileList.innerHTML = '<p class="text-muted">Chưa có file nào được gửi.</p>';
    return;
  }

  files.forEach(f => {
    const div = document.createElement('div');
    div.className = 'file-item';
    div.innerHTML = `
      <strong>${f.filename}</strong>
      <small>🆔 ${f.file_id}</small>
      <small>⏰ ${new Date(f.timestamp * 1000).toLocaleString()}</small>
      <button class="btn btn-sm btn-outline-success me-2" onclick="downloadFile('${f.file_id}')">⬇️ Tải</button>
      <button class="btn btn-sm btn-outline-info" onclick="verifyFile('${f.file_id}')">🔍 Kiểm Tra</button>
    `;
    fileList.appendChild(div);
  });
}

async function downloadFile(file_id) {
  window.open(`/download/${file_id}`, '_blank');
}

async function verifyFile(file_id) {
  const verifyStatus = document.getElementById('verifyStatus');
  verifyStatus.innerHTML = "🕵️‍♂️ Đang xác minh...";
  const resp = await fetch(`/api/verify/${file_id}`);
  const data = await resp.json();
  verifyStatus.innerHTML = data.valid
    ? '<div class="alert alert-success mt-3">✅ Chữ ký hợp lệ!</div>'
    : '<div class="alert alert-danger mt-3">❌ Chữ ký không hợp lệ!</div>';
}

loadFileList();
</script>
</body>
</html>


"""

# --------------------- Các route Flask ---------------------

@app.route("/")
def home():
    return redirect(url_for("send"))

@app.route("/send")
def send():
    return render_template_string(SEND_HTML)

@app.route("/receive")
def receive():
    return render_template_string(RECEIVE_HTML)

@app.route("/api/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file"}), 400

    data = file.read()
    hash_obj = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(hash_obj)
    signature_b64 = base64.b64encode(signature).decode()

    file_id = str(uuid.uuid4())
    filename = file.filename
    file_path = os.path.join(UPLOAD_FOLDER, f"{file_id}_{filename}")
    sig_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.sig")

    with open(file_path, "wb") as f:
        f.write(data)
    with open(sig_path, "wb") as f:
        f.write(signature)

    files_db[file_id] = {
        "filename": filename,
        "filepath": file_path,
        "sigpath": sig_path,
        "timestamp": os.path.getmtime(file_path)
    }

    return jsonify({"file_id": file_id, "signature": signature_b64})

@app.route("/api/files")
def list_files():
    return jsonify([
        {"file_id": fid, "filename": info["filename"], "timestamp": info["timestamp"]}
        for fid, info in files_db.items()
    ])

@app.route("/download/<file_id>")
def download(file_id):
    info = files_db.get(file_id)
    if not info:
        return "File not found", 404
    return send_file(info["filepath"], as_attachment=True, download_name=info["filename"])

@app.route("/api/verify/<file_id>")
def verify(file_id):
    info = files_db.get(file_id)
    if not info:
        return jsonify({"valid": False}), 404

    with open(info["filepath"], "rb") as f: #Đọc file
        data = f.read()
    with open(info["sigpath"], "rb") as f: #Đọc chữ ký
        signature = f.read()

    h = SHA256.new(data) #Tạo hàm băm mới 
    try:
        pkcs1_15.new(public_key).verify(h, signature) #So sánh hàm băm với chữ ký
        return jsonify({"valid": True})
    except (ValueError, TypeError):
        return jsonify({"valid": False})

@app.route("/public_key")
def get_public_key():
    return public_key.export_key().decode()

if __name__ == "__main__":
    app.run(host="172.16.19.95", port=5000, debug=True)
