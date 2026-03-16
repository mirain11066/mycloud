require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ── 設定 ──
const STORAGE = path.resolve(process.env.STORAGE_DIR || './storage');
const MAX_BYTES = (parseInt(process.env.MAX_UPLOAD_MB) || 500) * 1024 * 1024;
const SECRET = process.env.SECRET_KEY || 'change-me';
const PASSWORD = process.env.PASSWORD || 'admin';
const MAX_CONCURRENT = 3; // 同時アップロード上限

if (!fs.existsSync(STORAGE)) fs.mkdirSync(STORAGE, { recursive: true });

// ── アップロードキュー管理 ──
let activeUploads = 0;
const uploadQueue = [];

function processQueue() {
  while (uploadQueue.length > 0 && activeUploads < MAX_CONCURRENT) {
    const { req, res, next } = uploadQueue.shift();
    activeUploads++;
    next();
  }
}

function queueMiddleware(req, res, next) {
  if (activeUploads < MAX_CONCURRENT) {
    activeUploads++;
    next();
  } else {
    uploadQueue.push({ req, res, next });
  }
}

function releaseUpload() {
  activeUploads--;
  processQueue();
}

// ── 認証 ──
function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password !== PASSWORD) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ user: 'owner' }, SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 7 * 86400000 });
  res.json({ success: true, token: token })
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// ── ユーティリティ ──
function safePath(userPath) {
  const resolved = path.resolve(STORAGE, userPath || '');
  if (!resolved.startsWith(STORAGE)) throw new Error('Path traversal blocked');
  return resolved;
}

function getDirectorySize(dirPath) {
  let size = 0;
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        size += getDirectorySize(full);
      } else {
        size += fs.statSync(full).size;
      }
    }
  } catch {}
  return size;
}

// ── Multer設定（ストリーム書き込み） ──
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, _file, cb) => {
      const dir = safePath(req.query.dir || '');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (_req, file, cb) => {
      const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
      cb(null, originalName);
    },
  }),
  limits: { fileSize: MAX_BYTES },
});

// ── API ──

// ファイル一覧
app.get('/api/files', authMiddleware, (req, res) => {
  try {
    const dir = safePath(req.query.path || req.query.dir || '');
    if (!fs.existsSync(dir)) return res.json({ files: [], currentDir: '' });
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    const files = entries
      .filter(e => !e.name.startsWith('.'))
      .map(entry => {
        const fullPath = path.join(dir, entry.name);
        const stats = fs.statSync(fullPath);
        return {
          name: entry.name,
          path: path.relative(STORAGE, fullPath).replace(/\\/g, '/'),
          type: entry.isDirectory() ? 'directory' : 'file',
          size: entry.isDirectory() ? null : stats.size,
          modified: stats.mtime,
          ext: entry.isDirectory() ? null : path.extname(entry.name).toLowerCase().slice(1),
        };
      })
      .sort((a, b) => {
        if (a.type === 'directory' && b.type !== 'directory') return -1;
        if (a.type !== 'directory' && b.type === 'directory') return 1;
        return a.name.localeCompare(b.name);
      });
    res.json({ currentDir: path.relative(STORAGE, dir) || '', files });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});


// ストレージ情報
app.get('/api/storage-info', authMiddleware, (req, res) => {
  const used = getDirectorySize(STORAGE);
  res.json({
    used,
    limit: MAX_BYTES,
    percent: ((used / MAX_BYTES) * 100).toFixed(1),
    activeUploads,
    queueLength: uploadQueue.length,
  });
});

// アップロード（キュー制御付き・1ファイルずつ受付）
app.post('/api/upload', authMiddleware, queueMiddleware, (req, res) => {
  upload.array('files', 100)(req, res, (err) => {
    releaseUpload();
    if (err) {
      console.error('Upload error:', err.message);
      return res.status(500).json({ error: err.message });
    }
    res.json({ success: true, count: req.files.length });
  });
});

// 単一ファイルアップロード（フロントエンドから1ファイルずつ送る用）
app.post('/api/upload-single', authMiddleware, queueMiddleware, (req, res) => {
  upload.single('file')(req, res, (err) => {
    releaseUpload();
    if (err) {
      console.error('Upload error:', err.message);
      return res.status(500).json({ error: err.message });
    }
    res.json({ success: true, name: req.file?.originalname || '' });
  });
});

// アップロード状況確認
app.get('/api/upload-status', authMiddleware, (req, res) => {
  res.json({ activeUploads, queueLength: uploadQueue.length, maxConcurrent: MAX_CONCURRENT });
});

// フォルダ作成
app.post('/api/mkdir', authMiddleware, express.json(), (req, res) => {
  try {
    const folderName = req.body.name;
    if (!folderName) return res.status(400).json({ error: 'Name required' });
    const parentPath = req.body.path || '';
    const fullPath = safePath(parentPath ? parentPath + '/' + folderName : folderName);
    fs.mkdirSync(fullPath, { recursive: true });
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});


// ダウンロード
app.get('/api/download', authMiddleware, (req, res) => {
  try {
    const filePath = safePath(req.query.path);
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      return res.status(404).json({ error: 'Not found' });
    }
    res.download(filePath);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// プレビュー
app.get('/api/preview', authMiddleware, (req, res) => {
  try {
    const filePath = safePath(req.query.path);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
    const ext = path.extname(filePath).toLowerCase();
    const mimeMap = {
      '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
      '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
      '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime',
      '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.ogg': 'audio/ogg', '.flac': 'audio/flac',
      '.pdf': 'application/pdf',
      '.txt': 'text/plain', '.md': 'text/plain', '.json': 'application/json',
      '.js': 'text/plain', '.css': 'text/plain', '.html': 'text/plain',
      '.csv': 'text/plain', '.log': 'text/plain', '.xml': 'text/plain',
    };
    res.setHeader('Content-Type', mimeMap[ext] || 'application/octet-stream');
    fs.createReadStream(filePath).pipe(res);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// 削除
app.delete('/api/delete', authMiddleware, (req, res) => {
  try {
    const target = safePath(req.body.path);
    if (!fs.existsSync(target)) return res.status(404).json({ error: 'Not found' });
    const stats = fs.statSync(target);
    if (stats.isDirectory()) {
      fs.rmSync(target, { recursive: true, force: true });
    } else {
      fs.unlinkSync(target);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// リネーム
app.post('/api/rename', authMiddleware, (req, res) => {
  try {
    const from = safePath(req.body.from);
    const to = safePath(req.body.to);
    if (!fs.existsSync(from)) return res.status(404).json({ error: 'Not found' });
    const toDir = path.dirname(to);
    if (!fs.existsSync(toDir)) fs.mkdirSync(toDir, { recursive: true });
    fs.renameSync(from, to);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// 検索
app.get('/api/search', authMiddleware, (req, res) => {
  const query = (req.query.q || '').toLowerCase();
  if (!query) return res.json({ results: [] });
  const results = [];
  function walk(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      const full = path.join(dir, entry.name);
      if (entry.name.toLowerCase().includes(query)) {
        const stats = fs.statSync(full);
        results.push({
          name: entry.name,
          path: path.relative(STORAGE, full),
          type: entry.isDirectory() ? 'folder' : 'file',
          size: entry.isDirectory() ? null : stats.size,
          modified: stats.mtime,
        });
      }
      if (entry.isDirectory()) walk(full);
    }
  }
  walk(STORAGE);
  res.json({ results: results.slice(0, 100) });
});

// ── 静的ファイル ──
app.use(express.static(path.join(__dirname, 'public')));
app.get('/{*splat}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── 起動 ──
const PORT = process.env.PORT || 3000;
if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(PORT, () => {
    console.log(`☁️  MyCloud running on http://localhost:${PORT}`);
    console.log(`📂 Storage: ${STORAGE}`);
    console.log(`📦 Max upload: ${process.env.MAX_UPLOAD_MB || 500}MB`);
    console.log(`🔄 Max concurrent uploads: ${MAX_CONCURRENT}`);
  });
}
