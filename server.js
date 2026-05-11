require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Cloudinary ───────────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ─── PostgreSQL ───────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// ─── Middleware ───────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// multer: хранение в памяти (не на диск)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 }, // 500MB макс
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('video/')) cb(null, true);
    else cb(new Error('Только видео файлы'), false);
  },
});

// ─── JWT helper ───────────────────────────────────────────────
const SECRET = process.env.JWT_SECRET || 'cosmovibe_secret_key';

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Нет токена' });
  const token = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Токен недействителен' });
  }
}

// ─── БД: инициализация таблиц ─────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      avatar_url VARCHAR(500) DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS videos (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(200) NOT NULL,
      description TEXT DEFAULT '',
      category VARCHAR(50) DEFAULT 'other',
      cloudinary_id VARCHAR(300) NOT NULL,
      video_url VARCHAR(500) NOT NULL,
      thumbnail_url VARCHAR(500) DEFAULT '',
      duration INTEGER DEFAULT 0,
      views INTEGER DEFAULT 0,
      likes INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS likes (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
      PRIMARY KEY (user_id, video_id)
    );

    CREATE INDEX IF NOT EXISTS idx_videos_user ON videos(user_id);
    CREATE INDEX IF NOT EXISTS idx_videos_category ON videos(category);
    CREATE INDEX IF NOT EXISTS idx_videos_created ON videos(created_at DESC);
  `);
  console.log('✅ БД инициализирована');
}

// ─── ROUTES: Auth ─────────────────────────────────────────────

// Регистрация
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'Заполни все поля' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Пароль минимум 6 символов' });

    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1,$2,$3) RETURNING id, username, email',
      [username.trim(), email.trim().toLowerCase(), hash]
    );
    const token = jwt.sign({ id: rows[0].id, username: rows[0].username }, SECRET, { expiresIn: '30d' });
    res.json({ token, user: rows[0] });
  } catch (e) {
    if (e.code === '23505') {
      const field = e.detail.includes('username') ? 'Имя пользователя' : 'Email';
      return res.status(400).json({ error: `${field} уже занят` });
    }
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Вход
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email.trim().toLowerCase()]);
    if (!rows.length) return res.status(400).json({ error: 'Пользователь не найден' });

    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(400).json({ error: 'Неверный пароль' });

    const token = jwt.sign({ id: rows[0].id, username: rows[0].username }, SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: rows[0].id, username: rows[0].username, email: rows[0].email } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Текущий пользователь
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, email, avatar_url, created_at FROM users WHERE id=$1', [req.user.id]);
  res.json(rows[0]);
});

// ─── ROUTES: Videos ───────────────────────────────────────────

// Загрузка видео
app.post('/api/videos/upload', authMiddleware, upload.single('video'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не выбран' });

  try {
    const { title, description, category } = req.body;
    if (!title) return res.status(400).json({ error: 'Укажи название' });

    // Загружаем в Cloudinary через stream
    const uploadResult = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        {
          resource_type: 'video',
          folder: 'cosmovibe',
          eager: [{ width: 480, crop: 'scale' }],   // оптимизация
          eager_async: true,
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      streamifier.createReadStream(req.file.buffer).pipe(stream);
    });

    // Thumbnail — берём из Cloudinary автоматически
    const thumbUrl = cloudinary.url(uploadResult.public_id, {
      resource_type: 'video',
      format: 'jpg',
      transformation: [{ width: 640, crop: 'scale' }, { start_offset: '1' }],
    });

    const { rows } = await pool.query(
      `INSERT INTO videos (user_id, title, description, category, cloudinary_id, video_url, thumbnail_url, duration)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [
        req.user.id,
        title.trim(),
        description || '',
        category || 'other',
        uploadResult.public_id,
        uploadResult.secure_url,
        thumbUrl,
        Math.round(uploadResult.duration || 0),
      ]
    );

    res.json({ video: rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка загрузки: ' + e.message });
  }
});

// Список видео (с поиском, фильтром, пагинацией)
app.get('/api/videos', async (req, res) => {
  try {
    const { category, search, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    let where = [];
    let params = [];
    let i = 1;

    if (category && category !== 'all') {
      where.push(`v.category=$${i++}`);
      params.push(category);
    }
    if (search) {
      where.push(`(v.title ILIKE $${i} OR v.description ILIKE $${i})`);
      params.push(`%${search}%`);
      i++;
    }

    const whereStr = where.length ? 'WHERE ' + where.join(' AND ') : '';
    params.push(Number(limit), Number(offset));

    const { rows } = await pool.query(
      `SELECT v.*, u.username, u.avatar_url
       FROM videos v
       JOIN users u ON u.id = v.user_id
       ${whereStr}
       ORDER BY v.created_at DESC
       LIMIT $${i} OFFSET $${i+1}`,
      params
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Одно видео + инкремент просмотров
app.get('/api/videos/:id', async (req, res) => {
  try {
    await pool.query('UPDATE videos SET views=views+1 WHERE id=$1', [req.params.id]);
    const { rows } = await pool.query(
      `SELECT v.*, u.username, u.avatar_url FROM videos v JOIN users u ON u.id=v.user_id WHERE v.id=$1`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Видео не найдено' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Удаление видео
app.delete('/api/videos/:id', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM videos WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    if (!rows.length) return res.status(403).json({ error: 'Нет доступа' });

    await cloudinary.uploader.destroy(rows[0].cloudinary_id, { resource_type: 'video' });
    await pool.query('DELETE FROM videos WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Лайк
app.post('/api/videos/:id/like', authMiddleware, async (req, res) => {
  try {
    const vid = parseInt(req.params.id);
    const uid = req.user.id;
    const { rows } = await pool.query('SELECT 1 FROM likes WHERE user_id=$1 AND video_id=$2', [uid, vid]);
    if (rows.length) {
      await pool.query('DELETE FROM likes WHERE user_id=$1 AND video_id=$2', [uid, vid]);
      await pool.query('UPDATE videos SET likes=likes-1 WHERE id=$1', [vid]);
      res.json({ liked: false });
    } else {
      await pool.query('INSERT INTO likes VALUES ($1,$2)', [uid, vid]);
      await pool.query('UPDATE videos SET likes=likes+1 WHERE id=$1', [vid]);
      res.json({ liked: true });
    }
  } catch (e) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Видео конкретного пользователя
app.get('/api/users/:id/videos', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT v.*, u.username FROM videos v JOIN users u ON u.id=v.user_id WHERE v.user_id=$1 ORDER BY v.created_at DESC`,
    [req.params.id]
  );
  res.json(rows);
});

// ─── SPA fallback ─────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 CosmоVibe запущен на порту ${PORT}`));
}).catch(e => {
  console.error('Ошибка БД:', e);
  process.exit(1);
});
