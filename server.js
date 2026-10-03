import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
const cloudinary = require('cloudinary').v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database(path.join(__dirname, 'in2u.db'));

db.pragma('foreign_keys = ON');

const schemaPath = path.join(__dirname, 'schema.sql');
const schemaSql = await readFile(schemaPath, 'utf8');

if (typeof schemaSql !== 'string') {
  throw new Error('schema.sql could not be read as text');
}

db.exec(schemaSql);

const configuredOrigins = String(process.env.CORS_ORIGIN || '*')
  .split(',')
  .map(x => x.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (
      !origin ||
      configuredOrigins.includes('*') ||
      configuredOrigins.includes(origin)
    ) {
      return callback(null, true);
    }

    return callback(new Error('Origin not allowed by CORS'));
  },
  credentials: false,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET =
  process.env.JWT_SECRET || 'dev-only-change-this-secret';

const publicUser = u => ({
  id: u.id,
  name: u.name,
  username: u.username,
  email: u.email,
  bio: u.bio,
  photoUrl: u.photo_url,
  isPrivate: !!u.is_private,
  allowMessages: !!u.allow_messages,
  approveFollowers: !!u.approve_followers,
  showFollowers: !!u.show_followers,
  showFollowing: !!u.show_following
});

function tokenFor(u) {
  return jwt.sign(
    { sub: u.id },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';

    if (!h.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Authentication required'
      });
    }

    req.userId = jwt.verify(
      h.slice(7),
      JWT_SECRET
    ).sub;

    next();
  } catch {
    return res.status(401).json({
      error: 'Invalid or expired token'
    });
  }
}

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'In2U backend',
    time: new Date().toISOString()
  });
});

app.post('/api/auth/signup', async (req, res) => {
  const {
    name,
    email,
    password,
    username
  } = req.body || {};

  if (!name || !email || !password) {
    return res.status(400).json({
      error: 'Name, email and password are required'
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters'
    });
  }

  const cleanEmail = String(email)
    .trim()
    .toLowerCase();

  const cleanUsername =
    String(username || name)
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, '')
      .slice(0, 30) ||
    `user${Date.now()}`;

  try {
    const hash = await bcrypt.hash(password, 12);

    const info = db
      .prepare(
        'INSERT INTO users(name,username,email,password_hash) VALUES(?,?,?,?)'
      )
      .run(
        String(name).trim(),
        cleanUsername,
        cleanEmail,
        hash
      );

    const u = db
      .prepare('SELECT * FROM users WHERE id=?')
      .get(info.lastInsertRowid);

    res.status(201).json({
      token: tokenFor(u),
      user: publicUser(u)
    });
  } catch (e) {
    res.status(409).json({
      error:
        e.message.includes('users.email')
          ? 'Email already in use'
          : e.message.includes('users.username')
            ? 'Username already in use'
            : 'Account could not be created'
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const {
    email,
    password
  } = req.body || {};

  const u = db
    .prepare('SELECT * FROM users WHERE email=?')
    .get(
      String(email || '')
        .trim()
        .toLowerCase()
    );

  if (
    !u ||
    !(await bcrypt.compare(
      String(password || ''),
      u.password_hash
    ))
  ) {
    return res.status(401).json({
      error: 'Invalid email or password'
    });
  }

  res.json({
    token: tokenFor(u),
    user: publicUser(u)
  });
});

app.get('/api/me', auth, (req, res) => {
  const u = db
    .prepare('SELECT * FROM users WHERE id=?')
    .get(req.userId);

  res.json({
    user: publicUser(u)
  });
});

app.patch('/api/me', auth, (req, res) => {
  const u = db
    .prepare('SELECT * FROM users WHERE id=?')
    .get(req.userId);

  if (!u) {
    return res.status(404).json({
      error: 'User not found'
    });
  }

  const b = req.body || {};

  const vals = {
    name: b.name ?? u.name,
    username: b.username ?? u.username,
    bio: b.bio ?? u.bio,
    photo_url: b.photoUrl ?? u.photo_url,

    is_private:
      b.isPrivate === undefined
        ? u.is_private
        : +!!b.isPrivate,

    allow_messages:
      b.allowMessages === undefined
        ? u.allow_messages
        : +!!b.allowMessages,

    approve_followers:
      b.approveFollowers === undefined
        ? u.approve_followers
        : +!!b.approveFollowers,

    show_followers:
      b.showFollowers === undefined
        ? u.show_followers
        : +!!b.showFollowers,

    show_following:
      b.showFollowing === undefined
        ? u.show_following
        : +!!b.showFollowing
  };

  try {
    db.prepare(`
      UPDATE users
      SET
        name=?,
        username=?,
        bio=?,
        photo_url=?,
        is_private=?,
        allow_messages=?,
        approve_followers=?,
        show_followers=?,
        show_following=?
      WHERE id=?
    `).run(
      vals.name,
      vals.username,
      vals.bio,
      vals.photo_url,
      vals.is_private,
      vals.allow_messages,
      vals.approve_followers,
      vals.show_followers,
      vals.show_following,
      req.userId
    );

    res.json({
      user: publicUser(
        db
          .prepare('SELECT * FROM users WHERE id=?')
          .get(req.userId)
      )
    });
  } catch {
    res.status(409).json({
      error: 'Username may already be in use'
    });
  }
});

app.get('/api/users/:username', auth, (req, res) => {
  const u = db
    .prepare('SELECT * FROM users WHERE username=?')
    .get(req.params.username.toLowerCase());

  if (!u) {
    return res.status(404).json({
      error: 'User not found'
    });
  }

  const followers = db
    .prepare(`
      SELECT COUNT(*) n
      FROM follows
      WHERE following_id=?
      AND status='accepted'
    `)
    .get(u.id).n;

  const following = db
    .prepare(`
      SELECT COUNT(*) n
      FROM follows
      WHERE follower_id=?
      AND status='accepted'
    `)
    .get(u.id).n;

  res.json({
    user: {
      ...publicUser(u),
      followers,
      following
    }
  });
});

app.post('/api/users/:id/follow', auth, (req, res) => {
  const target = Number(req.params.id);

  if (target === req.userId) {
    return res.status(400).json({
      error: 'You cannot follow yourself'
    });
  }

  const u = db
    .prepare('SELECT * FROM users WHERE id=?')
    .get(target);

  if (!u) {
    return res.status(404).json({
      error: 'User not found'
    });
  }

  const status = u.approve_followers
    ? 'pending'
    : 'accepted';

  db.prepare(`
    INSERT INTO follows(
      follower_id,
      following_id,
      status
    )
    VALUES(?,?,?)
    ON CONFLICT(follower_id,following_id)
    DO UPDATE SET status=excluded.status
  `).run(
    req.userId,
    target,
    status
  );

  res.json({ status });
});

app.delete('/api/users/:id/follow', auth, (req, res) => {
  db.prepare(`
    DELETE FROM follows
    WHERE follower_id=?
    AND following_id=?
  `).run(
    req.userId,
    Number(req.params.id)
  );

  res.json({ ok: true });
});

app.get('/api/users/:id/followers', auth, (req, res) => {
  const u = db
    .prepare('SELECT * FROM users WHERE id=?')
    .get(Number(req.params.id));

  if (!u) {
    return res.status(404).json({
      error: 'User not found'
    });
  }

  if (
    u.is_private &&
    Number(req.params.id) !== req.userId &&
    !u.show_followers
  ) {
    return res.status(403).json({
      error: 'Followers list is private'
    });
  }

  const rows = db
    .prepare(`
      SELECT u.*
      FROM users u
      JOIN follows f
        ON f.follower_id=u.id
      WHERE f.following_id=?
      AND f.status='accepted'
      ORDER BY f.created_at DESC
    `)
    .all(u.id);

  res.json({
    users: rows.map(publicUser)
  });
});

app.get('/api/users/:id/following', auth, (req, res) => {
  const u = db
    .prepare('SELECT * FROM users WHERE id=?')
    .get(Number(req.params.id));

  if (!u) {
    return res.status(404).json({
      error: 'User not found'
    });
  }

  if (
    u.is_private &&
    Number(req.params.id) !== req.userId &&
    !u.show_following
  ) {
    return res.status(403).json({
      error: 'Following list is private'
    });
  }

  const rows = db
    .prepare(`
      SELECT u.*
      FROM users u
      JOIN follows f
        ON f.following_id=u.id
      WHERE f.follower_id=?
      AND f.status='accepted'
      ORDER BY f.created_at DESC
    `)
    .all(u.id);

  res.json({
    users: rows.map(publicUser)
  });
});

app.post('/api/posts', auth, (req, res) => {
  const {
    caption = '',
    media = []
  } = req.body || {};

  const tx = db.transaction(() => {
    const p = db
      .prepare(
        'INSERT INTO posts(user_id,caption) VALUES(?,?)'
      )
      .run(
        req.userId,
        String(caption)
      );

    const add = db.prepare(`
      INSERT INTO post_media(
        post_id,
        url,
        sort_order
      )
      VALUES(?,?,?)
    `);

    (Array.isArray(media) ? media : [])
      .slice(0, 5)
      .forEach((url, i) => {
        add.run(
          p.lastInsertRowid,
          String(url),
          i
        );
      });

    return p.lastInsertRowid;
  });

  const id = tx();

  res.status(201).json({
    post: db
      .prepare('SELECT * FROM posts WHERE id=?')
      .get(id)
  });
});

app.get('/api/feed', auth, (req, res) => {
  const rows = db
    .prepare(`
      SELECT
        p.id,
        p.caption,
        p.created_at,
        u.id user_id,
        u.name,
        u.username,
        u.photo_url
      FROM posts p
      JOIN users u
        ON u.id=p.user_id
      ORDER BY p.created_at DESC
      LIMIT 100
    `)
    .all();

  const media = db
    .prepare(`
      SELECT post_id,url
      FROM post_media
      ORDER BY sort_order
    `)
    .all();

  const map = {};

  for (const m of media) {
    (map[m.post_id] ??= []).push(m.url);
  }

  const reactions = db
    .prepare(`
      SELECT post_id,user_id,emoji
      FROM reactions
      ORDER BY created_at
    `)
    .all();

  const reactionMap = {};

  for (const r of reactions) {
    const x =
      reactionMap[r.post_id] ??= {
        counts: {},
        users: {}
      };

    x.counts[r.emoji] =
      (x.counts[r.emoji] || 0) + 1;

    (x.users[r.emoji] ??= [])
      .push(r.user_id);
  }

  const comments = db
    .prepare(`
      SELECT
        c.id,
        c.post_id,
        c.user_id,
        c.parent_id,
        c.text,
        c.created_at,
        u.name,
        u.username,
        u.photo_url
      FROM comments c
      JOIN users u
        ON u.id=c.user_id
      ORDER BY c.created_at
    `)
    .all();

  const commentMap = {};

  for (const c of comments) {
    (commentMap[c.post_id] ??= []).push({
      id: c.id,
      user: c.name,
      text: c.text,
      reactions: {},
      replies: [],
      parentId: c.parent_id
    });
  }

  for (const p of rows) {
    const arr = commentMap[p.id] || [];

    const byId = Object.fromEntries(
      arr.map(c => [c.id, c])
    );

    for (const c of arr) {
      if (
        c.parentId &&
        byId[c.parentId]
      ) {
        byId[c.parentId]
          .replies
          .push(c);
      }
    }

    commentMap[p.id] =
      arr
        .filter(c => !c.parentId)
        .map(c => {
          delete c.parentId;
          return c;
        });
  }

  const posts = rows.map(p => {
    const r =
      reactionMap[p.id] || {
        counts: {},
        users: {}
      };

    const reactionUsers =
      Object.fromEntries(
        Object.entries(r.users).map(
          ([e, ids]) => [
            e,
            ids.map(id => {
              const u = db
                .prepare(`
                  SELECT
                    name,
                    username,
                    photo_url
                  FROM users
                  WHERE id=?
                `)
                .get(id);

              return {
                name: u?.name || 'User',
                handle:
                  '@' +
                  (u?.username || 'user'),
                photo:
                  u?.photo_url || ''
              };
            })
          ]
        )
      );

    return {
      ...p,
      media: map[p.id] || [],
      reactions: r.counts,
      reactionUsers,
      comments:
        commentMap[p.id] || []
    };
  });

  res.json({ posts });
});

app.post(
  '/api/posts/:id/reactions',
  auth,
  (req, res) => {
    const emoji =
      String(
        req.body?.emoji || '❤️'
      );

    db.prepare(`
      INSERT INTO reactions(
        user_id,
        post_id,
        emoji
      )
      VALUES(?,?,?)
      ON CONFLICT(user_id,post_id)
      DO UPDATE SET emoji=excluded.emoji
    `).run(
      req.userId,
      Number(req.params.id),
      emoji
    );

    res.json({ ok: true });
  }
);

app.post(
  '/api/posts/:id/comments',
  auth,
  (req, res) => {
    const text =
      String(
        req.body?.text || ''
      ).trim();

    if (!text) {
      return res.status(400).json({
        error: 'Comment is required'
      });
    }

    const info = db
      .prepare(`
        INSERT INTO comments(
          post_id,
          user_id,
          parent_id,
          text
        )
        VALUES(?,?,?,?)
      `)
      .run(
        Number(req.params.id),
        req.userId,
        req.body?.parentId || null,
        text
      );

    res.status(201).json({
      id: info.lastInsertRowid
    });
  }
);

app.use((err, req, res, next) => {
  console.error(err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(err.status || 500).json({
    error: err.message || 'Server error'
  });
});

app.listen(
  process.env.PORT || 3000,
  '0.0.0.0',
  () =>
    console.log(
      `In2U backend running on port ${
        process.env.PORT || 3000
      }`
    )
);
