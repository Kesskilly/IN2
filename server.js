import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = String(
  process.env.JWT_SECRET || 'change-this-in2u-secret'
);

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '40mb' }));

const db = new Database('in2u.db');
db.pragma('journal_mode = WAL');

/* =========================
   DATABASE
========================= */

function ensureSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      bio TEXT DEFAULT '',
      photo_url TEXT DEFAULT '',
      is_private INTEGER DEFAULT 0,
      allow_messages INTEGER DEFAULT 1,
      approve_followers INTEGER DEFAULT 0,
      show_followers INTEGER DEFAULT 1,
      show_following INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS posts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      caption TEXT DEFAULT '',
      media_json TEXT DEFAULT '[]',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reactions(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      emoji TEXT NOT NULL,
      UNIQUE(post_id,user_id,emoji)
    );

    CREATE TABLE IF NOT EXISTS comments(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      text TEXT NOT NULL,
      parent_id INTEGER DEFAULT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS follows(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      follower_id INTEGER NOT NULL,
      following_id INTEGER NOT NULL,
      status TEXT DEFAULT 'accepted',
      UNIQUE(follower_id,following_id)
    );
  `);
}

ensureSchema();

/* =========================
   MULTER
========================= */

const upload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 100 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {
    const mime = String(file.mimetype || '');

    const allowed =
      /^(image|video|audio)\//i.test(mime);

    if (!allowed) {
      return cb(
        new Error(
          'Only image, video and audio files are supported'
        )
      );
    }

    cb(null, true);
  }
});

/* =========================
   CLOUDINARY
========================= */

function configureCloudinary() {
  const cloudName = String(
    process.env.CLOUDINARY_CLOUD_NAME || ''
  ).trim();

  const apiKey = String(
    process.env.CLOUDINARY_API_KEY || ''
  ).trim();

  const apiSecret = String(
    process.env.CLOUDINARY_API_SECRET || ''
  ).trim();

  if (!cloudName || !apiKey || !apiSecret) {
    console.error(
      'Cloudinary is NOT configured. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET in Render.'
    );

    return false;
  }

  cloudinary.config({
    cloud_name: cloudName,
    api_key: apiKey,
    api_secret: apiSecret,
    secure: true
  });

  return true;
}

const cloudinaryReady = configureCloudinary();

/* =========================
   JWT
========================= */

function signToken(userId) {
  return jwt.sign(
    {
      sub: String(userId)
    },
    JWT_SECRET,
    {
      expiresIn: '30d'
    }
  );
}

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
  const header = String(
    req.headers.authorization || ''
  );

  const token = header.startsWith('Bearer ')
    ? header.slice(7).trim()
    : '';

  if (!token) {
    return res.status(401).json({
      error: 'Authentication required'
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    const userId = Number(
      decoded?.sub
    );

    if (
      !Number.isInteger(userId) ||
      userId <= 0
    ) {
      throw new Error('Bad token subject');
    }

    const user = db
      .prepare(
        'SELECT * FROM users WHERE id=?'
      )
      .get(userId);

    if (!user) {
      return res.status(401).json({
        error: 'User not found'
      });
    }

    req.userId = userId;
    req.user = user;

    next();
  } catch {
    return res.status(401).json({
      error: 'Invalid or expired token'
    });
  }
}

/* =========================
   USER FORMAT
========================= */

function publicUser(u) {
  return {
    id: u.id,
    name: u.name,
    username: u.username,
    email: u.email,
    bio: u.bio || '',
    photoUrl: u.photo_url || '',
    isPrivate: !!u.is_private,
    allowMessages: u.allow_messages !== 0,
    approveFollowers: !!u.approve_followers,
    showFollowers: u.show_followers !== 0,
    showFollowing: u.show_following !== 0
  };
}

/* =========================
   CLOUDINARY UPLOAD
========================= */

function uploadBuffer(buffer, mimetype) {
  return new Promise((resolve, reject) => {
    if (!cloudinaryReady) {
      return reject(
        new Error(
          'Cloudinary is not configured on the server'
        )
      );
    }

    /*
      Cloudinary stores audio through
      the "video" resource type.
    */

    const resourceType =
      String(mimetype || '').startsWith('audio/') ||
      String(mimetype || '').startsWith('video/')
        ? 'video'
        : 'image';

    const stream =
      cloudinary.uploader.upload_stream(
        {
          folder: 'in2u',
          resource_type: resourceType,
          use_filename: false,
          unique_filename: true,
          overwrite: false
        },

        (error, result) => {
          if (error) {
            console.error(
              'Cloudinary upload error:',
              error
            );

            return reject(
              new Error(
                error?.message ||
                'Cloudinary upload failed'
              )
            );
          }

          resolve({
            url:
              result.secure_url ||
              result.url,

            publicId:
              result.public_id,

            resourceType:
              result.resource_type,

            format:
              result.format
          });
        }
      );

    stream.end(buffer);
  });
}

/* =========================
   HEALTH
========================= */

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'In2U backend',
    cloudinary: cloudinaryReady,
    time: new Date().toISOString()
  });
});

/* =========================
   SIGN UP
========================= */

app.post(
  '/api/auth/signup',
  async (req, res) => {
    try {
      const name = String(
        req.body?.name || ''
      ).trim();

      const email = String(
        req.body?.email || ''
      ).trim().toLowerCase();

      const password = String(
        req.body?.password || ''
      );

      const username = String(
        req.body?.username || ''
      ).trim().toLowerCase();

      if (
        !name ||
        !email ||
        !password ||
        !username
      ) {
        return res.status(400).json({
          error:
            'Name, email, username and password are required'
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            'Password must be at least 8 characters'
        });
      }

      const duplicate = db
        .prepare(
          'SELECT id FROM users WHERE email=? OR username=?'
        )
        .get(email, username);

      if (duplicate) {
        return res.status(409).json({
          error:
            'Email or username already exists'
        });
      }

      const hash =
        await bcrypt.hash(password, 12);

      const info = db
        .prepare(
          `INSERT INTO users
           (name,username,email,password_hash)
           VALUES(?,?,?,?)`
        )
        .run(
          name,
          username,
          email,
          hash
        );

      const user = db
        .prepare(
          'SELECT * FROM users WHERE id=?'
        )
        .get(info.lastInsertRowid);

      res.json({
        token: signToken(user.id),
        user: publicUser(user)
      });

    } catch (e) {
      console.error(
        'Signup error:',
        e
      );

      res.status(500).json({
        error:
          'Could not create account'
      });
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  '/api/auth/login',
  async (req, res) => {
    try {
      const email = String(
        req.body?.email || ''
      ).trim().toLowerCase();

      const password = String(
        req.body?.password || ''
      );

      const user = db
        .prepare(
          'SELECT * FROM users WHERE email=?'
        )
        .get(email);

      if (
        !user ||
        !(await bcrypt.compare(
          password,
          user.password_hash
        ))
      ) {
        return res.status(401).json({
          error:
            'Invalid email or password'
        });
      }

      res.json({
        token: signToken(user.id),
        user: publicUser(user)
      });

    } catch (e) {
      console.error(
        'Login error:',
        e
      );

      res.status(500).json({
        error: 'Could not log in'
      });
    }
  }
);

/* =========================
   CURRENT USER
========================= */

app.get(
  '/api/me',
  auth,
  (req, res) => {
    res.json({
      user: publicUser(req.user)
    });
  }
);

/* =========================
   UPDATE PROFILE
========================= */

app.patch(
  '/api/me',
  auth,
  (req, res) => {
    try {
      const b = req.body || {};

      const name =
        String(
          b.name ?? req.user.name
        ).trim() ||
        req.user.name;

      const username =
        String(
          b.username ??
          req.user.username
        )
          .trim()
          .toLowerCase() ||
        req.user.username;

      const bio = String(
        b.bio ??
        req.user.bio ??
        ''
      );

      const photoUrl = String(
        b.photoUrl ??
        req.user.photo_url ??
        ''
      );

      const isPrivate =
        b.isPrivate === undefined
          ? req.user.is_private
          : !!b.isPrivate;

      const allowMessages =
        b.allowMessages === undefined
          ? req.user.allow_messages
          : !!b.allowMessages;

      const approveFollowers =
        b.approveFollowers === undefined
          ? req.user.approve_followers
          : !!b.approveFollowers;

      const showFollowers =
        b.showFollowers === undefined
          ? req.user.show_followers
          : !!b.showFollowers;

      const showFollowing =
        b.showFollowing === undefined
          ? req.user.show_following
          : !!b.showFollowing;

      const existing = db
        .prepare(
          'SELECT id FROM users WHERE username=? AND id<>?'
        )
        .get(
          username,
          req.userId
        );

      if (existing) {
        return res.status(409).json({
          error:
            'Username already exists'
        });
      }

      db.prepare(`
        UPDATE users SET
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
        name,
        username,
        bio,
        photoUrl,
        isPrivate ? 1 : 0,
        allowMessages ? 1 : 0,
        approveFollowers ? 1 : 0,
        showFollowers ? 1 : 0,
        showFollowing ? 1 : 0,
        req.userId
      );

      res.json({
        user: publicUser(
          db
            .prepare(
              'SELECT * FROM users WHERE id=?'
            )
            .get(req.userId)
        )
      });

    } catch (e) {
      console.error(
        'Profile update error:',
        e
      );

      res.status(500).json({
        error:
          'Could not update profile'
      });
    }
  }
);

/* =========================
   MEDIA UPLOAD
========================= */

/*
  IMPORTANT:

  The browser does NOT upload directly
  to Cloudinary.

  Browser
      ↓
  /api/uploads
      ↓
  Render backend
      ↓
  Cloudinary
      ↓
  URL returned to browser

  This avoids the client-side
  "Invalid signature" problem.
*/

app.post(
  '/api/uploads',
  auth,
  (req, res) => {
    upload.single('file')(
      req,
      res,
      async (err) => {

        if (err) {
          console.error(
            'Upload middleware error:',
            err
          );

          return res.status(400).json({
            error:
              err.message ||
              'Invalid upload'
          });
        }

        if (!req.file) {
          return res.status(400).json({
            error:
              'No file uploaded'
          });
        }

        try {
          const result =
            await uploadBuffer(
              req.file.buffer,
              req.file.mimetype
            );

          res.json(result);

        } catch (e) {
          console.error(
            'Media upload failed:',
            e
          );

          res.status(502).json({
            error:
              e.message ||
              'Media upload failed'
          });
        }
      }
    );
  }
);

/*
  Old endpoint.

  This makes sure an outdated frontend
  gets a clear message instead of trying
  to use an old upload flow.
*/

app.post(
  '/api/upload',
  auth,
  (req, res) => {
    res.status(410).json({
      error:
        'Old upload endpoint. Refresh the In2U website so it uses /api/uploads.'
    });
  }
);

/* =========================
   CREATE POST
========================= */

app.post(
  '/api/posts',
  auth,
  (req, res) => {
    try {
      const caption = String(
        req.body?.caption || ''
      );

      const media =
        Array.isArray(
          req.body?.media
        )
          ? req.body.media
              .filter(
                x =>
                  typeof x === 'string' &&
                  /^https?:\/\//i.test(x)
              )
              .slice(0, 10)
          : [];

      const info = db
        .prepare(
          `INSERT INTO posts
           (user_id,caption,media_json)
           VALUES(?,?,?)`
        )
        .run(
          req.userId,
          caption,
          JSON.stringify(media)
        );

      res.json({
        ok: true,
        id: info.lastInsertRowid
      });

    } catch (e) {
      console.error(
        'Post creation error:',
        e
      );

      res.status(500).json({
        error:
          'Could not create post'
      });
    }
  }
);

/* =========================
   POST FORMAT
========================= */

function decoratePost(p) {

  const reactions = db
    .prepare(
      `SELECT emoji,COUNT(*) n
       FROM reactions
       WHERE post_id=?
       GROUP BY emoji`
    )
    .all(p.id);

  const reactionUsers = {};

  for (
    const r of db
      .prepare(`
        SELECT
          r.emoji,
          u.name,
          u.username,
          u.photo_url
        FROM reactions r
        JOIN users u
          ON u.id=r.user_id
        WHERE r.post_id=?
        ORDER BY r.id DESC
      `)
      .all(p.id)
  ) {
    (
      reactionUsers[r.emoji] ||=
        []
    ).push({
      name: r.name,
      handle:
        '@' + r.username,
      photo:
        r.photo_url || ''
    });
  }

  const comments =
    db.prepare(`
      SELECT
        c.*,
        u.name,
        u.username
      FROM comments c
      JOIN users u
        ON u.id=c.user_id
      WHERE c.post_id=?
      ORDER BY c.id ASC
    `).all(p.id);

  return {
    id: p.id,
    name: p.name,
    username: p.username,
    photo:
      p.photo_url || '',
    caption:
      p.caption || '',
    media:
      JSON.parse(
        p.media_json || '[]'
      ),
    created_at:
      p.created_at,

    reactions:
      Object.fromEntries(
        reactions.map(
          x => [
            x.emoji,
            x.n
          ]
        )
      ),

    reactionUsers,

    comments:
      comments.map(
        c => ({
          id: c.id,
          user: c.name,
          text: c.text,
          parentId:
            c.parent_id,
          replies: []
        })
      )
  };
}

/* =========================
   FEED
========================= */

app.get(
  '/api/feed',
  auth,
  (req, res) => {

    const posts = db
      .prepare(`
        SELECT
          p.*,
          u.name,
          u.username,
          u.photo_url
        FROM posts p
        JOIN users u
          ON u.id=p.user_id
        ORDER BY p.id DESC
        LIMIT 100
      `)
      .all();

    res.json({
      posts:
        posts.map(
          decoratePost
        )
    });
  }
);

/* =========================
   REACTIONS
========================= */

app.post(
  '/api/posts/:id/reactions',
  auth,
  (req, res) => {
    try {

      const postId =
        Number(
          req.params.id
        );

      const emoji =
        String(
          req.body?.emoji ||
          '❤️'
        );

      db.prepare(`
        INSERT OR IGNORE
        INTO reactions
        (post_id,user_id,emoji)
        VALUES(?,?,?)
      `).run(
        postId,
        req.userId,
        emoji
      );

      res.json({
        ok: true
      });

    } catch (e) {

      res.status(500).json({
        error:
          'Could not add reaction'
      });
    }
  }
);

/* =========================
   COMMENTS
========================= */

app.post(
  '/api/posts/:id/comments',
  auth,
  (req, res) => {
    try {

      const text =
        String(
          req.body?.text || ''
        ).trim();

      const parentId =
        req.body?.parentId == null
          ? null
          : Number(
              req.body.parentId
            );

      if (!text) {
        return res.status(400).json({
          error:
            'Comment cannot be empty'
        });
      }

      db.prepare(`
        INSERT INTO comments
        (post_id,user_id,text,parent_id)
        VALUES(?,?,?,?)
      `).run(
        Number(
          req.params.id
        ),
        req.userId,
        text,
        parentId
      );

      res.json({
        ok: true
      });

    } catch (e) {

      res.status(500).json({
        error:
          'Could not add comment'
      });
    }
  }
);

/* =========================
   FOLLOWERS
========================= */

app.get(
  '/api/users/:id/followers',
  auth,
  (req, res) => {

    const users =
      db.prepare(`
        SELECT u.*
        FROM follows f
        JOIN users u
          ON u.id=f.follower_id
        WHERE
          f.following_id=?
          AND f.status='accepted'
      `).all(
        Number(
          req.params.id
        )
      );

    res.json({
      users:
        users.map(
          publicUser
        )
    });
  }
);

/* =========================
   FOLLOWING
========================= */

app.get(
  '/api/users/:id/following',
  auth,
  (req, res) => {

    const users =
      db.prepare(`
        SELECT u.*
        FROM follows f
        JOIN users u
          ON u.id=f.following_id
        WHERE
          f.follower_id=?
          AND f.status='accepted'
      `).all(
        Number(
          req.params.id
        )
      );

    res.json({
      users:
        users.map(
          publicUser
        )
    });
  }
);

/* =========================
   FIND USER
========================= */

app.get(
  '/api/users/:username',
  auth,
  (req, res) => {

    const username =
      String(
        req.params.username
      )
        .replace(/^@/, '')
        .toLowerCase();

    const user =
      db.prepare(
        'SELECT * FROM users WHERE username=?'
      ).get(username);

    if (!user) {
      return res.status(404).json({
        error:
          'User not found'
      });
    }

    res.json({
      user:
        publicUser(user)
    });
  }
);

/* =========================
   FOLLOW USER
========================= */

app.post(
  '/api/users/:id/follow',
  auth,
  (req, res) => {

    const id =
      Number(
        req.params.id
      );

    if (id === req.userId) {
      return res.status(400).json({
        error:
          'You cannot follow yourself'
      });
    }

    const target =
      db.prepare(
        'SELECT * FROM users WHERE id=?'
      ).get(id);

    if (!target) {
      return res.status(404).json({
        error:
          'User not found'
      });
    }

    const status =
      target.approve_followers
        ? 'pending'
        : 'accepted';

    db.prepare(`
      INSERT INTO follows
      (follower_id,following_id,status)
      VALUES(?,?,?)

      ON CONFLICT(
        follower_id,
        following_id
      )

      DO UPDATE SET
        status=excluded.status
    `).run(
      req.userId,
      id,
      status
    );

    res.json({
      status
    });
  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (err, req, res, next) => {

    console.error(
      'Unhandled server error:',
      err
    );

    res.status(500).json({
      error:
        'Server error'
    });
  }
);

/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      `In2U backend running on port ${PORT}`
    );
  }
);
