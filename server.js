import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

/* =========================================================
   DATABASE
========================================================= */

const db = new Database(
  path.join(__dirname, 'in2u.db')
);

db.pragma('foreign_keys = ON');

const schemaPath = path.join(
  __dirname,
  'schema.sql'
);

const schemaSql = await readFile(
  schemaPath,
  'utf8'
);

db.exec(schemaSql);

/* =========================================================
   CLOUDINARY
========================================================= */

cloudinary.config({
  cloud_name:
    process.env.CLOUDINARY_CLOUD_NAME,

  api_key:
    process.env.CLOUDINARY_API_KEY,

  api_secret:
    process.env.CLOUDINARY_API_SECRET
});

/* =========================================================
   CORS
========================================================= */

const configuredOrigins =
  String(
    process.env.CORS_ORIGIN || '*'
  )
    .split(',')
    .map(x => x.trim())
    .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (
        !origin ||
        configuredOrigins.includes('*') ||
        configuredOrigins.includes(origin)
      ) {
        return callback(null, true);
      }

      return callback(
        new Error(
          'Origin not allowed by CORS'
        )
      );
    },

    credentials: false,

    methods: [
      'GET',
      'POST',
      'PATCH',
      'DELETE',
      'OPTIONS'
    ],

    allowedHeaders: [
      'Content-Type',
      'Authorization'
    ]
  })
);

/* =========================================================
   BODY PARSERS
========================================================= */

app.use(
  express.json({
    limit: '40mb'
  })
);

app.use(
  express.urlencoded({
    extended: true
  })
);

/* =========================================================
   MULTER
========================================================= */

const upload = multer({
  storage:
    multer.memoryStorage(),

  limits: {
    fileSize:
      100 * 1024 * 1024
  },

  fileFilter(
    req,
    file,
    cb
  ) {
    const type =
      String(
        file.mimetype || ''
      ).toLowerCase();

    if (
      type.startsWith('image/') ||
      type.startsWith('video/')
    ) {
      return cb(null, true);
    }

    cb(
      new Error(
        'Only image and video files are allowed'
      )
    );
  }
});

/* =========================================================
   AUTH / JWT
========================================================= */

const JWT_SECRET =
  String(
    process.env.JWT_SECRET ||
      'dev-only-change-this-secret'
  );

if (!process.env.JWT_SECRET) {
  console.warn(
    'WARNING: JWT_SECRET is not set. Set a permanent JWT_SECRET in Render Environment Variables.'
  );
}

const publicUser = u => ({
  id: u.id,
  name: u.name,
  username: u.username,
  email: u.email,
  bio: u.bio,
  photoUrl: u.photo_url,

  isPrivate:
    !!u.is_private,

  allowMessages:
    !!u.allow_messages,

  approveFollowers:
    !!u.approve_followers,

  showFollowers:
    !!u.show_followers,

  showFollowing:
    !!u.show_following
});

function tokenFor(u) {
  return jwt.sign(
    {
      sub: String(u.id)
    },

    JWT_SECRET,

    {
      expiresIn: '30d'
    }
  );
}

function auth(
  req,
  res,
  next
) {
  try {
    const header =
      String(
        req.headers.authorization ||
          ''
      );

    if (
      !header.startsWith(
        'Bearer '
      )
    ) {
      return res.status(401).json({
        error:
          'Authentication required'
      });
    }

    const token =
      header
        .slice(7)
        .trim();

    if (!token) {
      return res.status(401).json({
        error:
          'Authentication required'
      });
    }

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    if (
      !decoded ||
      decoded.sub ===
        undefined ||
      decoded.sub === null
    ) {
      return res.status(401).json({
        error:
          'Invalid or expired token'
      });
    }

    req.userId =
      Number(decoded.sub);

    if (
      !Number.isInteger(
        req.userId
      ) ||
      req.userId <= 0
    ) {
      return res.status(401).json({
        error:
          'Invalid user session'
      });
    }

    next();

  } catch (error) {
    console.error(
      'Auth error:',
      error?.message ||
        error
    );

    return res.status(401).json({
      error:
        'Invalid or expired token'
    });
  }
}

/* =========================================================
   HEALTH
========================================================= */

app.get(
  '/api/health',
  (req, res) => {
    res.json({
      ok: true,
      service:
        'In2U backend',
      time:
        new Date().toISOString()
    });
  }
);

/* =========================================================
   SIGN UP
========================================================= */

app.post(
  '/api/auth/signup',
  async (req, res) => {
    const {
      name,
      email,
      password,
      username
    } = req.body || {};

    const cleanName =
      String(
        name || ''
      ).trim();

    const cleanEmail =
      String(
        email || ''
      )
        .trim()
        .toLowerCase();

    const cleanPassword =
      String(
        password || ''
      );

    if (
      !cleanName ||
      !cleanEmail ||
      !cleanPassword
    ) {
      return res.status(400).json({
        error:
          'Name, email and password are required'
      });
    }

    if (
      cleanPassword.length <
      8
    ) {
      return res.status(400).json({
        error:
          'Password must be at least 8 characters'
      });
    }

    const cleanUsername =
      String(
        username ||
          cleanName
      )
        .trim()
        .toLowerCase()
        .replace(
          /[^a-z0-9_]/g,
          ''
        )
        .slice(0, 30) ||
      `user${Date.now()}`;

    try {
      const existingEmail =
        db.prepare(
          'SELECT id FROM users WHERE email=?'
        ).get(
          cleanEmail
        );

      if (existingEmail) {
        return res.status(409).json({
          error:
            'Email already in use'
        });
      }

      const existingUsername =
        db.prepare(
          'SELECT id FROM users WHERE username=?'
        ).get(
          cleanUsername
        );

      if (existingUsername) {
        return res.status(409).json({
          error:
            'Username already in use'
        });
      }

      const hash =
        await bcrypt.hash(
          cleanPassword,
          12
        );

      const info =
        db.prepare(`
          INSERT INTO users(
            name,
            username,
            email,
            password_hash
          )
          VALUES(?,?,?,?)
        `).run(
          cleanName,
          cleanUsername,
          cleanEmail,
          hash
        );

      const user =
        db.prepare(
          'SELECT * FROM users WHERE id=?'
        ).get(
          Number(
            info.lastInsertRowid
          )
        );

      if (!user) {
        return res.status(500).json({
          error:
            'Account was created but could not be loaded'
        });
      }

      return res.status(201).json({
        token:
          tokenFor(user),

        user:
          publicUser(user)
      });

    } catch (error) {
      console.error(
        'Signup error:',
        error
      );

      return res.status(500).json({
        error:
          'Account could not be created'
      });
    }
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  '/api/auth/login',
  async (req, res) => {
    const cleanEmail =
      String(
        req.body?.email || ''
      )
        .trim()
        .toLowerCase();

    const password =
      String(
        req.body?.password || ''
      );

    if (
      !cleanEmail ||
      !password
    ) {
      return res.status(400).json({
        error:
          'Email and password are required'
      });
    }

    try {
      const user =
        db.prepare(
          'SELECT * FROM users WHERE email=?'
        ).get(
          cleanEmail
        );

      if (!user) {
        return res.status(401).json({
          error:
            'Invalid email or password'
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            'Invalid email or password'
        });
      }

      return res.json({
        token:
          tokenFor(user),

        user:
          publicUser(user)
      });

    } catch (error) {
      console.error(
        'Login error:',
        error
      );

      return res.status(500).json({
        error:
          'Login failed'
      });
    }
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  '/api/me',
  auth,
  (req, res) => {
    const user =
      db.prepare(
        'SELECT * FROM users WHERE id=?'
      ).get(
        req.userId
      );

    if (!user) {
      return res.status(404).json({
        error:
          'User not found'
      });
    }

    return res.json({
      user:
        publicUser(user)
    });
  }
);

/* =========================================================
   UPDATE CURRENT USER
========================================================= */

app.patch(
  '/api/me',
  auth,
  (req, res) => {
    const user =
      db.prepare(
        'SELECT * FROM users WHERE id=?'
      ).get(
        req.userId
      );

    if (!user) {
      return res.status(404).json({
        error:
          'User not found'
      });
    }

    const b =
      req.body || {};

    const values = {
      name:
        b.name ??
        user.name,

      username:
        b.username ??
        user.username,

      bio:
        b.bio ??
        user.bio,

      photo_url:
        b.photoUrl ??
        user.photo_url,

      is_private:
        b.isPrivate ===
        undefined
          ? user.is_private
          : +!!b.isPrivate,

      allow_messages:
        b.allowMessages ===
        undefined
          ? user.allow_messages
          : +!!b.allowMessages,

      approve_followers:
        b.approveFollowers ===
        undefined
          ? user.approve_followers
          : +!!b.approveFollowers,

      show_followers:
        b.showFollowers ===
        undefined
          ? user.show_followers
          : +!!b.showFollowers,

      show_following:
        b.showFollowing ===
        undefined
          ? user.show_following
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
        values.name,
        values.username,
        values.bio,
        values.photo_url,
        values.is_private,
        values.allow_messages,
        values.approve_followers,
        values.show_followers,
        values.show_following,
        req.userId
      );

      const updated =
        db.prepare(
          'SELECT * FROM users WHERE id=?'
        ).get(
          req.userId
        );

      return res.json({
        user:
          publicUser(updated)
      });

    } catch (error) {
      console.error(
        'Profile update error:',
        error
      );

      return res.status(409).json({
        error:
          'Username may already be in use'
      });
    }
  }
);

/* =========================================================
   GET USER
========================================================= */

app.get(
  '/api/users/:username',
  auth,
  (req, res) => {
    const user =
      db.prepare(
        'SELECT * FROM users WHERE username=?'
      ).get(
        req.params.username
          .toLowerCase()
      );

    if (!user) {
      return res.status(404).json({
        error:
          'User not found'
      });
    }

    const followers =
      db.prepare(`
        SELECT COUNT(*) n
        FROM follows
        WHERE following_id=?
        AND status='accepted'
      `).get(
        user.id
      ).n;

    const following =
      db.prepare(`
        SELECT COUNT(*) n
        FROM follows
        WHERE follower_id=?
        AND status='accepted'
      `).get(
        user.id
      ).n;

    return res.json({
      user: {
        ...publicUser(user),
        followers,
        following
      }
    });
  }
);

/* =========================================================
   FOLLOW
========================================================= */

app.post(
  '/api/users/:id/follow',
  auth,
  (req, res) => {
    const target =
      Number(
        req.params.id
      );

    if (
      !Number.isInteger(
        target
      )
    ) {
      return res.status(400).json({
        error:
          'Invalid user ID'
      });
    }

    if (
      target ===
      req.userId
    ) {
      return res.status(400).json({
        error:
          'You cannot follow yourself'
      });
    }

    const user =
      db.prepare(
        'SELECT * FROM users WHERE id=?'
      ).get(
        target
      );

    if (!user) {
      return res.status(404).json({
        error:
          'User not found'
      });
    }

    const status =
      user.approve_followers
        ? 'pending'
        : 'accepted';

    db.prepare(`
      INSERT INTO follows(
        follower_id,
        following_id,
        status
      )
      VALUES(?,?,?)
      ON CONFLICT(
        follower_id,
        following_id
      )
      DO UPDATE SET
        status=excluded.status
    `).run(
      req.userId,
      target,
      status
    );

    return res.json({
      status
    });
  }
);

app.delete(
  '/api/users/:id/follow',
  auth,
  (req, res) => {
    db.prepare(`
      DELETE FROM follows
      WHERE follower_id=?
      AND following_id=?
    `).run(
      req.userId,
      Number(
        req.params.id
      )
    );

    return res.json({
      ok: true
    });
  }
);

/* =========================================================
   FOLLOWERS
========================================================= */

app.get(
  '/api/users/:id/followers',
  auth,
  (req, res) => {
    const id =
      Number(
        req.params.id
      );

    const user =
      db.prepare(
        'SELECT * FROM users WHERE id=?'
      ).get(
        id
      );

    if (!user) {
      return res.status(404).json({
        error:
          'User not found'
      });
    }

    if (
      user.is_private &&
      id !== req.userId &&
      !user.show_followers
    ) {
      return res.status(403).json({
        error:
          'Followers list is private'
      });
    }

    const rows =
      db.prepare(`
        SELECT u.*
        FROM users u
        JOIN follows f
          ON f.follower_id=u.id
        WHERE f.following_id=?
        AND f.status='accepted'
        ORDER BY f.created_at DESC
      `).all(
        id
      );

    return res.json({
      users:
        rows.map(
          publicUser
        )
    });
  }
);

/* =========================================================
   FOLLOWING
========================================================= */

app.get(
  '/api/users/:id/following',
  auth,
  (req, res) => {
    const id =
      Number(
        req.params.id
      );

    const user =
      db.prepare(
        'SELECT * FROM users WHERE id=?'
      ).get(
        id
      );

    if (!user) {
      return res.status(404).json({
        error:
          'User not found'
      });
    }

    if (
      user.is_private &&
      id !== req.userId &&
      !user.show_following
    ) {
      return res.status(403).json({
        error:
          'Following list is private'
      });
    }

    const rows =
      db.prepare(`
        SELECT u.*
        FROM users u
        JOIN follows f
          ON f.following_id=u.id
        WHERE f.follower_id=?
        AND f.status='accepted'
        ORDER BY f.created_at DESC
      `).all(
        id
      );

    return res.json({
      users:
        rows.map(
          publicUser
        )
    });
  }
);

/* =========================================================
   CLOUDINARY UPLOAD
========================================================= */

app.post(
  '/api/uploads',
  auth,
  upload.single('file'),

  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error:
            'No file provided'
        });
      }

      const cloudName =
        process.env
          .CLOUDINARY_CLOUD_NAME;

      const apiKey =
        process.env
          .CLOUDINARY_API_KEY;

      const apiSecret =
        process.env
          .CLOUDINARY_API_SECRET;

      if (
        !cloudName ||
        !apiKey ||
        !apiSecret
      ) {
        console.error(
          'Cloudinary environment variables are missing'
        );

        return res.status(500).json({
          error:
            'Cloudinary is not configured on the server'
        });
      }

      const mimeType =
        String(
          req.file.mimetype ||
            ''
        ).toLowerCase();

      const resourceType =
        mimeType.startsWith(
          'video/'
        )
          ? 'video'
          : 'image';

      console.log(
        `Uploading ${resourceType}: ${req.file.originalname} (${req.file.size} bytes)`
      );

      const result =
        await new Promise(
          (
            resolve,
            reject
          ) => {
            const stream =
              cloudinary
                .uploader
                .upload_stream(
                  {
                    folder:
                      'in2u',

                    resource_type:
                      resourceType
                  },

                  (
                    error,
                    uploadResult
                  ) => {
                    if (error) {
                      return reject(
                        error
                      );
                    }

                    resolve(
                      uploadResult
                    );
                  }
                );

            stream.end(
              req.file.buffer
            );
          }
        );

      console.log(
        'Cloudinary upload successful:',
        result.secure_url
      );

      return res.status(201).json({
        ok: true,

        url:
          result.secure_url,

        public_id:
          result.public_id,

        resourceType:
          result.resource_type,

        resource_type:
          result.resource_type,

        format:
          result.format,

        bytes:
          result.bytes
      });

    } catch (error) {
      console.error(
        'Cloudinary upload error:',
        error
      );

      return res.status(500).json({
        error:
          error?.message ||
          'Media upload failed'
      });
    }
  }
);

/* =========================================================
   CREATE POST
========================================================= */

app.post(
  '/api/posts',
  auth,
  (req, res) => {
    const caption =
      String(
        req.body?.caption ||
          ''
      );

    const media =
      Array.isArray(
        req.body?.media
      )
        ? req.body.media
        : [];

    try {
      const tx =
        db.transaction(
          () => {
            const post =
              db.prepare(`
                INSERT INTO posts(
                  user_id,
                  caption
                )
                VALUES(?,?)
              `).run(
                req.userId,
                caption
              );

            const addMedia =
              db.prepare(`
                INSERT INTO post_media(
                  post_id,
                  url,
                  sort_order
                )
                VALUES(?,?,?)
              `);

            media
              .slice(0, 5)
              .forEach(
                (
                  url,
                  index
                ) => {
                  if (url) {
                    addMedia.run(
                      post.lastInsertRowid,
                      String(url),
                      index
                    );
                  }
                }
              );

            return Number(
              post.lastInsertRowid
            );
          }
        );

      const postId =
        tx();

      return res.status(201).json({
        post:
          db.prepare(
            'SELECT * FROM posts WHERE id=?'
          ).get(
            postId
          )
      });

    } catch (error) {
      console.error(
        'Create post error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not create post'
      });
    }
  }
);

/* =========================================================
   FEED
========================================================= */

app.get(
  '/api/feed',
  auth,
  (req, res) => {
    const rows =
      db.prepare(`
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
      `).all();

    const media =
      db.prepare(`
        SELECT
          post_id,
          url
        FROM post_media
        ORDER BY sort_order
      `).all();

    const mediaMap = {};

    for (
      const item of media
    ) {
      (
        mediaMap[
          item.post_id
        ] ??= []
      ).push(
        item.url
      );
    }

    const reactions =
      db.prepare(`
        SELECT
          post_id,
          user_id,
          emoji
        FROM reactions
        ORDER BY created_at
      `).all();

    const reactionMap = {};

    for (
      const reaction of reactions
    ) {
      const entry =
        reactionMap[
          reaction.post_id
        ] ??= {
          counts: {},
          users: {}
        };

      entry.counts[
        reaction.emoji
      ] =
        (
          entry.counts[
            reaction.emoji
          ] || 0
        ) + 1;

      (
        entry.users[
          reaction.emoji
        ] ??= []
      ).push(
        Number(
          reaction.user_id
        )
      );
    }

    const comments =
      db.prepare(`
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
      `).all();

    const commentMap = {};

    for (
      const comment of comments
    ) {
      (
        commentMap[
          comment.post_id
        ] ??= []
      ).push({
        id:
          comment.id,

        user:
          comment.name,

        text:
          comment.text,

        reactions: {},

        replies: [],

        parentId:
          comment.parent_id
      });
    }

    for (
      const post of rows
    ) {
      const list =
        commentMap[
          post.id
        ] || [];

      const byId =
        Object.fromEntries(
          list.map(
            comment => [
              comment.id,
              comment
            ]
          )
        );

      for (
        const comment of list
      ) {
        if (
          comment.parentId &&
          byId[
            comment.parentId
          ]
        ) {
          byId[
            comment.parentId
          ]
            .replies
            .push(
              comment
            );
        }
      }

      commentMap[
        post.id
      ] =
        list
          .filter(
            comment =>
              !comment.parentId
          )
          .map(
            comment => {
              delete comment.parentId;
              return comment;
            }
          );
    }

    const posts =
      rows.map(
        post => {
          const reaction =
            reactionMap[
              post.id
            ] || {
              counts: {},
              users: {}
            };

          const reactionUsers =
            Object.fromEntries(
              Object.entries(
                reaction.users
              ).map(
                (
                  [
                    emoji,
                    ids
                  ]
                ) => [
                  emoji,

                  ids.map(
                    id => {
                      const user =
                        db.prepare(`
                          SELECT
                            name,
                            username,
                            photo_url
                          FROM users
                          WHERE id=?
                        `).get(
                          id
                        );

                      return {
                        name:
                          user?.name ||
                          'User',

                        handle:
                          '@' +
                          (
                            user?.username ||
                            'user'
                          ),

                        photo:
                          user?.photo_url ||
                          ''
                      };
                    }
                  )
                ]
              )
            );

          return {
            ...post,

            media:
              mediaMap[
                post.id
              ] || [],

            reactions:
              reaction.counts,

            reactionUsers,

            comments:
              commentMap[
                post.id
              ] || []
          };
        }
      );

    return res.json({
      posts
    });
  }
);

/* =========================================================
   REACTIONS
========================================================= */

app.post(
  '/api/posts/:id/reactions',
  auth,
  (req, res) => {
    const emoji =
      String(
        req.body?.emoji ||
          '❤️'
      );

    db.prepare(`
      INSERT INTO reactions(
        user_id,
        post_id,
        emoji
      )
      VALUES(?,?,?)
      ON CONFLICT(
        user_id,
        post_id
      )
      DO UPDATE SET
        emoji=excluded.emoji
    `).run(
      req.userId,
      Number(
        req.params.id
      ),
      emoji
    );

    return res.json({
      ok: true
    });
  }
);

/* =========================================================
   COMMENTS
========================================================= */

app.post(
  '/api/posts/:id/comments',
  auth,
  (req, res) => {
    const text =
      String(
        req.body?.text ||
          ''
      ).trim();

    if (!text) {
      return res.status(400).json({
        error:
          'Comment is required'
      });
    }

    const parentId =
      req.body?.parentId ===
        undefined ||
      req.body?.parentId ===
        null ||
      req.body?.parentId ===
        ''
        ? null
        : Number(
            req.body.parentId
          );

    const info =
      db.prepare(`
        INSERT INTO comments(
          post_id,
          user_id,
          parent_id,
          text
        )
        VALUES(?,?,?,?)
      `).run(
        Number(
          req.params.id
        ),

        req.userId,

        parentId,

        text
      );

    return res.status(201).json({
      id:
        Number(
          info.lastInsertRowid
        )
    });
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      'Server error:',
      err
    );

    if (
      res.headersSent
    ) {
      return next(err);
    }

    if (
      err?.code ===
      'LIMIT_FILE_SIZE'
    ) {
      return res.status(413).json({
        error:
          'File is too large. Maximum size is 100MB.'
      });
    }

    return res.status(
      err.status || 500
    ).json({
      error:
        err.message ||
        'Server error'
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

const PORT =
  Number(
    process.env.PORT ||
      3000
  );

app.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      `In2U backend running on port ${PORT}`
    );
  }
);
