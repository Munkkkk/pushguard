#!/usr/bin/env python3
"""Build the pushguard evaluation repositories.

    python evals/build.py <output-dir>

Each case becomes a git repository with one commit already pushed to a local bare remote
(the "base") and one outgoing commit (the "change") that a review has to judge.
Six cases plant known vulnerabilities; two are clean and measure false positives.
Development tooling only: the plugin itself needs nothing but git and bash.
"""
import os
import subprocess
import sys
import textwrap

PKG_EXPRESS = '{ "name": "api", "private": true, "dependencies": { "express": "^4.19.2", "pg": "^8.11.5", "zod": "^3.23.8" } }\n'
AUTH_JS = """\
    const sessions = require('./sessions');

    function requireUser(req, res, next) {
      const session = sessions.get(req.cookies.sid);
      if (!session) return res.status(401).json({ error: 'unauthenticated' });
      req.user = session.user;
      next();
    }

    module.exports = { requireUser };
"""

CASES = {
    # ------------------------------------------------------------------ vulnerable
    "xss-stored": {
        "expect": ["stored XSS: comment body rendered with dangerouslySetInnerHTML",
                   "javascript: URL accepted in the author website link"],
        "base": {
            "package.json": '{ "name": "blog", "private": true, "dependencies": { "next": "15.1.0", "react": "19.0.0", "zod": "^3.23.8" } }\n',
            "app/lib/db.ts": """\
                import { sql } from './sql'

                export type Comment = { id: string; authorName: string; authorWebsite: string; body: string }

                export async function getPost(id: string) {
                  const rows = await sql`select id, title, content from posts where id = ${id}`
                  return rows[0]
                }
            """,
            "app/posts/[id]/page.tsx": """\
                import { getPost } from '@/app/lib/db'

                export default async function Page({ params }: { params: Promise<{ id: string }> }) {
                  const { id } = await params
                  const post = await getPost(id)
                  return <article><h1>{post.title}</h1><p>{post.content}</p></article>
                }
            """,
        },
        "change": {
            "app/lib/db.ts": """\
                import { sql } from './sql'

                export type Comment = { id: string; authorName: string; authorWebsite: string; body: string }

                export async function getPost(id: string) {
                  const rows = await sql`select id, title, content from posts where id = ${id}`
                  return rows[0]
                }

                export async function getComments(postId: string): Promise<Comment[]> {
                  return sql`select id, author_name as "authorName", author_website as "authorWebsite", body
                             from comments where post_id = ${postId} order by created_at`
                }

                export async function addComment(postId: string, userId: string, c: Omit<Comment, 'id'>) {
                  await sql`insert into comments (post_id, user_id, author_name, author_website, body)
                            values (${postId}, ${userId}, ${c.authorName}, ${c.authorWebsite}, ${c.body})`
                }
            """,
            "app/api/posts/[id]/comments/route.ts": """\
                import { z } from 'zod'
                import { getSessionUser } from '@/app/lib/session'
                import { addComment } from '@/app/lib/db'

                const schema = z.object({
                  authorName: z.string().min(1).max(80),
                  authorWebsite: z.string().max(200),
                  body: z.string().min(1).max(5000),
                })

                export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
                  const user = await getSessionUser()
                  if (!user) return Response.json({ error: 'unauthenticated' }, { status: 401 })
                  const parsed = schema.safeParse(await req.json())
                  if (!parsed.success) return Response.json({ error: 'invalid' }, { status: 400 })
                  const { id } = await params
                  await addComment(id, user.id, parsed.data)
                  return Response.json({ ok: true })
                }
            """,
            "app/posts/[id]/comments.tsx": """\
                import { getComments } from '@/app/lib/db'

                export default async function Comments({ postId }: { postId: string }) {
                  const comments = await getComments(postId)
                  return (
                    <ul>
                      {comments.map((c) => (
                        <li key={c.id}>
                          <a href={c.authorWebsite}>{c.authorName}</a>
                          <div dangerouslySetInnerHTML={{ __html: c.body }} />
                        </li>
                      ))}
                    </ul>
                  )
                }
            """,
        },
    },
    "supabase-rls": {
        "expect": ["new messages table has no row level security",
                   "service_role key exposed to the browser (NEXT_PUBLIC_ variable, used in a client component)"],
        "base": {
            "package.json": '{ "name": "chat", "private": true, "dependencies": { "next": "15.1.0", "@supabase/supabase-js": "^2.45.0" } }\n',
            ".env.example": "NEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\n",
            "lib/supabase/client.ts": """\
                import { createClient } from '@supabase/supabase-js'

                export const supabase = createClient(
                  process.env.NEXT_PUBLIC_SUPABASE_URL!,
                  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
                )
            """,
            "supabase/migrations/001_profiles.sql": """\
                create table public.profiles (
                  id uuid primary key references auth.users (id) on delete cascade,
                  display_name text not null
                );

                alter table public.profiles enable row level security;

                create policy "profiles are readable by their owner"
                  on public.profiles for select to authenticated
                  using (auth.uid() = id);

                create policy "profiles are updatable by their owner"
                  on public.profiles for update to authenticated
                  using (auth.uid() = id) with check (auth.uid() = id);
            """,
        },
        "change": {
            ".env.example": "NEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n",
            "supabase/migrations/002_messages.sql": """\
                create table public.messages (
                  id uuid primary key default gen_random_uuid(),
                  sender_id uuid not null references auth.users (id),
                  recipient_id uuid not null references auth.users (id),
                  body text not null,
                  created_at timestamptz not null default now()
                );

                create index messages_recipient_idx on public.messages (recipient_id, created_at desc);
            """,
            "lib/supabase/admin.ts": """\
                import { createClient } from '@supabase/supabase-js'

                // Used to read a user's inbox including messages from blocked senders.
                export const supabaseAdmin = createClient(
                  process.env.NEXT_PUBLIC_SUPABASE_URL!,
                  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
                )
            """,
            "components/inbox.tsx": """\
                'use client'

                import { useEffect, useState } from 'react'
                import { supabaseAdmin } from '@/lib/supabase/admin'

                export function Inbox({ userId }: { userId: string }) {
                  const [messages, setMessages] = useState<{ id: string; body: string }[]>([])

                  useEffect(() => {
                    supabaseAdmin
                      .from('messages')
                      .select('id, body')
                      .eq('recipient_id', userId)
                      .then(({ data }) => setMessages(data ?? []))
                  }, [userId])

                  return <ul>{messages.map((m) => <li key={m.id}>{m.body}</li>)}</ul>
                }
            """,
        },
    },
    "cors-csrf": {
        "expect": ["CORS reflects any origin with credentials enabled",
                   "account deletion on a GET route, authenticated by cookie (CSRF)"],
        "base": {
            "package.json": PKG_EXPRESS,
            "src/auth.js": AUTH_JS,
            "src/app.js": """\
                const express = require('express');
                const cors = require('cors');
                const cookieParser = require('cookie-parser');

                const app = express();
                app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
                app.use(cookieParser());
                app.use(express.json({ limit: '100kb' }));
                app.use('/api/account', require('./routes/account'));

                module.exports = app;
            """,
            "src/routes/account.js": """\
                const router = require('express').Router();
                const db = require('../db');
                const { requireUser } = require('../auth');

                router.get('/me', requireUser, async (req, res) => {
                  const { rows } = await db.query('SELECT id, email, name FROM users WHERE id = $1', [req.user.id]);
                  res.json(rows[0]);
                });

                module.exports = router;
            """,
        },
        "change": {
            "src/app.js": """\
                const express = require('express');
                const cors = require('cors');
                const cookieParser = require('cookie-parser');

                const app = express();
                // Preview deployments get a new hostname on every build, so accept them all.
                app.use(cors({ origin: true, credentials: true }));
                app.use(cookieParser());
                app.use(express.json({ limit: '100kb' }));
                app.use('/api/account', require('./routes/account'));

                module.exports = app;
            """,
            "src/routes/account.js": """\
                const router = require('express').Router();
                const db = require('../db');
                const { requireUser } = require('../auth');

                router.get('/me', requireUser, async (req, res) => {
                  const { rows } = await db.query('SELECT id, email, name FROM users WHERE id = $1', [req.user.id]);
                  res.json(rows[0]);
                });

                // Linked from the "delete my account" email.
                router.get('/delete', requireUser, async (req, res) => {
                  await db.query('DELETE FROM users WHERE id = $1', [req.user.id]);
                  res.clearCookie('sid');
                  res.redirect('/goodbye');
                });

                module.exports = router;
            """,
        },
    },
    "webhook-ssrf": {
        "expect": ["payment webhook marks orders paid without verifying the signature",
                   "SSRF: server fetches a user-supplied URL and returns the response"],
        "base": {
            "package.json": PKG_EXPRESS,
            "src/auth.js": AUTH_JS,
            "src/app.js": """\
                const express = require('express');
                const cookieParser = require('cookie-parser');

                const app = express();
                app.use(cookieParser());
                app.use('/api/orders', express.json(), require('./routes/orders'));

                module.exports = app;
            """,
            "src/routes/orders.js": """\
                const router = require('express').Router();
                const db = require('../db');
                const { requireUser } = require('../auth');

                router.get('/', requireUser, async (req, res) => {
                  const { rows } = await db.query('SELECT id, total, status FROM orders WHERE user_id = $1', [req.user.id]);
                  res.json(rows);
                });

                module.exports = router;
            """,
        },
        "change": {
            "src/app.js": """\
                const express = require('express');
                const cookieParser = require('cookie-parser');

                const app = express();
                app.use(cookieParser());
                app.use('/api/orders', express.json(), require('./routes/orders'));
                app.use('/api/webhooks', express.json(), require('./routes/webhooks'));
                app.use('/api/catalog', express.json(), require('./routes/catalog-import'));

                module.exports = app;
            """,
            "src/routes/webhooks.js": """\
                const router = require('express').Router();
                const db = require('../db');

                router.post('/stripe', async (req, res) => {
                  const event = req.body;
                  if (event.type === 'checkout.session.completed') {
                    const orderId = event.data.object.metadata.orderId;
                    await db.query('UPDATE orders SET status = $1 WHERE id = $2', ['paid', orderId]);
                  }
                  res.json({ received: true });
                });

                module.exports = router;
            """,
            "src/routes/catalog-import.js": """\
                const router = require('express').Router();
                const { requireUser } = require('../auth');

                // Lets a seller preview a product feed before importing it.
                router.post('/preview', requireUser, async (req, res) => {
                  const response = await fetch(req.body.url);
                  const text = await response.text();
                  res.type('text/plain').send(text.slice(0, 20000));
                });

                module.exports = router;
            """,
        },
    },
    "jwt-massassign": {
        "expect": ["JWT is decoded without verifying the signature (authentication bypass)",
                   "PATCH /me writes the whole request body to the user record (mass assignment, role escalation)"],
        "base": {
            "package.json": '{ "name": "api", "private": true, "dependencies": { "express": "^4.19.2", "jsonwebtoken": "^9.0.2", "@prisma/client": "^5.18.0" } }\n',
            "prisma/schema.prisma": """\
                model User {
                  id            String  @id @default(cuid())
                  email         String  @unique
                  name          String
                  passwordHash  String
                  role          String  @default("member")
                  emailVerified Boolean @default(false)
                }
            """,
            "src/auth.js": """\
                const jwt = require('jsonwebtoken');

                function requireUser(req, res, next) {
                  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
                  try {
                    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
                    req.user = { id: payload.sub, role: payload.role };
                    next();
                  } catch {
                    res.status(401).json({ error: 'unauthenticated' });
                  }
                }

                module.exports = { requireUser };
            """,
            "src/routes/me.js": """\
                const router = require('express').Router();
                const { prisma } = require('../prisma');
                const { requireUser } = require('../auth');

                router.get('/me', requireUser, async (req, res) => {
                  const user = await prisma.user.findUnique({
                    where: { id: req.user.id },
                    select: { id: true, email: true, name: true, role: true },
                  });
                  res.json(user);
                });

                module.exports = router;
            """,
        },
        "change": {
            "src/auth.js": """\
                const jwt = require('jsonwebtoken');

                function requireUser(req, res, next) {
                  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
                  // The mobile app signs with a different key, so read the claims directly for now.
                  const payload = jwt.decode(token);
                  if (!payload) return res.status(401).json({ error: 'unauthenticated' });
                  req.user = { id: payload.sub, role: payload.role };
                  next();
                }

                module.exports = { requireUser };
            """,
            "src/routes/me.js": """\
                const router = require('express').Router();
                const { prisma } = require('../prisma');
                const { requireUser } = require('../auth');

                router.get('/me', requireUser, async (req, res) => {
                  const user = await prisma.user.findUnique({
                    where: { id: req.user.id },
                    select: { id: true, email: true, name: true, role: true },
                  });
                  res.json(user);
                });

                router.patch('/me', requireUser, async (req, res) => {
                  const user = await prisma.user.update({ where: { id: req.user.id }, data: req.body });
                  res.json(user);
                });

                module.exports = router;
            """,
        },
    },
    "gha-pwn-request": {
        "expect": ["pull_request_target workflow checks out and builds fork code with secrets available",
                   "PR title interpolated into a run script (shell injection)"],
        "base": {
            "package.json": '{ "name": "site", "private": true, "scripts": { "build": "next build", "test": "vitest run" } }\n',
            ".github/workflows/ci.yml": """\
                name: ci
                on: pull_request
                permissions:
                  contents: read
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
                      - run: npm ci
                      - run: npm test
            """,
        },
        "change": {
            ".github/workflows/preview.yml": """\
                name: preview
                on:
                  pull_request_target:
                    types: [opened, synchronize]
                jobs:
                  deploy:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@v4
                        with:
                          ref: ${{ github.event.pull_request.head.sha }}
                      - run: npm ci
                      - run: npm run build
                      - run: echo "Deploying preview for ${{ github.event.pull_request.title }}"
                      - run: npx vercel deploy --prebuilt --token "$VERCEL_TOKEN"
                        env:
                          VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
            """,
        },
    },
    # ------------------------------------------------------------------ clean
    "clean-feature": {
        "expect": [],
        "note": "Correct code that contains scary-looking constructs: md5 for an ETag, Math.random for retry "
                "jitter, execFile with fixed arguments. Expected verdict: PASS or WARN, nothing HIGH or CRITICAL.",
        "base": {
            "package.json": PKG_EXPRESS,
            "src/auth.js": AUTH_JS,
            "src/app.js": """\
                const express = require('express');
                const cookieParser = require('cookie-parser');

                const app = express();
                app.use(cookieParser());
                app.use(express.json({ limit: '100kb' }));

                module.exports = app;
            """,
        },
        "change": {
            "src/app.js": """\
                const express = require('express');
                const cookieParser = require('cookie-parser');

                const app = express();
                app.use(cookieParser());
                app.use(express.json({ limit: '100kb' }));
                app.use('/api/notes', require('./routes/notes'));

                module.exports = app;
            """,
            "src/retry.js": """\
                // Retries a flaky call with exponential backoff and random jitter.
                async function withRetry(fn, attempts = 3) {
                  for (let i = 0; ; i++) {
                    try {
                      return await fn();
                    } catch (err) {
                      if (i >= attempts - 1) throw err;
                      const delay = 2 ** i * 100 + Math.random() * 100;
                      await new Promise((resolve) => setTimeout(resolve, delay));
                    }
                  }
                }

                module.exports = { withRetry };
            """,
            "src/version.js": """\
                const { execFile } = require('node:child_process');
                const { promisify } = require('node:util');

                // Build identifier written to the server log at startup.
                async function buildId() {
                  const { stdout } = await promisify(execFile)('git', ['rev-parse', '--short', 'HEAD']);
                  return stdout.trim();
                }

                module.exports = { buildId };
            """,
            "src/routes/notes.js": """\
                const crypto = require('node:crypto');
                const router = require('express').Router();
                const { z } = require('zod');
                const db = require('../db');
                const { requireUser } = require('../auth');
                const { withRetry } = require('../retry');

                const noteSchema = z.object({ title: z.string().min(1).max(120), body: z.string().max(10000) }).strict();
                const idSchema = z.string().uuid();

                router.get('/', requireUser, async (req, res) => {
                  const { rows } = await withRetry(() =>
                    db.query('SELECT id, title, updated_at FROM notes WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 100', [req.user.id]));
                  // Cache validator only: md5 is fine here, nothing relies on collision resistance.
                  const etag = crypto.createHash('md5').update(JSON.stringify(rows)).digest('hex');
                  if (req.headers['if-none-match'] === etag) return res.status(304).end();
                  res.set('ETag', etag).set('Cache-Control', 'private, no-cache').json(rows);
                });

                router.post('/', requireUser, async (req, res) => {
                  const parsed = noteSchema.safeParse(req.body);
                  if (!parsed.success) return res.status(400).json({ error: 'invalid note' });
                  const { rows } = await db.query(
                    'INSERT INTO notes (user_id, title, body) VALUES ($1, $2, $3) RETURNING id',
                    [req.user.id, parsed.data.title, parsed.data.body]);
                  res.status(201).json(rows[0]);
                });

                router.delete('/:id', requireUser, async (req, res) => {
                  const id = idSchema.safeParse(req.params.id);
                  if (!id.success) return res.status(404).end();
                  const { rowCount } = await db.query('DELETE FROM notes WHERE id = $1 AND user_id = $2', [id.data, req.user.id]);
                  res.status(rowCount ? 204 : 404).end();
                });

                module.exports = router;
            """,
        },
    },
    "clean-refactor": {
        "expect": [],
        "note": "A pure refactor with a new unit test. Expected verdict: PASS with no finding.",
        "base": {
            "package.json": '{ "name": "pricing", "private": true, "scripts": { "test": "node --test" } }\n',
            "src/price.js": """\
                function total(items, taxRate) {
                  let sum = 0;
                  for (const item of items) sum += item.unitPrice * item.quantity;
                  return Math.round(sum * (1 + taxRate) * 100) / 100;
                }

                module.exports = { total };
            """,
        },
        "change": {
            "src/price.js": """\
                const { subtotal } = require('./subtotal');

                function roundCents(amount) {
                  return Math.round(amount * 100) / 100;
                }

                function total(items, taxRate) {
                  return roundCents(subtotal(items) * (1 + taxRate));
                }

                module.exports = { total, roundCents };
            """,
            "src/subtotal.js": """\
                function subtotal(items) {
                  return items.reduce((sum, item) => sum + item.unitPrice * item.quantity, 0);
                }

                module.exports = { subtotal };
            """,
            "test/price.test.js": """\
                const test = require('node:test');
                const assert = require('node:assert');
                const { total } = require('../src/price');

                test('total applies tax and rounds to cents', () => {
                  assert.strictEqual(total([{ unitPrice: 9.99, quantity: 3 }], 0.2), 35.96);
                });
            """,
        },
    },
}


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write_tree(root, files):
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path) or root, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(textwrap.dedent(content))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = os.path.abspath(sys.argv[1])
    os.makedirs(out, exist_ok=True)
    for name, case in CASES.items():
        repo, remote = os.path.join(out, name), os.path.join(out, name + ".git")
        if os.path.exists(repo):
            sys.exit(f"{repo} already exists: choose an empty output directory")
        subprocess.run(["git", "init", "-q", "--bare", remote], check=True)
        os.makedirs(repo)
        git(repo, "init", "-q", "-b", "main")
        for key, value in (("user.email", "eval@example.invalid"), ("user.name", "eval"),
                           ("core.autocrlf", "false"), ("commit.gpgsign", "false"), ("core.longpaths", "true")):
            git(repo, "config", key, value)
        write_tree(repo, case["base"])
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "base")
        git(repo, "remote", "add", "origin", remote)
        git(repo, "push", "-q", "-u", "origin", "main")
        write_tree(repo, case["change"])
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "change under review")
        print(f"{name}: {len(case['expect'])} planted finding(s)")


if __name__ == "__main__":
    main()
