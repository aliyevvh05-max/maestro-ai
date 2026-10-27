'use strict';
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cookieParser());
// Keep raw bytes for Paddle signature verification.
app.use('/api/webhook/paddle', express.raw({ type: 'application/json', limit: '1mb' }));
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || '').replace(/\/$/, '');
const JWT_SECRET = process.env.JWT_SECRET;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const PADDLE_API_KEY = process.env.PADDLE_API_KEY;
const PADDLE_WEBHOOK_SECRET = process.env.PADDLE_WEBHOOK_SECRET;
const PADDLE_ENV = process.env.PADDLE_ENV || 'sandbox';
const FREE_CREDITS = Math.max(1, Math.min(1, Number.parseInt(process.env.FREE_CREDITS || '1', 10) || 1));
if (!JWT_SECRET || JWT_SECRET.length < 32) { console.error('JWT_SECRET must be set to a random string of at least 32 characters.'); process.exit(1); }
const PLANS = {
  starter: { name: 'Starter', credits: 20, amount: 9, priceId: process.env.PADDLE_PRICE_STARTER },
  pro: { name: 'Pro', credits: 100, amount: 29, priceId: process.env.PADDLE_PRICE_PRO },
  studio: { name: 'Studio', credits: 500, amount: 49, priceId: process.env.PADDLE_PRICE_STUDIO }
};
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'maestro.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', password_hash TEXT, credits INTEGER NOT NULL DEFAULT 1, google_id TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS generations (id TEXT PRIMARY KEY, email TEXT NOT NULL, style TEXT, category TEXT, room TEXT, palette TEXT, before_image TEXT, after_image TEXT NOT NULL, provider TEXT DEFAULT 'openai', created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS generations_email ON generations(email, created_at DESC);
CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, email TEXT NOT NULL, plan TEXT NOT NULL, credits INTEGER NOT NULL, amount INTEGER NOT NULL, mode TEXT NOT NULL, created_at INTEGER NOT NULL);
`);
const q = {
 user: db.prepare('SELECT * FROM users WHERE email=?'),
 insertUser: db.prepare('INSERT INTO users(email,name,password_hash,credits,created_at) VALUES(?,?,?,?,?)'),
 credits: db.prepare('UPDATE users SET credits=credits+? WHERE email=?'),
 setCredits: db.prepare('UPDATE users SET credits=? WHERE email=?'),
 addGen: db.prepare('INSERT INTO generations(id,email,style,category,room,palette,before_image,after_image,provider,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)'),
 gens: db.prepare('SELECT id,style,category,room,palette,before_image AS "before",after_image AS "after",provider,created_at AS ts FROM generations WHERE email=? ORDER BY created_at DESC LIMIT 100'),
 gen: db.prepare('SELECT * FROM generations WHERE id=? AND email=?'),
 delGen: db.prepare('DELETE FROM generations WHERE id=? AND email=?'),
 order: db.prepare('INSERT OR IGNORE INTO orders(id,email,plan,credits,amount,mode,created_at) VALUES(?,?,?,?,?,?,?)'),
 orders: db.prepare('SELECT id,plan,credits,amount,mode,created_at AS ts FROM orders WHERE email=? ORDER BY created_at DESC LIMIT 100')
};
const signupLimit = rateLimit({ windowMs: 24*60*60*1000, max: 10, standardHeaders: true, legacyHeaders: false });
const authLimit = rateLimit({ windowMs: 15*60*1000, max: 30, standardHeaders: true, legacyHeaders: false });
const genLimit = rateLimit({ windowMs: 60*1000, max: 8, standardHeaders: true, legacyHeaders: false });
const emailNorm = v => String(v || '').trim().toLowerCase();
const validEmail = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254;
const safeUser = u => ({ email: u.email, name: u.name || u.email.split('@')[0], credits: u.credits });
function sign(payload) { return Buffer.from(JSON.stringify(payload)).toString('base64url') + '.' + crypto.createHmac('sha256', JWT_SECRET).update(Buffer.from(JSON.stringify(payload)).toString('base64url')).digest('base64url'); }
function verify(token) { try { if (!JWT_SECRET || !token) return null; const [p,s] = token.split('.'); const expected = crypto.createHmac('sha256', JWT_SECRET).update(p).digest(); const actual = Buffer.from(s, 'base64url'); if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null; const data = JSON.parse(Buffer.from(p,'base64url').toString()); return data.exp > Date.now() ? data : null; } catch { return null; } }
function setSession(res, email) { const token = sign({ email, exp: Date.now()+30*24*60*60*1000 }); res.cookie('maestro_session', token, { httpOnly:true, secure: process.env.NODE_ENV === 'production', sameSite:'lax', maxAge:30*24*60*60*1000, path:'/' }); }
function current(req) { const p = verify(req.cookies.maestro_session); return p ? q.user.get(p.email) : null; }
function needUser(req,res,next) { const u=current(req); if(!u) return res.status(401).json({error:'Please sign in first.'}); req.user=u; next(); }
function emailKey(em) { return emailNorm(em).replace(/@googlemail\.com$/, '@gmail.com'); }
app.get('/api/health', (_req,res) => res.json({ ok:true, ai:!!OPENAI_API_KEY, payments:!!(PADDLE_API_KEY && PADDLE_WEBHOOK_SECRET && Object.values(PLANS).every(p=>p.priceId)), google:!!(GOOGLE_CLIENT_ID&&GOOGLE_CLIENT_SECRET), author:'Created by Aliyev' }));
app.get('/api/meta', (_req,res)=>res.json({appName:'Maestro AI', author:'Created by Aliyev', paddleEnvironment:PADDLE_ENV, googleClientId:GOOGLE_CLIENT_ID||''}));
// Google-only authentication: email/password signup, login and password reset are intentionally disabled.
app.post('/api/generate',genLimit,needUser,async(req,res)=>{
 const u=q.user.get(req.user.email); if(u.credits<1)return res.status(402).json({error:'You have no credits left. Choose a package to continue.'}); if(!OPENAI_API_KEY)return res.status(503).json({error:'AI generation is not configured. Add OPENAI_API_KEY in Render environment variables.'});
 const image=String(req.body.image||''); const match=image.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/); if(!match)return res.status(400).json({error:'Upload a valid JPG, PNG or WebP room photo.'}); if(match[2].length>12*1024*1024)return res.status(413).json({error:'Image is too large. Please upload a smaller photo.'});
 const style=String(req.body.style||'Modern').slice(0,80),category=String(req.body.category||'Interior').slice(0,80),room=String(req.body.room||'Room').slice(0,60),palette=String(req.body.palette||'Auto').slice(0,60),custom=String(req.body.custom||'').slice(0,1000);
 const prompt=`Photorealistic interior redesign of the exact room in the input photo. Preserve the room's structural geometry, walls, windows, doors, camera angle and perspective. Redesign in ${style} style (${category}) for a ${room}. Color palette: ${palette}. Style guidance: ${String(req.body.description||'cohesive materials, realistic lighting, premium interior design').slice(0,500)}. ${custom} Produce a polished, realistic architectural interior photograph, no text, no watermark.`;
 try {
  const form=new FormData(); form.append('model',process.env.OPENAI_IMAGE_MODEL||'gpt-image-1'); form.append('image',new Blob([Buffer.from(match[2],'base64')],{type:match[1]}),'room.'+(match[1].split('/')[1])); form.append('prompt',prompt); form.append('size','1024x1024'); form.append('quality','medium');
  const response=await fetch('https://api.openai.com/v1/images/edits',{method:'POST',headers:{Authorization:`Bearer ${OPENAI_API_KEY}`},body:form}); const payload=await response.json(); if(!response.ok) { console.error('OpenAI generation failed:',payload.error?.message||response.status); return res.status(response.status===429?429:502).json({error:response.status===429?'AI service is busy. Please try again shortly.':'AI generation failed. Check your OpenAI API key, billing and image model access.'}); }
  const b64=payload.data?.[0]?.b64_json; if(!b64)return res.status(502).json({error:'AI provider returned no image.'}); const output='data:image/png;base64,'+b64; const id=crypto.randomUUID();
  const tx=db.transaction(()=>{q.setCredits.run(u.credits-1,u.email);q.addGen.run(id,u.email,style,category,room,palette,image,output,'openai',Date.now());}); tx(); res.json({ok:true,image:output,credits:u.credits-1,generation:{id,style,category,room,palette,before:image,after:output,provider:'openai',ts:Date.now()}});
 }catch(e){console.error('generate:',e.message);res.status(502).json({error:'Generation failed. Please try again.'});}
});
app.get('/api/generations',needUser,(req,res)=>res.json({generations:q.gens.all(req.user.email),orders:q.orders.all(req.user.email)}));
app.delete('/api/generations/:id',needUser,(req,res)=>{q.delGen.run(req.params.id,req.user.email);res.json({ok:true});});
app.post('/api/checkout',needUser,async(req,res)=>{
 const plan=PLANS[req.body.plan]; if(!plan)return res.status(400).json({error:'Choose a valid package.'}); if(!PADDLE_API_KEY||!plan.priceId||!BASE_URL)return res.status(503).json({error:'Paddle is not fully configured. Set PADDLE_API_KEY, BASE_URL and all three PADDLE_PRICE_* IDs in Render.'});
 try { const apiBase=PADDLE_ENV==='production'?'https://api.paddle.com':'https://sandbox-api.paddle.com'; const r=await fetch(apiBase+'/transactions',{method:'POST',headers:{Authorization:`Bearer ${PADDLE_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({items:[{price_id:plan.priceId,quantity:1}],custom_data:{email:req.user.email,plan:req.body.plan},checkout:{url:BASE_URL+'/?checkout=return'}})}); const data=await r.json(); if(!r.ok){console.error('Paddle checkout:',JSON.stringify(data));return res.status(502).json({error:'Could not start checkout. Check Paddle price IDs and API permissions.'});} const url=data.data?.checkout?.url; if(!url)return res.status(502).json({error:'Paddle did not return a checkout URL.'}); res.json({ok:true,url}); } catch(e){console.error('checkout:',e.message);res.status(502).json({error:'Could not start payment.'});}
});
function verifyPaddle(raw,header){ if(!PADDLE_WEBHOOK_SECRET||!header)return false; const parts=Object.fromEntries(header.split(';').map(x=>x.trim().split('='))); if(!parts.ts||!parts.h1||!/^\d+$/.test(parts.ts)||Math.abs(Date.now()/1000-Number(parts.ts))>300)return false; const signed=`${parts.ts}:${raw.toString('utf8')}`; const expected=crypto.createHmac('sha256',PADDLE_WEBHOOK_SECRET).update(signed).digest('hex'); try{return crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(parts.h1));}catch{return false;} }
app.post('/api/webhook/paddle',(req,res)=>{
 const raw=Buffer.isBuffer(req.body)?req.body:Buffer.from(JSON.stringify(req.body||{})); if(!verifyPaddle(raw,req.get('Paddle-Signature')))return res.status(401).json({error:'Invalid webhook signature.'});
 try {const event=JSON.parse(raw.toString('utf8')); if(event.event_type==='transaction.completed'){const t=event.data||{},email=emailKey(t.custom_data?.email||t.customer?.email),planKey=t.custom_data?.plan,plan=PLANS[planKey];if(!plan||!email||!t.id)return res.status(400).json({error:'Missing transaction metadata.'}); const item=t.items?.[0]; if(item?.price?.id!==plan.priceId)return res.status(400).json({error:'Price does not match selected package.'}); const tx=db.transaction(()=>{const result=q.order.run(String(t.id),email,planKey,plan.credits,plan.amount,'paddle',Date.now());if(result.changes)q.credits.run(plan.credits,email);});tx();} res.json({received:true});}catch(e){console.error('Paddle webhook:',e.message);res.status(500).json({received:false});}
});
// Google OAuth: configure exact callback URL as BASE_URL/api/auth/google/callback in Google Cloud Console.
app.get('/api/auth/google',(req,res)=>{if(!GOOGLE_CLIENT_ID||!BASE_URL)return res.status(503).send('Google sign-in is not configured.');const state=crypto.randomBytes(24).toString('hex');res.cookie('google_oauth_state',state,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',maxAge:10*60*1000});const u=new URL('https://accounts.google.com/o/oauth2/v2/auth');u.searchParams.set('client_id',GOOGLE_CLIENT_ID);u.searchParams.set('redirect_uri',BASE_URL+'/api/auth/google/callback');u.searchParams.set('response_type','code');u.searchParams.set('scope','openid email profile');u.searchParams.set('state',state);u.searchParams.set('prompt','select_account');res.redirect(u.toString());});
app.get('/api/auth/google/callback',async(req,res)=>{try{if(!GOOGLE_CLIENT_ID||!GOOGLE_CLIENT_SECRET||!BASE_URL)throw new Error('Google OAuth is not configured');if(!req.query.state||req.query.state!==req.cookies.google_oauth_state)throw new Error('Invalid Google OAuth state');const tokenRes=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code:String(req.query.code||''),client_id:GOOGLE_CLIENT_ID,client_secret:GOOGLE_CLIENT_SECRET,redirect_uri:BASE_URL+'/api/auth/google/callback',grant_type:'authorization_code'})});const tokens=await tokenRes.json();if(!tokenRes.ok||!tokens.access_token)throw new Error('Google token exchange failed');const profileRes=await fetch('https://www.googleapis.com/oauth2/v2/userinfo',{headers:{Authorization:'Bearer '+tokens.access_token}});const profile=await profileRes.json();const email=emailKey(profile.email);if(!profile.verified_email||!validEmail(email))throw new Error('Google did not return a verified email');let u=q.user.get(email);if(!u){q.insertUser.run(email,String(profile.name||'').slice(0,100),null,FREE_CREDITS,Date.now());u=q.user.get(email);}setSession(res,email);res.clearCookie('google_oauth_state');res.redirect('/?google=success');}catch(e){console.error('Google OAuth:',e.message);res.redirect('/?google=error');}});
app.get('*',(_req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.listen(PORT,()=>console.log(`Maestro AI listening on ${PORT} · Created by Aliyev`));
