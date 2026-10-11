'use strict';
// OUR Galaxy: dependency-free Node.js server. No npm install is needed.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const URL = require('node:url').URL;
const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
const DB = path.join(DATA, 'store.json');
fs.mkdirSync(DATA, {recursive:true});
function readEnv(){try{for(const line of fs.readFileSync(path.join(ROOT,'.env'),'utf8').split(/\r?\n/)){const m=line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);if(m&&!process.env[m[1]])process.env[m[1]]=m[2].replace(/^['"]|['"]$/g,'')}}catch{}}
readEnv();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_USER = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
let store;

try {
  store = JSON.parse(fs.readFileSync(DB, 'utf8'));
} catch {
  store = { users: [], orders: [] };
}

// পুরোনো ডেটা অক্ষত রেখে Wallet-এর জায়গা তৈরি
if (!Array.isArray(store.users)) store.users = [];
if (!Array.isArray(store.orders)) store.orders = [];
if (!Array.isArray(store.walletRequests)) store.walletRequests = [];
if (!Array.isArray(store.walletTransactions)) store.walletTransactions = [];
if (!store.walletBalances || typeof store.walletBalances !== 'object' ||
    Array.isArray(store.walletBalances)) {
  store.walletBalances = {};
}

function save() {
  fs.writeFileSync(DB, JSON.stringify(store, null, 2), 'utf8');
}

save();
function save(){fs.writeFileSync(DB,JSON.stringify(store,null,2),'utf8')}
const sessions = new Map();
const products={ff25:{diamonds:25,label:'Starter Pack'},ff50:{diamonds:50,label:'Mini Pack'},ff100:{diamonds:100,label:'Value Pack'},ff210:{diamonds:210,label:'Plus Pack'},ff530:{diamonds:530,label:'Pro Pack'},ff1080:{diamonds:1080,label:'Max Pack'}};
const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.ico':'image/x-icon'};
function send(res,status,data,headers={}){const body=typeof data==='string'?data:JSON.stringify(data);res.writeHead(status,{'Content-Type':typeof data==='string'?'text/plain; charset=utf-8':'application/json; charset=utf-8','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY','Cache-Control':'no-store',...headers});res.end(body)}
function cookie(req,name){const s=req.headers.cookie||'';const p=s.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='));return p?decodeURIComponent(p.slice(name.length+1)):''}
function auth(req){const id=cookie(req,'ogsid');return sessions.get(id)||null}
function setSession(res,who){const id=crypto.randomBytes(32).toString('hex');sessions.set(id,{...who,created:Date.now()});res.setHeader('Set-Cookie',`ogsid=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`)}
function clearSession(req,res){const id=cookie(req,'ogsid');sessions.delete(id);res.setHeader('Set-Cookie','ogsid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0')}
function readBody(req){return new Promise((resolve,reject)=>{let b='';req.on('data',c=>{b+=c;if(b.length>20000){reject(new Error('Request too large'));req.destroy()}});req.on('end',()=>{try{resolve(b?JSON.parse(b):{})}catch{reject(new Error('Invalid JSON'))}});req.on('error',reject)})}
function needUser(req,res){const s=auth(req);if(!s||s.type!=='user'){send(res,401,{error:'প্রথমে লগইন করো।'});return null}const u=store.users.find(x=>x.id===s.id);if(!u){send(res,401,{error:'অ্যাকাউন্ট পাওয়া যায়নি।'});return null}return u}
function needAdmin(req,res){const s=auth(req);if(!s||s.type!=='admin'){send(res,401,{error:'অ্যাডমিন লগইন প্রয়োজন।'});return false}return true}
function hashPassword(p,salt=crypto.randomBytes(16).toString('hex')){return new Promise((resolve,reject)=>crypto.scrypt(p,salt,64,(e,k)=>e?reject(e):resolve({salt,hash:k.toString('hex')})))}
async function checkPassword(p,record){const k=await hashPassword(p,record.salt);return crypto.timingSafeEqual(Buffer.from(k.hash,'hex'),Buffer.from(record.hash,'hex'))}
const loginAttempts=new Map();function limited(ip){const now=Date.now(),a=loginAttempts.get(ip)||{n:0,t:now};if(now-a.t>600000){a.n=0;a.t=now}a.n++;loginAttempts.set(ip,a);return a.n>12}
async function api(req,res,url){const ip=req.socket.remoteAddress||'unknown';
 if(req.method==='POST'&&url.pathname==='/api/register'){
  if(limited(ip))return send(res,429,{error:'অনেকবার চেষ্টা হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করো।'});
  const b=await readBody(req),name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');
  if(name.length<2||name.length>60)return send(res,400,{error:'নাম ২–৬০ অক্ষরের মধ্যে লিখো।'});if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254)return send(res,400,{error:'সঠিক ইমেইল দাও।'});if(password.length<8||password.length>128)return send(res,400,{error:'পাসওয়ার্ড ৮–১২৮ অক্ষরের হতে হবে।'});if(store.users.some(u=>u.email===email))return send(res,409,{error:'এই ইমেইল দিয়ে আগে অ্যাকাউন্ট তৈরি হয়েছে।'});
  const pw=await hashPassword(password),u={id:crypto.randomUUID(),name,email,password:pw,created_at:new Date().toISOString()};store.users.push(u);save();setSession(res,{type:'user',id:u.id});return send(res,201,{user:{id:u.id,name,email}})
 }
 if(req.method==='POST'&&url.pathname==='/api/login'){
  if(limited(ip))return send(res,429,{error:'অনেকবার চেষ্টা হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করো।'});const b=await readBody(req),email=String(b.email||'').trim().toLowerCase(),u=store.users.find(x=>x.email===email);if(!u||!(await checkPassword(String(b.password||''),u.password)))return send(res,401,{error:'ইমেইল অথবা পাসওয়ার্ড সঠিক নয়।'});setSession(res,{type:'user',id:u.id});return send(res,200,{user:{id:u.id,name:u.name,email:u.email}})
 }
 if(req.method==='GET'&&url.pathname==='/api/me'){const u=needUser(req,res);if(u)return send(res,200,{user:{id:u.id,name:u.name,email:u.email}});return}
 if(req.method==='POST'&&url.pathname==='/api/logout'){clearSession(req,res);return send(res,200,{ok:true})}
 if(req.method==='POST'&&url.pathname==='/api/orders'){
  const u=needUser(req,res);if(!u)return;const b=await readBody(req),p=products[String(b.packageId||'')],uid=String(b.uid||'').trim(),nickname=String(b.nickname||'').trim().slice(0,40),region=String(b.region||'Bangladesh');if(!p)return send(res,400,{error:'সঠিক প্যাকেজ বেছে নাও।'});if(!/^\d{6,12}$/.test(uid))return send(res,400,{error:'৬–১২ সংখ্যার সঠিক Player UID দাও।'});if(!['Bangladesh','Other'].includes(region))return send(res,400,{error:'সঠিক Region বেছে নাও।'});
  const order={order_id:'OG-'+new Date().toISOString().slice(0,10).replace(/-/g,'')+'-'+crypto.randomBytes(3).toString('hex').toUpperCase(),user_id:u.id,customer_name:u.name,email:u.email,uid,nickname,region,package_id:b.packageId,item_name:`Free Fire · ${p.diamonds} Diamonds`,amount:null,status:'Pending',created_at:new Date().toISOString()};store.orders.unshift(order);save();return send(res,201,{order:{order_id:order.order_id,item_name:order.item_name,amount:order.amount,status:order.status,created_at:order.created_at}})
 }
 if(req.method==='GET'&&url.pathname==='/api/orders'){const u=needUser(req,res);if(!u)return;return send(res,200,{orders:store.orders.filter(o=>o.user_id===u.id).slice(0,100).map(({order_id,item_name,amount,status,created_at})=>({order_id,item_name,amount,status,created_at}))})}
 if(req.method==='POST'&&url.pathname==='/api/admin/login'){
  if(limited(ip))return send(res,429,{error:'অনেকবার চেষ্টা হয়েছে। পরে আবার চেষ্টা করো।'});const b=await readBody(req);if(!ADMIN_PASS||!SESSION_SECRET||String(b.username)!==ADMIN_USER||!crypto.timingSafeEqual(crypto.createHash('sha256').update(String(b.password||'')).digest(),crypto.createHash('sha256').update(ADMIN_PASS).digest())){return send(res,401,{error:'লগইন তথ্য সঠিক নয় অথবা .env সেট করা নেই।'})}setSession(res,{type:'admin'});return send(res,200,{ok:true})
 }
 if(req.method==='GET'&&url.pathname==='/api/admin/me'){return auth(req)?.type==='admin'?send(res,200,{ok:true}):send(res,401,{error:'লগইন করা নেই।'})}
 if(req.method==='POST'&&url.pathname==='/api/admin/logout'){clearSession(req,res);return send(res,200,{ok:true})}
 if(url.pathname==='/api/admin/orders'&&req.method==='GET'){if(!needAdmin(req,res))return;return send(res,200,{orders:store.orders.map(o=>({...o,password:undefined}))})}
 if(url.pathname.startsWith('/api/admin/orders/')&&req.method==='PATCH'){if(!needAdmin(req,res))return;const id=decodeURIComponent(url.pathname.split('/').pop()),o=store.orders.find(x=>x.order_id===id);if(!o)return send(res,404,{error:'অর্ডার পাওয়া যায়নি।'});const b=await readBody(req),statuses=['Pending','Price Confirmed','Processing','Completed','Cancelled'];if(!statuses.includes(b.status))return send(res,400,{error:'সঠিক স্ট্যাটাস বেছে নাও।'});let amount=null;if(b.amount!==''&&b.amount!==null&&b.amount!==undefined){amount=Number(b.amount);if(!Number.isFinite(amount)||amount<0||amount>10000000)return send(res,400,{error:'সঠিক মূল্য লিখো।'})}o.status=b.status;o.amount=amount;o.updated_at=new Date().toISOString();save();return send(res,200,{order:{order_id:o.order_id,status:o.status,amount:o.amount}})}
 return send(res,404,{error:'API endpoint পাওয়া যায়নি।'})
}
const server=http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');if(url.pathname.startsWith('/api/'))return await api(req,res,url);let p=decodeURIComponent(url.pathname);if(p==='/')p='/index.html';const file=path.resolve(ROOT,'.'+p);if(!file.startsWith(ROOT+path.sep))return send(res,403,'Forbidden');fs.readFile(file,(err,data)=>{if(err)return send(res,404,'Not found');res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY'});res.end(data)})}catch(e){console.error(e);send(res,e.message==='Invalid JSON'?400:500,{error:e.message==='Invalid JSON'?'সঠিক তথ্য পাঠাও।':'সার্ভারে সমস্যা হয়েছে।'})}});
server.listen(PORT,()=>{console.log(`OUR Galaxy চালু: http://localhost:${PORT}`);if(!ADMIN_PASS||ADMIN_PASS.length<12)console.log('সতর্কতা: .env ফাইলে কমপক্ষে ১২ অক্ষরের ADMIN_PASSWORD সেট করো।');if(!SESSION_SECRET||SESSION_SECRET.length<32)console.log('সতর্কতা: .env ফাইলে কমপক্ষে ৩২ অক্ষরের SESSION_SECRET সেট করো।')});
