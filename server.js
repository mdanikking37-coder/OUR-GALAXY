'use strict';
// OUR Galaxy: dependency-free Node.js server. No npm install is needed.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const URL = require('node:url').URL;
const { Pool } = require('pg');
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

if (!store.products || typeof store.products !== 'object' || Array.isArray(store.products)) {
  store.products = {
    ff25: { diamonds: 25, label: 'Starter Pack' },
    ff50: { diamonds: 50, label: 'Mini Pack' },
    ff100: { diamonds: 100, label: 'Value Pack' },
    ff210: { diamonds: 210, label: 'Plus Pack' },
    ff530: { diamonds: 530, label: 'Pro Pack' },
    ff1080: { diamonds: 1080, label: 'Max Pack' }
  };
  save();
}
const products = store.products;
if (!Array.isArray(store.memberships)) {
  store.memberships = [
    { id: 'weekly-lite', name: 'Weekly Lite', price: 43, image: '' },
    { id: 'weekly', name: 'Weekly', price: 156, image: '' },
    { id: 'monthly', name: 'Monthly', price: 779, image: '' }
  ];
  save();
}

const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.ico':'image/x-icon'};
function send(res,status,data,headers={}){const body=typeof data==='string'?data:JSON.stringify(data);res.writeHead(status,{'Content-Type':typeof data==='string'?'text/plain; charset=utf-8':'application/json; charset=utf-8','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY','Cache-Control':'no-store',...headers});res.end(body)}
function cookie(req,name){const s=req.headers.cookie||'';const p=s.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='));return p?decodeURIComponent(p.slice(name.length+1)):''}
function auth(req){const id=cookie(req,'ogsid');return sessions.get(id)||null}
function setSession(res,who){const id=crypto.randomBytes(32).toString('hex');sessions.set(id,{...who,created:Date.now()});res.setHeader('Set-Cookie',`ogsid=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`)}
function clearSession(req,res){const id=cookie(req,'ogsid');sessions.delete(id);res.setHeader('Set-Cookie','ogsid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0')}

function readBody(req, limit = 20000) {
  return new Promise((resolve, reject) => {
    let b = '';
    let rejected = false;

    req.on('data', chunk => {
      if (rejected) return;

      b += chunk.toString('utf8');

      if (Buffer.byteLength(b, 'utf8') > limit) {
        rejected = true;
        reject(new Error('Request too large'));
        req.destroy();
      }
    });

    req.on('end', () => {
      if (rejected) return;

      try {
        resolve(b ? JSON.parse(b) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', error => {
      if (!rejected) reject(error);
    });
  });
}

function needUser(req,res){const s=auth(req);if(!s||s.type!=='user'){send(res,401,{error:'প্রথমে লগইন করো।'});return null}const u=store.users.find(x=>x.id===s.id);if(!u){send(res,401,{error:'অ্যাকাউন্ট পাওয়া যায়নি।'});return null}return u}
function needAdmin(req,res){const s=auth(req);if(!s||s.type!=='admin'){send(res,401,{error:'অ্যাডমিন লগইন প্রয়োজন।'});return false}return true}
function hashPassword(p,salt=crypto.randomBytes(16).toString('hex')){return new Promise((resolve,reject)=>crypto.scrypt(p,salt,64,(e,k)=>e?reject(e):resolve({salt,hash:k.toString('hex')})))}
async function checkPassword(p,record){const k=await hashPassword(p,record.salt);return crypto.timingSafeEqual(Buffer.from(k.hash,'hex'),Buffer.from(record.hash,'hex'))}
const loginAttempts=new Map();function limited(ip){const now=Date.now(),a=loginAttempts.get(ip)||{n:0,t:now};if(now-a.t>600000){a.n=0;a.t=now}a.n++;loginAttempts.set(ip,a);return a.n>12}
function walletBalance(userId) {
  return Number(store.walletBalances[userId] || 0);
}
async function api(req,res,url){const ip=req.socket.remoteAddress||'unknown';

 if (req.method === 'GET' && url.pathname === '/api/wallet') {
  const u = needUser(req, res);
  if (!u) return;

  return send(res, 200, {
    balance: walletBalance(u.id),
    requests: store.walletRequests
      .filter(r => r.user_id === u.id)
      .map(({request_id, method, amount, transaction_id, status, created_at}) =>
        ({request_id, method, amount, transaction_id, status, created_at}))
      .slice(0, 50),
    transactions: store.walletTransactions
      .filter(t => t.user_id === u.id)
      .slice(0, 50)
  });
 }

 if (req.method === 'POST' && url.pathname === '/api/wallet/deposit') {
  const u = needUser(req, res);
  if (!u) return;

  const b = await readBody(req);
  const method = String(b.method || '');
  const amount = Number(b.amount);
  const transactionId = String(b.transaction_id || '').trim();

  if (!['bKash', 'Nagad', 'Rocket'].includes(method)) {
    return send(res, 400, {error: 'bKash, Nagad অথবা Rocket বেছে নাও।'});
  }

  if (!Number.isSafeInteger(amount) || amount < 20 || amount > 50000) {
    return send(res, 400, {error: '২০ থেকে ৫০,০০০ টাকার মধ্যে পরিমাণ দাও।'});
  }

  if (transactionId.length < 5 || transactionId.length > 100) {
    return send(res, 400, {error: 'সঠিক Transaction ID দাও।'});
  }

  const duplicate = store.walletRequests.some(r =>
    r.method === method &&
    r.transaction_id.toLowerCase() === transactionId.toLowerCase()
  );

  if (duplicate) {
    return send(res, 409, {error: 'এই Transaction ID আগে জমা দেওয়া হয়েছে।'});
  }

  const request = {
    request_id: crypto.randomUUID(),
    user_id: u.id,
    method,
    amount,
    transaction_id: transactionId,
    status: 'Pending',
    created_at: new Date().toISOString()
  };

  store.walletRequests.unshift(request);
  save();

  return send(res, 201, {
    message: 'অনুরোধ জমা হয়েছে। অ্যাডমিন যাচাই করার পর ব্যালেন্স যোগ হবে।',
    request: {
      request_id: request.request_id,
      amount: request.amount,
      status: request.status
    }
  });
 }
                                
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
                                
 if (req.method === 'GET' && url.pathname === '/api/admin/wallet/requests') {
  if (!needAdmin(req, res)) return;

  return send(res, 200, {
    requests: store.walletRequests.map(r => ({
      request_id: r.request_id,
      user_id: r.user_id,
      customer_name: store.users.find(u => u.id === r.user_id)?.name || 'Unknown',
      email: store.users.find(u => u.id === r.user_id)?.email || '',
      method: r.method,
      amount: r.amount,
      transaction_id: r.transaction_id,
      status: r.status,
      created_at: r.created_at
    }))
  });
 }

 if (
  req.method === 'PATCH' &&
  url.pathname.startsWith('/api/admin/wallet/requests/')
 ) {
  if (!needAdmin(req, res)) return;

  const id = decodeURIComponent(url.pathname.split('/').pop());
  const r = store.walletRequests.find(x => x.request_id === id);

  if (!r) {
    return send(res, 404, {error: 'পেমেন্ট অনুরোধ পাওয়া যায়নি।'});
  }

  if (r.status !== 'Pending') {
    return send(res, 409, {error: 'এই অনুরোধ আগেই নিষ্পত্তি হয়েছে।'});
  }

  const b = await readBody(req);

  if (!['approve', 'reject'].includes(b.action)) {
    return send(res, 400, {error: 'সঠিক অ্যাকশন বেছে নাও।'});
  }

  const userExists = store.users.some(u => u.id === r.user_id);
  if (!userExists) {
    return send(res, 404, {error: 'ইউজার অ্যাকাউন্ট পাওয়া যায়নি।'});
  }

  if (b.action === 'approve') {
    const oldBalance = walletBalance(r.user_id);
    const newBalance = oldBalance + r.amount;

    if (!Number.isSafeInteger(newBalance)) {
      return send(res, 400, {error: 'ব্যালেন্স হিসাব করা যাচ্ছে না।'});
    }

    store.walletBalances[r.user_id] = newBalance;
    store.walletTransactions.unshift({
      transaction_id: crypto.randomUUID(),
      user_id: r.user_id,
      type: 'Deposit',
      amount: r.amount,
      method: r.method,
      reference: r.transaction_id,
      created_at: new Date().toISOString()
    });

    r.status = 'Approved';
  } else {
    r.status = 'Rejected';
  }

  r.reviewed_at = new Date().toISOString();
  save();

  return send(res, 200, {
    message: r.status === 'Approved'
      ? 'পেমেন্ট অনুমোদিত হয়েছে।'
      : 'পেমেন্ট বাতিল করা হয়েছে।',
    status: r.status
  });
 }

 if(url.pathname==='/api/admin/orders'&&req.method==='GET'){if(!needAdmin(req,res))return;return send(res,200,{orders:store.orders.map(o=>({...o,password:undefined}))})}
 if(url.pathname.startsWith('/api/admin/orders/')&&req.method==='PATCH'){if(!needAdmin(req,res))return;const id=decodeURIComponent(url.pathname.split('/').pop()),o=store.orders.find(x=>x.order_id===id);if(!o)return send(res,404,{error:'অর্ডার পাওয়া যায়নি।'});const b=await readBody(req),statuses=['Pending','Price Confirmed','Processing','Completed','Cancelled'];if(!statuses.includes(b.status))return send(res,400,{error:'সঠিক স্ট্যাটাস বেছে নাও।'});let amount=null;if(b.amount!==''&&b.amount!==null&&b.amount!==undefined){amount=Number(b.amount);if(!Number.isFinite(amount)||amount<0||amount>10000000)return send(res,400,{error:'সঠিক মূল্য লিখো।'})}o.status=b.status;o.amount=amount;o.updated_at=new Date().toISOString();save();return send(res,200,{order:{order_id:o.order_id,status:o.status,amount:o.amount}})}
 if (req.method === 'GET' && url.pathname === '/api/memberships') {
  return send(res, 200, {
    memberships: store.memberships
  });
}

if (req.method === 'GET' && url.pathname === '/api/admin/memberships') {
  if (!needAdmin(req, res)) return;

  return send(res, 200, {
    memberships: store.memberships
  });
}

if (req.method === 'PATCH' &&
if (req.method === 'PATCH' &&
    url.pathname.startsWith('/api/admin/memberships/')) {
  if (!needAdmin(req, res)) return;

  const id = decodeURIComponent(url.pathname.split('/').pop());
  const membership = store.memberships.find(item => item.id === id);

  if (!membership) {
    return send(res, 404, {
      error: 'Membership পাওয়া যায়নি।'
    });
  }

  const body = await readBody(req, 400000);

  if (body.image !== undefined) {
    const image = String(body.image || '');

    if (
      image &&
      !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(image)
    ) {
      return send(res, 400, {
        error: 'JPG, PNG অথবা WebP ছবি আপলোড করো।'
      });
    }

    if (image.length > 300000) {
      return send(res, 413, {
        error: 'ছবিটি অনেক বড়। ছোট ছবি বেছে নাও।'
      });
    }

    membership.image = image;
  }

  if (body.price !== undefined) {
    const price = Number(body.price);

    if (!Number.isFinite(price) || price < 1 || price > 100000) {
      return send(res, 400, {
        error: 'দাম ১ থেকে ১০০০০০ টাকার মধ্যে দাও।'
      });
    }

    membership.price = price;
  }

  save();

  return send(res, 200, {
    message: 'Membership-এর তথ্য সংরক্ষিত হয়েছে।',
    membership
  });
}  if (!needAdmin(req, res)) return;

  const id = decodeURIComponent(url.pathname.split('/').pop());
  const membership = store.memberships.find(item => item.id === id);

  if (!membership) {
    return send(res, 404, {
      error: 'Membership পাওয়া যায়নি।'
    });
  }

  const body = await readBody(req, 400000);
  const image = String(body.image || '');

  if (
    image &&
    !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(image)
  ) {
    return send(res, 400, {
      error: 'JPG, PNG অথবা WebP ছবি আপলোড করো।'
    });
  }

  if (image.length > 300000) {
    return send(res, 413, {
      error: 'ছবিটি অনেক বড়। ছোট ছবি বেছে নাও।'
    });
  }

  membership.image = image;
  save();

  return send(res, 200, {
    message: 'Membership-এর ছবি সংরক্ষিত হয়েছে।',
    membership
  });
}                               
 if (req.method === 'GET' && url.pathname === '/api/products') {
  return send(
    res,
    200,
    {
      products: Object.entries(store.products).map(([id, p]) => ({
        id,
        ...p
      }))
    },
    { 'Access-Control-Allow-Origin': '*' }
  );
} 

if (req.method === 'POST' &&
    url.pathname === '/api/admin/products/bulk-import') {
  if (!needAdmin(req, res)) return;

  const packages = [
    [25, 20], [50, 35], [100, 70], [115, 78],
    [240, 157], [355, 237], [480, 315], [505, 337],
    [610, 395], [725, 479], [850, 559], [965, 635],
    [1015, 689], [1090, 719], [1240, 789],
    [1595, 1035], [1850, 1199], [2090, 1349],
    [2530, 1590], [3140, 1995], [4010, 2559],
    [5060, 3179], [10120, 6350]
  ];

  for (const [diamonds, price] of packages) {
    const id = 'ff' + diamonds;
    const old = store.products[id] || {};

    store.products[id] = {
      ...old,
      diamonds,
      label: diamonds + ' Diamond',
      price
    };
  }

  save();

  return send(res, 200, {
    message: '২৩টি Diamond প্যাকেজ যোগ বা আপডেট হয়েছে।',
    count: packages.length
  });
}

if (req.method === 'POST' &&
    url.pathname === '/api/admin/products/bulk-import') {
  if (!needAdmin(req, res)) return;

  const packages = [
    [25, 20], [50, 35], [100, 70], [115, 78],
    [240, 157], [355, 237], [480, 315], [505, 337],
    [610, 395], [725, 479], [850, 559], [965, 635],
    [1015, 689], [1090, 719], [1240, 789],
    [1595, 1035], [1850, 1199], [2090, 1349],
    [2530, 1590], [3140, 1995], [4010, 2559],
    [5060, 3179], [10120, 6350]
  ];

  for (const [diamonds, price] of packages) {
    const id = 'ff' + diamonds;
    const old = store.products[id] || {};

    store.products[id] = {
      ...old,
      diamonds,
      label: diamonds + ' Diamond',
      price
    };
  }

  save();

  return send(res, 200, {
    message: '২৩টি Diamond প্যাকেজ যোগ বা আপডেট হয়েছে।',
    count: packages.length
  });
}
                                
if (req.method === 'GET' && url.pathname === '/api/admin/products') {
  if (!needAdmin(req, res)) return;
  return send(res, 200, { products: Object.entries(store.products).map(([id, p]) => ({ id, ...p })) });
}

if (req.method === 'POST' && url.pathname === '/api/admin/products') {
  if (!needAdmin(req, res)) return;
  const b = await readBody(req);
  const id = String(b.id || '').trim();
  const label = String(b.label || '').trim();
  const diamonds = Number(b.diamonds);
  const price = Number(b.price);

  if (!/^[a-zA-Z0-9_-]{2,40}$/.test(id) || store.products[id]) {
    return send(res, 400, { error: 'প্যাকেজ ID ভুল অথবা আগে থেকেই আছে।' });
  }
  if (!label || label.length > 80 ||
      !Number.isSafeInteger(diamonds) || diamonds < 1 ||
      !Number.isSafeInteger(price) || price < 1 || price > 1000000) {
    return send(res, 400, { error: 'প্যাকেজের নাম, ডায়মন্ড ও দাম সঠিকভাবে দাও।' });
  }

  store.products[id] = { label, diamonds, price };
  save();
  return send(res, 201, { message: 'নতুন প্যাকেজ যোগ হয়েছে।', product: { id, ...store.products[id] } });
}

if (req.method === 'DELETE' &&
    url.pathname.startsWith('/api/admin/products/')) {
  if (!needAdmin(req, res)) return;

  const id = decodeURIComponent(url.pathname.split('/').pop());

  if (!store.products[id]) {
    return send(res, 404, { error: 'প্যাকেজ পাওয়া যায়নি।' });
  }

  delete store.products[id];
  save();

  return send(res, 200, {
    message: 'প্যাকেজ মুছে ফেলা হয়েছে।'
  });
}

if (req.method === 'PATCH' && url.pathname.startsWith('/api/admin/products/')) {
  if (!needAdmin(req, res)) return;
  const id = decodeURIComponent(url.pathname.split('/').pop());
  const p = store.products[id];
  if (!p) return send(res, 404, { error: 'প্যাকেজ পাওয়া যায়নি।' });

  const b = await readBody(req);
  const label = String(b.label ?? p.label).trim();
  const diamonds = Number(b.diamonds ?? p.diamonds);
  const price = Number(b.price ?? p.price);

  if (!label || label.length > 80 ||
      !Number.isSafeInteger(diamonds) || diamonds < 1 ||
      !Number.isSafeInteger(price) || price < 1 || price > 1000000) {
    return send(res, 400, { error: 'নাম, ডায়মন্ড বা দাম সঠিক নয়।' });
  }

  Object.assign(p, { label, diamonds, price });
  save();
  return send(res, 200, { message: 'প্যাকেজ আপডেট হয়েছে।', product: { id, ...p } });
}

 return send(res,404,{error:'API endpoint পাওয়া যায়নি।'})
}
const server=http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');if(url.pathname.startsWith('/api/'))return await api(req,res,url);let p=decodeURIComponent(url.pathname);if(p==='/')p='/index.html';const file=path.resolve(ROOT,'.'+p);if(!file.startsWith(ROOT+path.sep))return send(res,403,'Forbidden');fs.readFile(file,(err,data)=>{if(err)return send(res,404,'Not found');res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY'});res.end(data)})}catch(e){console.error(e);send(res,e.message==='Invalid JSON'?400:500,{error:e.message==='Invalid JSON'?'সঠিক তথ্য পাঠাও।':'সার্ভারে সমস্যা হয়েছে।'})}});
server.listen(PORT,()=>{console.log(`OUR Galaxy চালু: http://localhost:${PORT}`);if(!ADMIN_PASS||ADMIN_PASS.length<12)console.log('সতর্কতা: .env ফাইলে কমপক্ষে ১২ অক্ষরের ADMIN_PASSWORD সেট করো।');if(!SESSION_SECRET||SESSION_SECRET.length<32)console.log('সতর্কতা: .env ফাইলে কমপক্ষে ৩২ অক্ষরের SESSION_SECRET সেট করো।')});
