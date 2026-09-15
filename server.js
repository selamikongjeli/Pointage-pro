
const express=require('express'),crypto=require('crypto'),path=require('path');
const {Pool}=require('pg');
const app=express(),PORT=process.env.PORT||3000,SECRET=process.env.POINTAGE_SECRET||'change-me';
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:false});
app.use(express.json());app.use(express.static(path.join(__dirname,'public')));
const hp=(p,s)=>crypto.scryptSync(String(p),s,32).toString('hex');
const mk=p=>{let s=crypto.randomBytes(16).toString('hex');return{salt:s,hash:hp(p,s)}};
const ok=(p,r)=>!!(r && r.pin_salt && r.pin_hash) && hp(p,r.pin_salt)===r.pin_hash;
const sig=p=>crypto.createHmac('sha256',SECRET).update(p).digest('hex');
const token=()=>{let p=String(Math.floor(Date.now()/60000));return p+'.'+sig(p)};
function valid(t){try{let [p,s]=String(t||'').split('.');for(let o of [0,-1,1]){let q=String(Math.floor(Date.now()/60000)+o),a=Buffer.from(s||''),b=Buffer.from(sig(q));if(p===q&&a.length===b.length&&crypto.timingSafeEqual(a,b))return true}}catch{}return false}
async function init(){await pool.query(`
CREATE TABLE IF NOT EXISTS settings(id int primary key,company text not null default 'Mon entreprise',admin_pin_salt text,admin_pin_hash text);
INSERT INTO settings(id) VALUES(1) ON CONFLICT(id) DO NOTHING;
CREATE TABLE IF NOT EXISTS staff(id uuid primary key,name text not null,code text unique not null,role text not null default 'Employé',active boolean not null default true,pin_salt text not null,pin_hash text not null);
CREATE TABLE IF NOT EXISTS punches(id uuid primary key,staff_id uuid not null references staff(id) on delete cascade,type text not null,time timestamptz not null default now());
CREATE INDEX IF NOT EXISTS idx_punch ON punches(staff_id,time);`)}
async function settings(){return (await pool.query('select * from settings where id=1')).rows[0]}
async function auth(req,res,next){let r=await settings();if(!r.admin_pin_hash)return res.status(428).json({error:'ADMIN_NOT_SETUP'});if(!ok(req.headers['x-admin-pin']||'',r))return res.status(401).json({error:'BAD_ADMIN_PIN'});next()}
async function staff(code){return (await pool.query('select * from staff where code=$1 and active=true',[code])).rows[0]}
app.get('/api/status',async(req,res)=>{let r=await settings();res.json({adminSetup:!!r.admin_pin_hash,company:r.company})});
app.post('/api/setup',async(req,res)=>{let r=await settings();if(r.admin_pin_hash)return res.status(409).json({error:'ALREADY'});let pin=String(req.body.pin||'');if(pin.length<4)return res.status(400).json({error:'PIN'});let p=mk(pin);await pool.query('update settings set company=$1,admin_pin_salt=$2,admin_pin_hash=$3 where id=1',[req.body.company||'Mon entreprise',p.salt,p.hash]);res.json({ok:true})});
app.get('/api/qr',auth,(req,res)=>res.json({token:token(),expiresIn:60-(Math.floor(Date.now()/1000)%60)}));
app.get('/api/staff',auth,async(req,res)=>res.json((await pool.query('select id,name,code,role,active from staff order by name')).rows));
app.post('/api/staff',auth,async(req,res)=>{let pin=String(req.body.pin||'');if(!req.body.name||!req.body.code||pin.length<4)return res.status(400).json({error:'INVALID'});let p=mk(pin);try{await pool.query('insert into staff(id,name,code,role,pin_salt,pin_hash) values($1,$2,$3,$4,$5,$6)',[crypto.randomUUID(),req.body.name,req.body.code,req.body.role||'Employé',p.salt,p.hash]);res.json({ok:true})}catch(e){res.status(409).json({error:'CODE_EXISTS'})}});
app.post('/api/login',async(req,res)=>{let s=await staff(String(req.body.code||''));if(!s||!ok(req.body.pin||'',s))return res.status(401).json({error:'BAD_LOGIN'});res.json({ok:true,staff:{name:s.name,role:s.role}})});
function next(last,a){if(!last)return a==='in';if(last.type==='out')return a==='in';if(last.type==='in')return a==='pause_start'||a==='out';if(last.type==='pause_start')return a==='pause_end';if(last.type==='pause_end')return a==='pause_start'||a==='out';return false}
app.post('/api/punch',async(req,res)=>{if(!valid(req.body.token))return res.status(400).json({error:'QR_EXPIRED'});let s=await staff(String(req.body.code||''));if(!s||!ok(req.body.pin||'',s))return res.status(401).json({error:'BAD_LOGIN'});let a=req.body.action;if(!['in','pause_start','pause_end','out'].includes(a))return res.status(400).json({error:'BAD_ACTION'});let last=(await pool.query('select * from punches where staff_id=$1 order by time desc limit 1',[s.id])).rows[0];if(!next(last,a))return res.status(409).json({error:'INVALID_SEQUENCE'});let q=await pool.query('insert into punches(id,staff_id,type) values($1,$2,$3) returning time',[crypto.randomUUID(),s.id,a]);res.json({ok:true,type:a,time:q.rows[0].time,name:s.name})});
app.get('/api/history',auth,async(req,res)=>res.json((await pool.query("select p.type,p.time,s.name as staff_name,s.code from punches p join staff s on s.id=p.staff_id order by p.time desc limit 1000")).rows));
app.get('/api/report',auth,async(req,res)=>{let m=String(req.query.month||new Date().toISOString().slice(0,7)),st=m+'-01';let rows=(await pool.query("select s.id,s.name,s.code,p.type,p.time from staff s left join punches p on p.staff_id=s.id and p.time >= $1::date and p.time < ($1::date + interval '1 month') where s.active=true order by s.name,p.time",[st])).rows,by={};for(let r of rows){by[r.id]??={name:r.name,code:r.code,e:[]};if(r.type)by[r.id].e.push(r)}let employees=Object.values(by).map(x=>{let work=0,pause=0,inn=null,ps=null;for(let e of x.e){let t=new Date(e.time);if(e.type==='in')inn=t;else if(e.type==='pause_start')ps=t;else if(e.type==='pause_end'&&ps){pause+=t-ps;ps=null}else if(e.type==='out'&&inn){work+=t-inn;inn=null}}return{name:x.name,code:x.code,hours:+Math.max(0,(work-pause)/3600000).toFixed(2),events:x.e.length}});res.json({month:m,employees})});
app.get('/api/export.csv',auth,async(req,res)=>{let m=String(req.query.month||new Date().toISOString().slice(0,7)),st=m+'-01';let rows=(await pool.query("select s.name,s.code,p.type,p.time from punches p join staff s on s.id=p.staff_id where p.time >= $1::date and p.time < ($1::date + interval '1 month') order by s.name,p.time",[st])).rows,L={in:'Entrée',pause_start:'Début pause',pause_end:'Fin pause',out:'Sortie'},lines=['Employé;Code;Action;Date/heure'];for(let r of rows)lines.push([r.name,r.code,L[r.type],new Date(r.time).toLocaleString('fr-BE')].map(v=>`"${String(v).replaceAll('"','""')}"`).join(';'));res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition',`attachment; filename="pointage-${m}.csv"`);res.send('\ufeff'+lines.join('\n'))});
async function resetAdminPin(){
  const p=mk('1234');
  await pool.query(
    'UPDATE settings SET admin_pin_salt=$1, admin_pin_hash=$2 WHERE id=1',
    [p.salt,p.hash]
  );
  console.log('PIN patron réinitialisé à 1234');
}
init()
  .then(resetAdminPin)
  .then(()=>app.listen(PORT,()=>console.log('Pointage Pro v3 prêt')))
  .catch(e=>{console.error(e);process.exit(1)});
