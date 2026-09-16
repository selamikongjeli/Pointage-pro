
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
// ===== QR PERMANENT PAR ETABLISSEMENT =====

function permanentQR(establishmentId){
  const payload=Buffer.from(
    'EST:'+String(establishmentId)
  ).toString('base64url');

  const signature=sig('PERMANENT:'+payload);

  return payload+'.'+signature;
}

function readPermanentQR(token){
  try{
    const parts=String(token||'').split('.');

    if(parts.length!==2){
      return null;
    }

    const payload=parts[0];
    const signature=parts[1];

    const expected=sig('PERMANENT:'+payload);

    const a=Buffer.from(signature);
    const b=Buffer.from(expected);

    if(a.length!==b.length){
      return null;
    }

    if(!crypto.timingSafeEqual(a,b)){
      return null;
    }

    const text=Buffer.from(
      payload,
      'base64url'
    ).toString('utf8');

    if(!text.startsWith('EST:')){
      return null;
    }

    const establishmentId=text.slice(4);

    if(!establishmentId){
      return null;
    }

    return establishmentId;

  }catch(e){
    return null;
  }
}
async function init(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings(
      id int primary key,
      company text not null default 'Mon entreprise',
      admin_pin_salt text,
      admin_pin_hash text
    );

    INSERT INTO settings(id)
    VALUES(1)
    ON CONFLICT(id) DO NOTHING;

    CREATE TABLE IF NOT EXISTS establishments(
      id uuid primary key,
      name text not null,
      address text,
      latitude double precision,
      longitude double precision,
      radius_m integer not null default 30,
      active boolean not null default true,
      created_at timestamptz not null default now()
    );

    CREATE TABLE IF NOT EXISTS managers(
      id uuid primary key,
      establishment_id uuid not null references establishments(id) on delete cascade,
      name text not null,
      username text unique not null,
      pin_salt text not null,
      pin_hash text not null,
      active boolean not null default true,
      created_at timestamptz not null default now()
    );
ALTER TABLE managers
ADD COLUMN IF NOT EXISTS session_version integer NOT NULL DEFAULT 1;
    CREATE TABLE IF NOT EXISTS staff(
      id uuid primary key,
      name text not null,
      code text unique not null,
      role text not null default 'Employé',
      active boolean not null default true,
      pin_salt text,
      pin_hash text
    );

    ALTER TABLE staff
    ADD COLUMN IF NOT EXISTS establishment_id uuid
    REFERENCES establishments(id) ON DELETE SET NULL;

    CREATE TABLE IF NOT EXISTS punches(
      id uuid primary key,
      staff_id uuid not null references staff(id) on delete cascade,
      type text not null,
      time timestamptz not null default now()
    );

    ALTER TABLE punches
    ADD COLUMN IF NOT EXISTS establishment_id uuid
    REFERENCES establishments(id) ON DELETE SET NULL;
ALTER TABLE establishments
ADD COLUMN IF NOT EXISTS closing_time time NOT NULL DEFAULT '23:30';

ALTER TABLE establishments
ADD COLUMN IF NOT EXISTS max_day_span_minutes integer NOT NULL DEFAULT 660;

ALTER TABLE establishments
ADD COLUMN IF NOT EXISTS weekly_max_minutes integer NOT NULL DEFAULT 3000;

ALTER TABLE establishments
ALTER COLUMN radius_m SET DEFAULT 30;

ALTER TABLE punches
ADD COLUMN IF NOT EXISTS automatic boolean NOT NULL DEFAULT false;

ALTER TABLE punches
ADD COLUMN IF NOT EXISTS auto_reason text;
    CREATE INDEX IF NOT EXISTS idx_punch
    ON punches(staff_id,time);

    CREATE INDEX IF NOT EXISTS idx_staff_establishment
    ON staff(establishment_id);

    CREATE INDEX IF NOT EXISTS idx_punch_establishment
    ON punches(establishment_id,time);
  `);
}
async function settings(){return (await pool.query('select * from settings where id=1')).rows[0]}
async function auth(req,res,next){let r=await settings();if(!r.admin_pin_hash)return res.status(428).json({error:'ADMIN_NOT_SETUP'});if(!r.admin_pin_salt || hp(req.headers['x-admin-pin']||'',r.admin_pin_salt)!==r.admin_pin_hash)return res.status(401).json({error:'BAD_ADMIN_PIN'});next()}
async function staff(code){return (await pool.query('select * from staff where code=$1 and active=true',[code])).rows[0]}
// ===== SUPER ADMIN : ETABLISSEMENTS =====

app.get('/api/admin/establishments', auth, async(req,res)=>{
  const q = await pool.query(`
    SELECT e.*,
      (SELECT COUNT(*) FROM staff s WHERE s.establishment_id=e.id) AS staff_count,
      (SELECT COUNT(*) FROM managers m WHERE m.establishment_id=e.id AND m.active=true) AS manager_count
    FROM establishments e
    ORDER BY e.created_at DESC
  `);

  res.json(q.rows);
});

app.post('/api/admin/establishments', auth, async(req,res)=>{
  const name = String(req.body.name || '').trim();
  const address = String(req.body.address || '').trim();

  const latitude =
    req.body.latitude === '' || req.body.latitude == null
      ? null
      : Number(req.body.latitude);

  const longitude =
    req.body.longitude === '' || req.body.longitude == null
      ? null
      : Number(req.body.longitude);

  const radius = Number(req.body.radius_m || 30);

  if(!name){
    return res.status(400).json({error:'NAME_REQUIRED'});
  }

  if(latitude !== null && !Number.isFinite(latitude)){
    return res.status(400).json({error:'BAD_LATITUDE'});
  }

  if(longitude !== null && !Number.isFinite(longitude)){
    return res.status(400).json({error:'BAD_LONGITUDE'});
  }

  if(!Number.isFinite(radius) || radius < 20 || radius > 2000){
    return res.status(400).json({error:'BAD_RADIUS'});
  }

  const id = crypto.randomUUID();

  const q = await pool.query(`
    INSERT INTO establishments
      (id,name,address,latitude,longitude,radius_m)
    VALUES($1,$2,$3,$4,$5,$6)
    RETURNING *
  `,[id,name,address,latitude,longitude,radius]);

  res.json(q.rows[0]);
});
// ===== POSITION GPS ETABLISSEMENT =====

app.patch('/api/admin/establishments/:id/location',auth,async(req,res)=>{
  const latitude=Number(req.body.latitude);
  const longitude=Number(req.body.longitude);
  const radius=Number(req.body.radius_m || 30);

  if(
    !Number.isFinite(latitude) ||
    latitude < -90 ||
    latitude > 90
  ){
    return res.status(400).json({error:'BAD_LATITUDE'});
  }

  if(
    !Number.isFinite(longitude) ||
    longitude < -180 ||
    longitude > 180
  ){
    return res.status(400).json({error:'BAD_LONGITUDE'});
  }

  if(
    !Number.isFinite(radius) ||
    radius < 20 ||
    radius > 2000
  ){
    return res.status(400).json({error:'BAD_RADIUS'});
  }

  const q=await pool.query(`
    UPDATE establishments
    SET
      latitude=$1,
      longitude=$2,
      radius_m=$3
    WHERE id=$4
    RETURNING
      id,
      name,
      address,
      latitude,
      longitude,
      radius_m
  `,[
    latitude,
    longitude,
    radius,
    req.params.id
  ]);

  if(!q.rows[0]){
    return res.status(404).json({
      error:'ESTABLISHMENT_NOT_FOUND'
    });
  }

  res.json({
    ok:true,
    establishment:q.rows[0]
  });
});

app.post('/api/admin/establishments/:id/manager', auth, async(req,res)=>{
  const establishmentId = req.params.id;
  const name = String(req.body.name || '').trim();
  const username = String(req.body.username || '').trim().toLowerCase();
  const pin = String(req.body.pin || '');

  if(!name || !username || pin.length < 4){
    return res.status(400).json({error:'INVALID'});
  }

  const est = await pool.query(
    'SELECT id FROM establishments WHERE id=$1 AND active=true',
    [establishmentId]
  );

  if(!est.rows[0]){
    return res.status(404).json({error:'ESTABLISHMENT_NOT_FOUND'});
  }

  const p = mk(pin);

  try{
    const q = await pool.query(`
      INSERT INTO managers
        (id,establishment_id,name,username,pin_salt,pin_hash)
      VALUES($1,$2,$3,$4,$5,$6)
      RETURNING id,establishment_id,name,username,active
    `,[
      crypto.randomUUID(),
      establishmentId,
      name,
      username,
      p.salt,
      p.hash
    ]);

    res.json(q.rows[0]);

  }catch(e){
    if(e.code === '23505'){
      return res.status(409).json({error:'USERNAME_ALREADY_EXISTS'});
    }

    console.error(e);
    res.status(500).json({error:'SERVER_ERROR'});
  }
});
// ===== CONNEXION RESPONSABLE =====

function makeManagerToken(m){
  const payload=Buffer.from(JSON.stringify({
  mid:m.id,
  eid:m.establishment_id,
  sv:m.session_version,
  exp:Date.now()+(12*60*60*1000)
})).toString('base64url');

  const signature=crypto
    .createHmac('sha256',SECRET)
    .update('manager:'+payload)
    .digest('hex');

  return payload+'.'+signature;
}

function readManagerToken(token){
  try{
    const parts=String(token||'').split('.');
    if(parts.length!==2) return null;

    const payload=parts[0];
    const signature=parts[1];

    const expected=crypto
      .createHmac('sha256',SECRET)
      .update('manager:'+payload)
      .digest('hex');

    if(signature.length!==expected.length) return null;

    if(!crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    )) return null;

    const data=JSON.parse(
      Buffer.from(payload,'base64url').toString('utf8')
    );

   if(!data.mid || !data.eid || !data.sv || !data.exp) return null;
    if(Date.now()>data.exp) return null;

    return data;

  }catch(e){
    return null;
  }
}

async function managerAuth(req,res,next){
  const h=String(req.headers.authorization||'');

  const token=h.startsWith('Bearer ')
    ? h.slice(7)
    : '';

  const data=readManagerToken(token);

  if(!data){
    return res.status(401).json({
      error:'BAD_MANAGER_TOKEN'
    });
  }

  const q=await pool.query(`
  SELECT
    m.id,
    m.name,
    m.username,
    m.establishment_id,
    m.session_version,
    e.name AS establishment_name
  FROM managers m
  JOIN establishments e
    ON e.id=m.establishment_id
  WHERE
    m.id=$1
    AND m.establishment_id=$2
    AND m.session_version=$3
    AND m.active=true
    AND e.active=true
  LIMIT 1
`,[data.mid,data.eid,data.sv]);

  if(!q.rows[0]){
    return res.status(401).json({
      error:'MANAGER_DISABLED'
    });
  }

  req.manager=q.rows[0];
  next();
}

app.post('/api/manager/login',async(req,res)=>{
  const username=String(req.body.username||'')
    .trim()
    .toLowerCase();

  const pin=String(req.body.pin||'');

  const q=await pool.query(`
    SELECT
      m.id,
      m.name,
      m.username,
      m.establishment_id,
      m.session_version,
      m.pin_salt,
      m.pin_hash,
      e.name AS establishment_name
    FROM managers m
    JOIN establishments e
      ON e.id=m.establishment_id
    WHERE
      LOWER(m.username)=LOWER($1)
      AND m.active=true
      AND e.active=true
    LIMIT 1
  `,[username]);

  const m=q.rows[0];

  if(!m || !ok(pin,m)){
    return res.status(401).json({
      error:'BAD_MANAGER_LOGIN'
    });
  }

  res.json({
    ok:true,
    token:makeManagerToken(m),
    manager:{
      id:m.id,
      name:m.name,
      username:m.username,
      establishment_id:m.establishment_id,
      establishment_name:m.establishment_name
    }
  });
});

app.get('/api/manager/me',managerAuth,(req,res)=>{
  res.json({
    ok:true,
    manager:req.manager
  });
});

app.get('/api/manager/permanent-qr',managerAuth,(req,res)=>{
  res.json({
    ok:true,
    establishment_id:req.manager.establishment_id,
    establishment_name:req.manager.establishment_name,
    token:permanentQR(req.manager.establishment_id)
  });
});
app.get('/api/admin/establishments/:id/managers',auth,async(req,res)=>{
  const q=await pool.query(`
    SELECT id,name,username,active
    FROM managers
    WHERE establishment_id=$1
    ORDER BY name
  `,[req.params.id]);

  res.json(q.rows);
});

app.patch('/api/admin/managers/:id/reset-pin',auth,async(req,res)=>{
  const pin=String(req.body.pin||'');

  if(pin.length<4){
    return res.status(400).json({error:'PIN'});
  }

  const p=mk(pin);

  const q=await pool.query(`
    UPDATE managers
    SET
      pin_salt=$1,
      pin_hash=$2,
      session_version=session_version+1
    WHERE id=$3
    RETURNING id,name,username
  `,[p.salt,p.hash,req.params.id]);

  if(!q.rows[0]){
    return res.status(404).json({error:'NOT_FOUND'});
  }

  res.json({
    ok:true,
    manager:q.rows[0]
  });
});
// ===== EMPLOYES DU RESPONSABLE =====

app.get('/api/manager/staff',managerAuth,async(req,res)=>{
  const q=await pool.query(`
    SELECT id,name,code,role,active
    FROM staff
    WHERE establishment_id=$1
    AND active=true
    ORDER BY name
  `,[req.manager.establishment_id]);

  res.json(q.rows);
});

app.post('/api/manager/staff',managerAuth,async(req,res)=>{
  const name=String(req.body.name||'').trim();
  const code=String(req.body.code||'').trim();
  const role=String(req.body.role||'Employé').trim();
  const pin=String(req.body.pin||'');

  if(!name || !code || pin.length<4){
    return res.status(400).json({error:'INVALID'});
  }

  const p=mk(pin);

  try{
    await pool.query(`
      INSERT INTO staff
        (id,name,code,role,pin_salt,pin_hash,establishment_id)
      VALUES($1,$2,$3,$4,$5,$6,$7)
    `,[
      crypto.randomUUID(),
      name,
      code,
      role,
      p.salt,
      p.hash,
      req.manager.establishment_id
    ]);

    res.json({ok:true});

  }catch(e){
    if(e.code==='23505'){
      return res.status(409).json({error:'CODE_EXISTS'});
    }

    console.error(e);
    res.status(500).json({error:'SERVER_ERROR'});
  }
});

app.patch('/api/manager/staff/:id',managerAuth,async(req,res)=>{
  const id=req.params.id;
  const name=String(req.body.name||'').trim();
  const code=String(req.body.code||'').trim();
  const role=String(req.body.role||'Employé').trim();
  const pin=String(req.body.pin||'');

  if(!name || !code){
    return res.status(400).json({error:'INVALID'});
  }

  try{
    if(pin){
      if(pin.length<4){
        return res.status(400).json({error:'PIN'});
      }

      const p=mk(pin);

      const q=await pool.query(`
        UPDATE staff
        SET name=$1,code=$2,role=$3,pin_salt=$4,pin_hash=$5
        WHERE id=$6 AND establishment_id=$7
        RETURNING id
      `,[
        name,code,role,p.salt,p.hash,
        id,req.manager.establishment_id
      ]);

      if(!q.rows[0]){
        return res.status(404).json({error:'NOT_FOUND'});
      }

    }else{

      const q=await pool.query(`
        UPDATE staff
        SET name=$1,code=$2,role=$3
        WHERE id=$4 AND establishment_id=$5
        RETURNING id
      `,[
        name,code,role,
        id,req.manager.establishment_id
      ]);

      if(!q.rows[0]){
        return res.status(404).json({error:'NOT_FOUND'});
      }
    }

    res.json({ok:true});

  }catch(e){
    if(e.code==='23505'){
      return res.status(409).json({error:'CODE_EXISTS'});
    }

    console.error(e);
    res.status(500).json({error:'SERVER_ERROR'});
  }
});

app.delete('/api/manager/staff/:id',managerAuth,async(req,res)=>{

  const q=await pool.query(`
    UPDATE staff
    SET active=false
    WHERE id=$1
      AND establishment_id=$2
      AND active=true
    RETURNING id,name,code
  `,[
    req.params.id,
    req.manager.establishment_id
  ]);

  if(!q.rows[0]){
    return res.status(404).json({
      error:'NOT_FOUND'
    });
  }

  res.json({
    ok:true,
    staff:q.rows[0]
  });
});

  res.json({ok:true});
});
app.get('/api/status',async(req,res)=>{let r=await settings();res.json({adminSetup:!!r.admin_pin_hash,company:r.company})});
app.post('/api/setup',async(req,res)=>{let r=await settings();if(r.admin_pin_hash)return res.status(409).json({error:'ALREADY'});let pin=String(req.body.pin||'');if(pin.length<4)return res.status(400).json({error:'PIN'});let p=mk(pin);await pool.query('update settings set company=$1,admin_pin_salt=$2,admin_pin_hash=$3 where id=1',[req.body.company||'Mon entreprise',p.salt,p.hash]);res.json({ok:true})});
app.get('/api/qr',auth,(req,res)=>res.json({token:token(),expiresIn:60-(Math.floor(Date.now()/1000)%60)}));
app.get('/api/staff',auth,async(req,res)=>
  res.json(
    (
      await pool.query(`
        SELECT id,name,code,role,active
        FROM staff
        WHERE active=true
        ORDER BY name
      `)
    ).rows
  )
);
app.post('/api/staff',auth,async(req,res)=>{let pin=String(req.body.pin||'');if(!req.body.name||!req.body.code||pin.length<4)return res.status(400).json({error:'INVALID'});let p=mk(pin);try{await pool.query('insert into staff(id,name,code,role,pin_salt,pin_hash) values($1,$2,$3,$4,$5,$6)',[crypto.randomUUID(),req.body.name,req.body.code,req.body.role||'Employé',p.salt,p.hash]);res.json({ok:true})}catch(e){res.status(409).json({error:'CODE_EXISTS'})}});
app.patch('/api/staff/:id',auth,async(req,res)=>{
  let id=req.params.id;
  let name=String(req.body.name||'').trim();
  let code=String(req.body.code||'').trim();
  let role=String(req.body.role||'Employé').trim();
  let pin=String(req.body.pin||'');

  if(!name||!code) return res.status(400).json({error:'INVALID'});

  try{
    if(pin){
      if(pin.length<4) return res.status(400).json({error:'PIN'});
      let p=mk(pin);
      await pool.query(
        'update staff set name=$1,code=$2,role=$3,pin_salt=$4,pin_hash=$5 where id=$6',
        [name,code,role,p.salt,p.hash,id]
      );
    }else{
      await pool.query(
        'update staff set name=$1,code=$2,role=$3 where id=$4',
        [name,code,role,id]
      );
    }
    res.json({ok:true});
  }catch(e){
    res.status(409).json({error:'CODE_EXISTS'});
  }
});

app.delete('/api/staff/:id',auth,async(req,res)=>{

  const q=await pool.query(`
    UPDATE staff
    SET active=false
    WHERE id=$1
      AND active=true
    RETURNING id,name,code
  `,[req.params.id]);

  if(!q.rows[0]){
    return res.status(404).json({
      error:'NOT_FOUND'
    });
  }

  res.json({
    ok:true,
    staff:q.rows[0]
  });
});
});
app.post('/api/login',async(req,res)=>{
  let s=await staff(String(req.body.code||''));

  if(!s || !ok(req.body.pin||'',s)){
    return res.status(401).json({
      error:'BAD_LOGIN'
    });
  }

  res.json({
    ok:true,
    staff:{
      name:s.name,
      role:s.role
    }
  });
});
// ===== LIMITES TEMPS DE TRAVAIL =====

async function establishmentRules(s){
  if(!s.establishment_id) return null;

  const q=await pool.query(`
    SELECT
      id,
      closing_time,
      max_day_span_minutes,
      weekly_max_minutes
    FROM establishments
    WHERE id=$1 AND active=true
    LIMIT 1
  `,[s.establishment_id]);

  return q.rows[0] || null;
}


async function firstInOfDay(staffId,referenceTime){
  const q=await pool.query(`
    SELECT time
    FROM punches
    WHERE staff_id=$1
      AND type='in'
      AND (time AT TIME ZONE 'Europe/Brussels')::date =
          ($2::timestamptz AT TIME ZONE 'Europe/Brussels')::date
    ORDER BY time
    LIMIT 1
  `,[staffId,referenceTime]);

  return q.rows[0]
    ? new Date(q.rows[0].time)
    : null;
}


async function closingDate(referenceTime,closingTime){
  const q=await pool.query(`
    SELECT (
      (
        ($1::timestamptz AT TIME ZONE 'Europe/Brussels')::date
        + $2::time
      )
      AT TIME ZONE 'Europe/Brussels'
    ) AS closing
  `,[referenceTime,closingTime]);

  return new Date(q.rows[0].closing);
}


async function weekEvents(staffId,referenceTime,until){
  const q=await pool.query(`
    SELECT type,time
    FROM punches
    WHERE staff_id=$1

      AND
      (time AT TIME ZONE 'Europe/Brussels') >=
      date_trunc(
        'week',
        $2::timestamptz AT TIME ZONE 'Europe/Brussels'
      )

      AND
      (time AT TIME ZONE 'Europe/Brussels') <
      date_trunc(
        'week',
        $2::timestamptz AT TIME ZONE 'Europe/Brussels'
      ) + interval '7 days'

      AND time <= $3

    ORDER BY time
  `,[staffId,referenceTime,until]);

  return q.rows;
}


function workedMs(events,until=null){

  let total=0;
  let activeStart=null;

  for(const e of events){

    const t=new Date(e.time);

    if(until && t>until){
      break;
    }

    if(e.type==='in'){

      activeStart=t;

    }else if(e.type==='pause_start'){

      if(activeStart){
        total+=t-activeStart;
        activeStart=null;
      }

    }else if(e.type==='pause_end'){

      activeStart=t;

    }else if(e.type==='out'){

      if(activeStart){
        total+=t-activeStart;
      }

      activeStart=null;
    }
  }

  if(until && activeStart){
    total+=until-activeStart;
  }

  return Math.max(0,total);
}


function timeWhenWorkReached(events,until,targetMs){

  if(targetMs<=0){
    const first=events.find(e=>e.type==='in');

    return first
      ? new Date(first.time)
      : null;
  }

  let done=0;
  let activeStart=null;

  for(const e of events){

    const t=new Date(e.time);

    if(t>until){
      break;
    }

    if(e.type==='in'){

      activeStart=t;

    }else if(
      e.type==='pause_start' ||
      e.type==='out'
    ){

      if(activeStart){

        const segment=t-activeStart;

        if(done+segment>=targetMs){

          return new Date(
            activeStart.getTime()+
            (targetMs-done)
          );
        }

        done+=segment;
        activeStart=null;
      }

    }else if(e.type==='pause_end'){

      activeStart=t;
    }
  }

  if(activeStart){

    const segment=until-activeStart;

    if(done+segment>=targetMs){

      return new Date(
        activeStart.getTime()+
        (targetMs-done)
      );
    }
  }

  return null;
}


async function weeklyWorkedMs(staffId,referenceTime,until){

  const events=await weekEvents(
    staffId,
    referenceTime,
    until
  );

  return workedMs(events,until);
}


// Vérifie s'il faut créer une sortie automatique
async function enforceAutomaticExit(s){

  const rules=await establishmentRules(s);

  if(!rules){
    return null;
  }

  const lastQ=await pool.query(`
    SELECT *
    FROM punches
    WHERE staff_id=$1
    ORDER BY time DESC
    LIMIT 1
  `,[s.id]);

  const last=lastQ.rows[0];

  if(!last || last.type==='out'){
    return null;
  }


  const inQ=await pool.query(`
    SELECT time
    FROM punches
    WHERE staff_id=$1
      AND type='in'
      AND time <= $2
    ORDER BY time DESC
    LIMIT 1
  `,[s.id,last.time]);

  if(!inQ.rows[0]){
    return null;
  }

  const shiftStart=
    new Date(inQ.rows[0].time);


  const shiftEventsQ=await pool.query(`
    SELECT type,time
    FROM punches
    WHERE staff_id=$1
      AND time >= $2
    ORDER BY time
  `,[s.id,shiftStart]);

  const shiftEvents=shiftEventsQ.rows;


  // Première entrée de la journée
  const firstIn=
    await firstInOfDay(
      s.id,
      shiftStart
    );

  const rawDayLimit=
    new Date(
      firstIn.getTime()+
      Number(rules.max_day_span_minutes)*60000
    );

  // Sécurité : jamais avant le début du service actuel
  const dayLimit=
    new Date(
      Math.max(
        rawDayLimit.getTime(),
        shiftStart.getTime()
      )
    );


  // Heure de fermeture de l'établissement
  const rawClosing=
    await closingDate(
      shiftStart,
      rules.closing_time
    );

  const closingLimit=
    new Date(
      Math.max(
        rawClosing.getTime(),
        shiftStart.getTime()
      )
    );


  const now=new Date();

  const hardUntil=new Date(
    Math.min(
      now.getTime(),
      dayLimit.getTime(),
      closingLimit.getTime()
    )
  );


  // Heures déjà faites dans la semaine
  // avant le service actuel
  const beforeShift=
    new Date(
      shiftStart.getTime()-1
    );

  const previousWeekEvents=
    await weekEvents(
      s.id,
      shiftStart,
      beforeShift
    );

  const previousWeekMs=
    workedMs(previousWeekEvents);

  const weeklyLimitMs=
    Number(rules.weekly_max_minutes)*60000;

  const remainingWeekMs=
    weeklyLimitMs-previousWeekMs;


  let weeklyLimitTime=null;

  if(remainingWeekMs<=0){

    weeklyLimitTime=shiftStart;

  }else{

    weeklyLimitTime=
      timeWhenWorkReached(
        shiftEvents,
        hardUntil,
        remainingWeekMs
      );
  }


  const candidates=[];


  if(dayLimit<=now){
    candidates.push({
      time:dayLimit,
      reason:'MAX_JOUR'
    });
  }


  if(closingLimit<=now){
    candidates.push({
      time:closingLimit,
      reason:'FERMETURE_ETABLISSEMENT'
    });
  }


  if(
    weeklyLimitTime &&
    weeklyLimitTime<=now
  ){
    candidates.push({
      time:weeklyLimitTime,
      reason:'MAX_SEMAINE'
    });
  }


  if(!candidates.length){
    return null;
  }


  candidates.sort(
    (a,b)=>a.time-b.time
  );

  const exit=candidates[0];


  // Vérification supplémentaire pour éviter
  // une double sortie automatique
  const check=await pool.query(`
    SELECT type
    FROM punches
    WHERE staff_id=$1
    ORDER BY time DESC
    LIMIT 1
  `,[s.id]);

  if(
    !check.rows[0] ||
    check.rows[0].type==='out'
  ){
    return null;
  }


  await pool.query(`
    INSERT INTO punches(
      id,
      staff_id,
      establishment_id,
      type,
      time,
      automatic,
      auto_reason
    )
    VALUES(
      $1,$2,$3,'out',$4,true,$5
    )
  `,[
    crypto.randomUUID(),
    s.id,
    s.establishment_id,
    exit.time,
    exit.reason
  ]);


  return exit;
}


// ===== POINTAGE EMPLOYE =====
// ===== DISTANCE GPS =====

function distanceMeters(lat1,lon1,lat2,lon2){

  const R=6371000;

  const rad=n=>
    Number(n)*Math.PI/180;

  const dLat=
    rad(lat2-lat1);

  const dLon=
    rad(lon2-lon1);

  const a=
    Math.sin(dLat/2)*
    Math.sin(dLat/2)
    +
    Math.cos(rad(lat1))*
    Math.cos(rad(lat2))*
    Math.sin(dLon/2)*
    Math.sin(dLon/2);

  const c=
    2*Math.atan2(
      Math.sqrt(a),
      Math.sqrt(1-a)
    );

  return R*c;
}

app.post('/api/punch',async(req,res)=>{

  const s=await staff(
    String(req.body.code||'')
  );

  if(
    !s ||
    !ok(req.body.pin||'',s)
  ){
    return res.status(401).json({
      error:'BAD_LOGIN'
    });
  }


  const action=req.body.action;

  if(
    ![
      'in',
      'pause_start',
      'pause_end',
      'out'
    ].includes(action)
  ){
    return res.status(400).json({
      error:'BAD_ACTION'
    });
  }


  // ===== QR PERMANENT =====

  const qrEstablishmentId=
    readPermanentQR(req.body.token);

  if(!qrEstablishmentId){
    return res.status(400).json({
      error:'BAD_QR'
    });
  }


  if(
    !s.establishment_id ||
    String(s.establishment_id)!==
    String(qrEstablishmentId)
  ){
    return res.status(403).json({
      error:'WRONG_ESTABLISHMENT'
    });
  }


  // ===== GPS EMPLOYE =====

  const latitude=
    Number(req.body.latitude);

  const longitude=
    Number(req.body.longitude);

  const accuracy=
    Number(req.body.accuracy);


  if(
    !Number.isFinite(latitude) ||
    !Number.isFinite(longitude)
  ){
    return res.status(400).json({
      error:'GPS_REQUIRED'
    });
  }


  if(
    Number.isFinite(accuracy) &&
    accuracy>100
  ){
    return res.status(400).json({
      error:'GPS_INACCURATE',
      accuracy
    });
  }


  const estQ=await pool.query(`
    SELECT
      id,
      latitude,
      longitude,
      radius_m
    FROM establishments
    WHERE id=$1
      AND active=true
    LIMIT 1
  `,[qrEstablishmentId]);


  const establishment=
    estQ.rows[0];


  if(!establishment){
    return res.status(404).json({
      error:'ESTABLISHMENT_NOT_FOUND'
    });
  }


  if(
    establishment.latitude==null ||
    establishment.longitude==null
  ){
    return res.status(409).json({
      error:'GPS_NOT_CONFIGURED'
    });
  }


  const distance=
    distanceMeters(
      latitude,
      longitude,
      Number(establishment.latitude),
      Number(establishment.longitude)
    );


  const radius=
    Number(establishment.radius_m || 30);


  if(distance>radius){
    return res.status(403).json({
      error:'TOO_FAR',
      distance:Math.round(distance),
      radius
    });
  }


  // Vérifie les sorties automatiques
  await enforceAutomaticExit(s);


  const lastQ=await pool.query(`
    SELECT *
    FROM punches
    WHERE staff_id=$1
    ORDER BY time DESC
    LIMIT 1
  `,[s.id]);

  const last=lastQ.rows[0];


  if(!next(last,action)){

    if(
      last &&
      last.type==='out' &&
      last.automatic
    ){
      return res.status(409).json({
        error:'AUTO_CLOSED',
        reason:last.auto_reason,
        time:last.time
      });
    }

    return res.status(409).json({
      error:'INVALID_SEQUENCE'
    });
  }


  const rules=
    await establishmentRules(s);


  if(action==='in' && rules){

    const now=new Date();


    const localTime=await pool.query(`
      SELECT
        (
          $1::timestamptz
          AT TIME ZONE 'Europe/Brussels'
        )::time >= $2::time
        AS closed
    `,[now,rules.closing_time]);


    if(localTime.rows[0].closed){
      return res.status(409).json({
        error:'ESTABLISHMENT_CLOSED'
      });
    }


    const firstIn=
      await firstInOfDay(
        s.id,
        now
      );


    if(firstIn){

      const dayDeadline=
        new Date(
          firstIn.getTime()+
          Number(
            rules.max_day_span_minutes
          )*60000
        );


      if(now>=dayDeadline){
        return res.status(409).json({
          error:'DAY_LIMIT'
        });
      }
    }


    const weekMs=
      await weeklyWorkedMs(
        s.id,
        now,
        now
      );


    const weekLimitMs=
      Number(
        rules.weekly_max_minutes
      )*60000;


    if(weekMs>=weekLimitMs){
      return res.status(409).json({
        error:'WEEK_LIMIT'
      });
    }
  }


  const q=await pool.query(`
    INSERT INTO punches(
      id,
      staff_id,
      establishment_id,
      type
    )
    VALUES($1,$2,$3,$4)
    RETURNING time
  `,[
    crypto.randomUUID(),
    s.id,
    qrEstablishmentId,
    action
  ]);


  res.json({
    ok:true,
    type:action,
    time:q.rows[0].time,
    name:s.name,
    distance:Math.round(distance),
    radius
  });
});
function next(last, a) {
  if (!last) return a === 'in';

  if (last.type === 'in')
    return a === 'pause_start' || a === 'out';

  if (last.type === 'pause_start')
    return a === 'pause_end';

  if (last.type === 'pause_end')
    return a === 'pause_start' || a === 'out';

  if (last.type === 'out')
    return a === 'in';

  return false;
}

app.get('/api/history',auth,async(req,res)=>res.json((await pool.query("select p.type,p.time,s.name as staff_name,s.code from punches p join staff s on s.id=p.staff_id order by p.time desc limit 1000")).rows));
// ===== RAPPORTS JOUR / SEMAINE / MOIS =====

function reportDayKey(value){
  const parts=new Intl.DateTimeFormat('en-CA',{
    timeZone:'Europe/Brussels',
    year:'numeric',
    month:'2-digit',
    day:'2-digit'
  }).formatToParts(new Date(value));

  const p={};

  for(const x of parts){
    if(x.type!=='literal'){
      p[x.type]=x.value;
    }
  }

  return p.year+'-'+p.month+'-'+p.day;
}


function weekStartFromDay(day){
  const d=new Date(day+'T12:00:00Z');

  const diff=(d.getUTCDay()+6)%7;

  d.setUTCDate(
    d.getUTCDate()-diff
  );

  return d.toISOString().slice(0,10);
}


function addDaysToDay(day,number){
  const d=new Date(day+'T12:00:00Z');

  d.setUTCDate(
    d.getUTCDate()+number
  );

  return d.toISOString().slice(0,10);
}


async function buildHoursReport(month,establishmentId=null){

  if(!/^\d{4}-\d{2}$/.test(month)){
    throw new Error('BAD_MONTH');
  }


  // Employés concernés
  let staffSql=`
    SELECT
      id,
      name,
      code,
      establishment_id
    FROM staff
    WHERE active=true
  `;

  const staffParams=[];

  if(establishmentId){
    staffParams.push(establishmentId);

    staffSql+=`
      AND establishment_id=$1
    `;
  }

  staffSql+=`
    ORDER BY name
  `;


  const staffRows=
    (await pool.query(
      staffSql,
      staffParams
    )).rows;


  // Applique d'abord les éventuelles
  // sorties automatiques 11h / 50h / 23h30
  for(const s of staffRows){
    try{
      await enforceAutomaticExit(s);
    }catch(e){
      console.error(
        'AUTO EXIT REPORT',
        s.id,
        e
      );
    }
  }


  const params=[month];

  let establishmentFilter='';

  if(establishmentId){
    params.push(establishmentId);

    establishmentFilter=`
      AND s.establishment_id=$2
    `;
  }


  // On prend les semaines complètes
  // qui touchent le mois demandé
  const punches=
    (await pool.query(`
      SELECT
        p.staff_id,
        p.type,
        p.time,
        p.automatic,
        p.auto_reason

      FROM punches p

      JOIN staff s
        ON s.id=p.staff_id

      WHERE
        s.active=true

        ${establishmentFilter}

        AND
        (
          p.time
          AT TIME ZONE 'Europe/Brussels'
        )::date
        >=
        date_trunc(
          'week',
          ($1 || '-01')::date
        )::date

        AND
        (
          p.time
          AT TIME ZONE 'Europe/Brussels'
        )::date
        <
        (
          date_trunc(
            'week',
            (
              ($1 || '-01')::date
              + interval '1 month'
              - interval '1 day'
            )
          )::date
          + 7
        )

      ORDER BY
        p.staff_id,
        p.time
    `,params)).rows;


  const eventsByStaff={};

  for(const p of punches){

    if(!eventsByStaff[p.staff_id]){
      eventsByStaff[p.staff_id]=[];
    }

    eventsByStaff[p.staff_id].push(p);
  }


  const daily=[];


  for(const person of staffRows){

    const events=
      eventsByStaff[person.id] || [];

    const days={};

    let shift=null;


    function saveShift(){

      if(!shift){
        return;
      }


      if(!days[shift.day]){

        days[shift.day]={
          workMs:0,
          pauseMs:0,
          events:0,
          firstIn:null,
          lastOut:null,
          open:false,
          automaticExits:0,
          reasons:new Set()
        };
      }


      const d=days[shift.day];

      d.workMs+=shift.workMs;
      d.pauseMs+=shift.pauseMs;
      d.events+=shift.events;

      d.open=d.open || shift.open;


      if(
        !d.firstIn ||
        shift.firstIn<d.firstIn
      ){
        d.firstIn=shift.firstIn;
      }


      if(
        shift.lastOut &&
        (
          !d.lastOut ||
          shift.lastOut>d.lastOut
        )
      ){
        d.lastOut=shift.lastOut;
      }


      if(shift.automatic){
        d.automaticExits++;
      }


      for(const reason of shift.reasons){
        d.reasons.add(reason);
      }


      shift=null;
    }


    for(const event of events){

      const time=new Date(event.time);


      if(event.type==='in'){

        // Sécurité anciennes données
        if(shift){
          saveShift();
        }


        shift={
          day:reportDayKey(time),
          firstIn:time,
          lastOut:null,
          activeStart:time,
          pauseStart:null,
          workMs:0,
          pauseMs:0,
          events:1,
          open:true,
          automatic:false,
          reasons:new Set()
        };

        continue;
      }


      if(!shift){
        continue;
      }


      shift.events++;


      if(event.type==='pause_start'){

        if(shift.activeStart){

          shift.workMs+=
            time-shift.activeStart;

          shift.activeStart=null;
        }

        shift.pauseStart=time;

      }else if(event.type==='pause_end'){

        if(shift.pauseStart){

          shift.pauseMs+=
            time-shift.pauseStart;

          shift.pauseStart=null;
        }

        shift.activeStart=time;

      }else if(event.type==='out'){

        if(shift.activeStart){

          shift.workMs+=
            time-shift.activeStart;

          shift.activeStart=null;
        }


        // Si la sortie automatique tombe
        // pendant une pause
        if(shift.pauseStart){

          shift.pauseMs+=
            time-shift.pauseStart;

          shift.pauseStart=null;
        }


        shift.lastOut=time;
        shift.open=false;


        if(event.automatic){

          shift.automatic=true;

          if(event.auto_reason){
            shift.reasons.add(
              event.auto_reason
            );
          }
        }


        saveShift();
      }
    }


    // Service encore en cours aujourd'hui
    if(shift){

      const now=new Date();

      if(
        reportDayKey(now)===
        shift.day
      ){

        if(shift.activeStart){

          shift.workMs+=
            now-shift.activeStart;

          shift.activeStart=now;
        }


        if(shift.pauseStart){

          shift.pauseMs+=
            now-shift.pauseStart;

          shift.pauseStart=now;
        }
      }


      shift.open=true;

      saveShift();
    }


    for(const [date,d] of Object.entries(days)){

      daily.push({
        staff_id:person.id,
        name:person.name,
        code:person.code,

        date,

        work_minutes:
          Math.round(
            d.workMs/60000
          ),

        pause_minutes:
          Math.round(
            d.pauseMs/60000
          ),

        events:d.events,

        first_in:
          d.firstIn
            ? d.firstIn.toISOString()
            : null,

        last_out:
          d.lastOut
            ? d.lastOut.toISOString()
            : null,

        open:d.open,

        automatic_exits:
          d.automaticExits,

        auto_reasons:
          Array.from(d.reasons)
      });
    }
  }


  // ===== PAR SEMAINE =====

  const weeklyMap={};


  for(const d of daily){

    const weekStart=
      weekStartFromDay(d.date);

    const key=
      d.staff_id+'|'+weekStart;


    if(!weeklyMap[key]){

      weeklyMap[key]={
        staff_id:d.staff_id,
        name:d.name,
        code:d.code,

        week_start:weekStart,

        week_end:
          addDaysToDay(
            weekStart,
            6
          ),

        work_minutes:0,
        pause_minutes:0,
        days:0,
        automatic_exits:0
      };
    }


    const w=weeklyMap[key];

    w.work_minutes+=
      d.work_minutes;

    w.pause_minutes+=
      d.pause_minutes;

    w.days++;

    w.automatic_exits+=
      d.automatic_exits;
  }


  const weekly=
    Object.values(weeklyMap);


  // ===== PAR MOIS =====

  const monthlyMap={};


  for(const person of staffRows){

    monthlyMap[person.id]={
      staff_id:person.id,
      name:person.name,
      code:person.code,

      work_minutes:0,
      pause_minutes:0,
      days:0,
      events:0,
      automatic_exits:0
    };
  }


  for(const d of daily){

    if(
      !d.date.startsWith(
        month+'-'
      )
    ){
      continue;
    }


    const m=
      monthlyMap[d.staff_id];


    if(!m){
      continue;
    }


    m.work_minutes+=
      d.work_minutes;

    m.pause_minutes+=
      d.pause_minutes;

    m.days++;

    m.events+=
      d.events;

    m.automatic_exits+=
      d.automatic_exits;
  }


  const monthly=
    Object.values(monthlyMap);


  // Compatibilité avec votre ancien écran
  const employees=
    monthly.map(m=>({

      name:m.name,

      code:m.code,

      hours:
        Number(
          (
            m.work_minutes/60
          ).toFixed(2)
        ),

      events:m.events
    }));


  daily.sort(
    (a,b)=>
      a.date.localeCompare(b.date)
      ||
      a.name.localeCompare(b.name)
  );


  weekly.sort(
    (a,b)=>
      a.week_start.localeCompare(
        b.week_start
      )
      ||
      a.name.localeCompare(b.name)
  );


  monthly.sort(
    (a,b)=>
      a.name.localeCompare(b.name)
  );


  return {
    month,
    daily,
    weekly,
    monthly,
    employees
  };
}


// ===== RAPPORT SUPER ADMIN =====

app.get('/api/report',auth,async(req,res)=>{
  try{

    const month=String(
      req.query.month ||
      new Date().toISOString().slice(0,7)
    );

    res.json(
      await buildHoursReport(month)
    );

  }catch(e){

    console.error(e);

    res.status(400).json({
      error:'REPORT_ERROR'
    });
  }
});


// ===== RAPPORT RESPONSABLE =====

app.get('/api/manager/report',managerAuth,async(req,res)=>{
  try{

    const month=String(
      req.query.month ||
      new Date().toISOString().slice(0,7)
    );

    res.json(
      await buildHoursReport(
        month,
        req.manager.establishment_id
      )
    );

  }catch(e){

    console.error(e);

    res.status(400).json({
      error:'REPORT_ERROR'
    });
  }
});


app.get('/api/export.csv',auth,async(req,res)=>{let m=String(req.query.month||new Date().toISOString().slice(0,7)),st=m+'-01';let rows=(await pool.query("select s.name,s.code,p.type,p.time from punches p join staff s on s.id=p.staff_id where p.time >= $1::date and p.time < ($1::date + interval '1 month') order by s.name,p.time",[st])).rows,L={in:'Entrée',pause_start:'Début pause',pause_end:'Fin pause',out:'Sortie'},lines=['Employé;Code;Action;Date/heure'];for(let r of rows)lines.push([r.name,r.code,L[r.type],new Date(r.time).toLocaleString('fr-BE')].map(v=>`"${String(v).replaceAll('"','""')}"`).join(';'));res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition',`attachment; filename="pointage-${m}.csv"`);res.send('\ufeff'+lines.join('\n'))});


init()
  .then(() => app.listen(PORT, () => console.log('Pointage Pro v3 prêt')))

  .catch(e => {
    console.error(e);
    process.exit(1);
  });
