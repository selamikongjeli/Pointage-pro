
const express=require('express'),crypto=require('crypto'),path=require('path'),cors=require('cors');
const {Pool}=require('pg');
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const SECRET = process.env.POINTAGE_SECRET;

if (!SECRET) {
  console.error('POINTAGE_SECRET manquant');
  process.exit(1);
}
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:false});
app.use(cors({
  origin:[
    'http://localhost',
    'https://localhost',
    'capacitor://localhost',
    'https://pointage-pro-juk7.onrender.com'
  ],
  methods:['GET','POST','PATCH','DELETE','OPTIONS'],
  allowedHeaders:[
    'Content-Type',
    'Authorization',
    'x-admin-pin'
  ]
}));

app.use(express.json({limit:'8mb'}));
app.use(express.static(path.join(__dirname,'public')));const hp=(p,s)=>crypto.scryptSync(String(p),s,32).toString('hex');
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

    -- Informations légales et adresse complète des établissements existants.
    ALTER TABLE establishments
    ADD COLUMN IF NOT EXISTS vat_number text;

    ALTER TABLE establishments
    ADD COLUMN IF NOT EXISTS street_address text;

    ALTER TABLE establishments
    ADD COLUMN IF NOT EXISTS postal_code text;

    ALTER TABLE establishments
    ADD COLUMN IF NOT EXISTS city text;

    ALTER TABLE establishments
    ADD COLUMN IF NOT EXISTS country text;

    -- Paramètres déplacements / construction. Le tarif est défini par établissement.
    ALTER TABLE establishments
    ADD COLUMN IF NOT EXISTS mileage_rate numeric(10,3) NOT NULL DEFAULT 0;

    ALTER TABLE establishments
    ADD COLUMN IF NOT EXISTS travel_measurement text NOT NULL DEFAULT 'both';

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

    ALTER TABLE staff
    ADD COLUMN IF NOT EXISTS national_number text;

    -- onsite = QR + rayon GPS, mobile = pointage libre avec GPS,
    -- construction = heures chantier + trajets kilométriques séparés.
    ALTER TABLE staff
    ADD COLUMN IF NOT EXISTS punch_mode text NOT NULL DEFAULT 'onsite';

    CREATE TABLE IF NOT EXISTS punches(
      id uuid primary key,
      staff_id uuid not null references staff(id) on delete cascade,
      type text not null,
      time timestamptz not null default now()
    );

    CREATE TABLE IF NOT EXISTS staff_schedules(
      id uuid primary key,
      staff_id uuid not null references staff(id) on delete cascade,
      establishment_id uuid not null references establishments(id) on delete cascade,
      work_date date not null,
      planned_start time not null,
      planned_end time not null,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      UNIQUE(staff_id,work_date)
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

ALTER TABLE punches
ADD COLUMN IF NOT EXISTS latitude double precision;

ALTER TABLE punches
ADD COLUMN IF NOT EXISTS longitude double precision;

ALTER TABLE punches
ADD COLUMN IF NOT EXISTS accuracy double precision;

ALTER TABLE punches
ADD COLUMN IF NOT EXISTS work_site_name text;

    CREATE TABLE IF NOT EXISTS travel_sessions(
      id uuid primary key,
      staff_id uuid not null references staff(id) on delete cascade,
      establishment_id uuid references establishments(id) on delete set null,
      trip_type text not null,
      start_time timestamptz not null default now(),
      end_time timestamptz,
      start_latitude double precision,
      start_longitude double precision,
      start_accuracy double precision,
      end_latitude double precision,
      end_longitude double precision,
      end_accuracy double precision,
      start_odometer_km numeric(12,1),
      end_odometer_km numeric(12,1),
      odometer_km numeric(12,1),
      gps_km numeric(12,3),
      approved_km numeric(12,1),
      mileage_rate numeric(10,3) NOT NULL DEFAULT 0,
      status text NOT NULL DEFAULT 'open',
      start_photo bytea,
      start_photo_mime text,
      end_photo bytea,
      end_photo_mime text,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );

    CREATE TABLE IF NOT EXISTS travel_gps_points(
      id bigserial primary key,
      trip_id uuid not null references travel_sessions(id) on delete cascade,
      captured_at timestamptz not null,
      latitude double precision not null,
      longitude double precision not null,
      accuracy double precision
    );

    CREATE INDEX IF NOT EXISTS idx_travel_staff_time
    ON travel_sessions(staff_id,start_time);

    CREATE UNIQUE INDEX IF NOT EXISTS idx_travel_open_staff
    ON travel_sessions(staff_id)
    WHERE status='open';

    CREATE INDEX IF NOT EXISTS idx_travel_establishment_time
    ON travel_sessions(establishment_id,start_time);

    CREATE INDEX IF NOT EXISTS idx_travel_points_trip
    ON travel_gps_points(trip_id,captured_at);

    CREATE INDEX IF NOT EXISTS idx_punch
    ON punches(staff_id,time);

    CREATE INDEX IF NOT EXISTS idx_staff_establishment
    ON staff(establishment_id);

    CREATE UNIQUE INDEX IF NOT EXISTS idx_staff_national_number_unique
    ON staff(national_number)
    WHERE national_number IS NOT NULL;

    CREATE INDEX IF NOT EXISTS idx_punch_establishment
    ON punches(establishment_id,time);

    CREATE INDEX IF NOT EXISTS idx_staff_schedules_establishment_date
    ON staff_schedules(establishment_id,work_date);

    CREATE INDEX IF NOT EXISTS idx_staff_schedules_staff_date
    ON staff_schedules(staff_id,work_date);
  `);
}
async function settings(){return (await pool.query('select * from settings where id=1')).rows[0]}
async function auth(req,res,next){let r=await settings();if(!r.admin_pin_hash)return res.status(428).json({error:'ADMIN_NOT_SETUP'});if(!r.admin_pin_salt || hp(req.headers['x-admin-pin']||'',r.admin_pin_salt)!==r.admin_pin_hash)return res.status(401).json({error:'BAD_ADMIN_PIN'});next()}
async function staff(code){return (await pool.query('select * from staff where code=$1 and active=true',[code])).rows[0]}

function normalizePunchMode(value){
  const v=String(value||'onsite').trim().toLowerCase();
  return ['onsite','mobile','construction'].includes(v) ? v : '';
}

function punchModeLabel(value){
  return value==='mobile' ? 'Déplacement' : value==='construction' ? 'Construction' : 'Sur place';
}

function cleanPhotoBase64(value){
  if(!value) return null;
  const raw=String(value).replace(/^data:[^;]+;base64,/, '');
  if(!/^[A-Za-z0-9+/=\r\n]+$/.test(raw)) return null;
  const b=Buffer.from(raw,'base64');
  if(!b.length || b.length>2500000) return null;
  return b;
}


// ===== NUMERO NATIONAL / NISS-BIS =====

function normalizeNationalNumber(value){
  return String(value||'').replace(/\D/g,'');
}

function validNationalNumber(value){
  const digits=normalizeNationalNumber(value);
  if(digits.length!==11) return false;

  const base=digits.slice(0,9);
  const check=Number(digits.slice(9));
  const oldCheck=97-(Number(base)%97);
  const newCheck=97-(Number('2'+base)%97);

  return check===oldCheck || check===newCheck;
}

function formatNationalNumber(value){
  const digits=normalizeNationalNumber(value);
  if(digits.length!==11) return '';

  return digits.slice(0,2)+'.'+
    digits.slice(2,4)+'.'+
    digits.slice(4,6)+'-'+
    digits.slice(6,9)+'.'+
    digits.slice(9,11);
}

function uniqueStaffError(res,e){
  if(e.code!=='23505') return false;

  const constraint=String(e.constraint||'');
  if(constraint.includes('national_number')){
    res.status(409).json({error:'NISS_EXISTS'});
  }else{
    res.status(409).json({error:'CODE_EXISTS'});
  }
  return true;
}
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

// Format belge : le même numéro TVA peut être utilisé par plusieurs établissements.
function normalizeVatNumber(value){
  const compact=String(value||'').trim().toUpperCase().replace(/[\s.\-]/g,'');
  return /^\d{10}$/.test(compact) ? 'BE'+compact : compact;
}

function readEstablishmentDetails(body){
  const name=String(body.name||'').trim();
  const vatNumber=normalizeVatNumber(body.vat_number);
  const street=String(body.street_address||'').trim();
  const postalCode=String(body.postal_code||'').trim();
  const city=String(body.city||'').trim();
  const country=String(body.country||'').trim();
  const mileageRate=body.mileage_rate==='' || body.mileage_rate==null
    ? 0 : Number(body.mileage_rate);
  const travelMeasurement=['both','odometer','gps'].includes(String(body.travel_measurement||'both'))
    ? String(body.travel_measurement||'both') : 'both';
  // On conserve « address » pour les anciens écrans et anciens établissements.
  const fullAddress=[
    street,
    [postalCode,city].filter(Boolean).join(' '),
    country
  ].filter(Boolean).join(', ') || String(body.address||'').trim();
  return {name,vatNumber,street,postalCode,city,country,fullAddress,mileageRate,travelMeasurement};
}

app.post('/api/admin/establishments',auth,async(req,res)=>{
  const d=readEstablishmentDetails(req.body);

  if(!d.name) return res.status(400).json({error:'NAME_REQUIRED'});
  if(d.vatNumber && !/^BE\d{10}$/.test(d.vatNumber)){
    return res.status(400).json({error:'BAD_VAT'});
  }
  if(!Number.isFinite(d.mileageRate) || d.mileageRate<0 || d.mileageRate>10){
    return res.status(400).json({error:'BAD_MILEAGE_RATE'});
  }

  const latitude=req.body.latitude==='' || req.body.latitude==null
    ? null : Number(req.body.latitude);
  const longitude=req.body.longitude==='' || req.body.longitude==null
    ? null : Number(req.body.longitude);
  const radius=Number(req.body.radius_m||30);

  if(latitude!==null && (!Number.isFinite(latitude) || latitude < -90 || latitude > 90)){
    return res.status(400).json({error:'BAD_LATITUDE'});
  }
  if(longitude!==null && (!Number.isFinite(longitude) || longitude < -180 || longitude > 180)){
    return res.status(400).json({error:'BAD_LONGITUDE'});
  }
  if(!Number.isFinite(radius) || radius<20 || radius>2000){
    return res.status(400).json({error:'BAD_RADIUS'});
  }

  const q=await pool.query(`
    INSERT INTO establishments
      (id,name,address,vat_number,street_address,postal_code,city,country,
       mileage_rate,travel_measurement,latitude,longitude,radius_m)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    RETURNING *
  `,[
    crypto.randomUUID(),d.name,d.fullAddress,d.vatNumber||null,
    d.street||null,d.postalCode||null,d.city||null,d.country||null,
    d.mileageRate,d.travelMeasurement,latitude,longitude,radius
  ]);

  res.json(q.rows[0]);
});

// Le patron peut compléter les établissements créés avant ces nouveaux champs.
// Les coordonnées GPS et les horaires de pointage ne sont jamais modifiés ici.
app.patch('/api/admin/establishments/:id/details',auth,async(req,res)=>{
  const d=readEstablishmentDetails(req.body);

  if(!d.name) return res.status(400).json({error:'NAME_REQUIRED'});
  if(d.vatNumber && !/^BE\d{10}$/.test(d.vatNumber)){
    return res.status(400).json({error:'BAD_VAT'});
  }
  if(!Number.isFinite(d.mileageRate) || d.mileageRate<0 || d.mileageRate>10){
    return res.status(400).json({error:'BAD_MILEAGE_RATE'});
  }
  if(!d.street || !d.postalCode || !d.city || !d.country){
    return res.status(400).json({error:'ADDRESS_REQUIRED'});
  }

  const q=await pool.query(`
    UPDATE establishments
    SET name=$1,address=$2,vat_number=$3,
        street_address=$4,postal_code=$5,city=$6,country=$7,
        mileage_rate=$8,travel_measurement=$9
    WHERE id=$10
    RETURNING *
  `,[
    d.name,d.fullAddress,d.vatNumber||null,d.street,d.postalCode,
    d.city,d.country,d.mileageRate,d.travelMeasurement,req.params.id
  ]);

  if(!q.rows[0]){
    return res.status(404).json({error:'ESTABLISHMENT_NOT_FOUND'});
  }
  res.json({ok:true,establishment:q.rows[0]});
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
// ===== PROTECTION LOGIN RESPONSABLE =====
const managerLoginAttempts = new Map();

const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_BLOCK_TIME = 15 * 60 * 1000; // 15 minutes

function getManagerLoginKey(req, username) {
  return username;
}
app.post('/api/manager/login',async(req,res)=>{
  const username=String(req.body.username||'')
    .trim()
    .toLowerCase();

  const pin=String(req.body.pin||'');
const loginKey = getManagerLoginKey(req, username);
const loginAttempt = managerLoginAttempts.get(loginKey);

if (loginAttempt && loginAttempt.blockedUntil > Date.now()) {
  const remainingSeconds = Math.ceil(
    (loginAttempt.blockedUntil - Date.now()) / 1000
  );

  return res.status(429).json({
    error: 'TOO_MANY_LOGIN_ATTEMPTS',
    retry_after_seconds: remainingSeconds
  });
}

if (loginAttempt && loginAttempt.blockedUntil <= Date.now()) {
  managerLoginAttempts.delete(loginKey);
}
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

if (!m || !ok(pin,m)) {
  const current = managerLoginAttempts.get(loginKey) || {
    count: 0,
    blockedUntil: 0
  };

  current.count += 1;

  if (current.count >= MAX_LOGIN_ATTEMPTS) {
    current.blockedUntil = Date.now() + LOGIN_BLOCK_TIME;
    current.count = 0;

    managerLoginAttempts.set(loginKey, current);

    return res.status(429).json({
      error: 'TOO_MANY_LOGIN_ATTEMPTS',
      retry_after_seconds: Math.ceil(LOGIN_BLOCK_TIME / 1000)
    });
  }

  managerLoginAttempts.set(loginKey, current);

  return res.status(401).json({
    error: 'BAD_MANAGER_LOGIN',
    attempts_remaining: MAX_LOGIN_ATTEMPTS - current.count
  });
}
managerLoginAttempts.delete(loginKey);
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


// ===== EMPLOYES DESACTIVES RESPONSABLE =====

app.get('/api/manager/staff/inactive',managerAuth,async(req,res)=>{

  const q=await pool.query(`
    SELECT id,name,code,role,active,national_number,punch_mode
    FROM staff
    WHERE establishment_id=$1
      AND active=false
    ORDER BY name
  `,[req.manager.establishment_id]);

  res.json(q.rows);
});


app.patch('/api/manager/staff/:id/reactivate',managerAuth,async(req,res)=>{

  const q=await pool.query(`
    UPDATE staff
    SET active=true
    WHERE id=$1
      AND establishment_id=$2
      AND active=false
    RETURNING id,name,code,role,active,national_number,punch_mode
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
    SELECT id,name,code,role,active,national_number,punch_mode
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
  const nationalNumber=normalizeNationalNumber(req.body.national_number);
  const punchMode=normalizePunchMode(req.body.punch_mode);

  if(!name || !code || pin.length<4 || !punchMode){
    return res.status(400).json({error:'INVALID'});
  }

  if(nationalNumber && !validNationalNumber(nationalNumber)){
    return res.status(400).json({error:'BAD_NISS'});
  }

  const p=mk(pin);

  try{
    await pool.query(`
      INSERT INTO staff
        (id,name,code,role,pin_salt,pin_hash,establishment_id,national_number,punch_mode)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
    `,[
      crypto.randomUUID(),
      name,
      code,
      role,
      p.salt,
      p.hash,
      req.manager.establishment_id,
      nationalNumber || null,
      punchMode
    ]);

    res.json({ok:true});

  }catch(e){
    if(uniqueStaffError(res,e)){
      return;
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

  const currentQ=await pool.query(`
    SELECT national_number,punch_mode
    FROM staff
    WHERE id=$1 AND establishment_id=$2
    LIMIT 1
  `,[id,req.manager.establishment_id]);

  if(!currentQ.rows[0]){
    return res.status(404).json({error:'NOT_FOUND'});
  }

  const hasNationalNumber=Object.prototype.hasOwnProperty.call(req.body,'national_number');
  const nationalNumber=hasNationalNumber
    ? normalizeNationalNumber(req.body.national_number)
    : String(currentQ.rows[0].national_number||'');
  const punchMode=normalizePunchMode(
    req.body.punch_mode || currentQ.rows[0].punch_mode || 'onsite'
  );

  if(!name || !code || !punchMode){
    return res.status(400).json({error:'INVALID'});
  }

  if(nationalNumber && !validNationalNumber(nationalNumber)){
    return res.status(400).json({error:'BAD_NISS'});
  }

  try{
    if(pin){
      if(pin.length<4){
        return res.status(400).json({error:'PIN'});
      }

      const p=mk(pin);

      const q=await pool.query(`
        UPDATE staff
        SET name=$1,code=$2,role=$3,pin_salt=$4,pin_hash=$5,national_number=$6,punch_mode=$7
        WHERE id=$8 AND establishment_id=$9
        RETURNING id
      `,[
        name,code,role,p.salt,p.hash,nationalNumber || null,punchMode,
        id,req.manager.establishment_id
      ]);

      if(!q.rows[0]){
        return res.status(404).json({error:'NOT_FOUND'});
      }

    }else{

      const q=await pool.query(`
        UPDATE staff
        SET name=$1,code=$2,role=$3,national_number=$4,punch_mode=$5
        WHERE id=$6 AND establishment_id=$7
        RETURNING id
      `,[
        name,code,role,nationalNumber || null,punchMode,
        id,req.manager.establishment_id
      ]);

      if(!q.rows[0]){
        return res.status(404).json({error:'NOT_FOUND'});
      }
    }

    res.json({ok:true});

  }catch(e){
    if(uniqueStaffError(res,e)){
      return;
    }

    console.error(e);
    res.status(500).json({error:'SERVER_ERROR'});
  }
});

app.delete('/api/manager/staff/:id',managerAuth,async(req,res)=>{

  const staffId=req.params.id;

  const employee=await pool.query(`
    SELECT id,name,code
    FROM staff
    WHERE id=$1
      AND establishment_id=$2
      AND active=true
    LIMIT 1
  `,[
    staffId,
    req.manager.establishment_id
  ]);

  if(!employee.rows[0]){
    return res.status(404).json({
      error:'NOT_FOUND'
    });
  }

  const last=await pool.query(`
    SELECT type,time
    FROM punches
    WHERE staff_id=$1
    ORDER BY time DESC
    LIMIT 1
  `,[staffId]);

  if(
    last.rows[0] &&
    last.rows[0].type!=='out'
  ){
    return res.status(409).json({
      error:'STAFF_CLOCKED_IN'
    });
  }

  const q=await pool.query(`
    UPDATE staff
    SET active=false
    WHERE id=$1
      AND establishment_id=$2
      AND active=true
    RETURNING id,name,code
  `,[
    staffId,
    req.manager.establishment_id
  ]);

  res.json({
    ok:true,
    staff:q.rows[0]
  });
});

// ===== HORAIRES PREVUS RESPONSABLE =====

function validWorkDate(value){
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value||''));
}

function validClock(value){
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(String(value||''));
}

app.get('/api/manager/schedules',managerAuth,async(req,res)=>{
  const month=String(req.query.month||new Date().toISOString().slice(0,7));

  if(!/^\d{4}-\d{2}$/.test(month)){
    return res.status(400).json({error:'BAD_MONTH'});
  }

  const q=await pool.query(`
    SELECT
      ss.id,
      ss.staff_id,
      s.name,
      s.code,
      s.national_number,
      ss.work_date::text AS date,
      to_char(ss.planned_start,'HH24:MI') AS planned_start,
      to_char(ss.planned_end,'HH24:MI') AS planned_end
    FROM staff_schedules ss
    JOIN staff s ON s.id=ss.staff_id
    WHERE ss.establishment_id=$1
      AND s.establishment_id=$1
      AND ss.work_date >= ($2 || '-01')::date
      AND ss.work_date < (($2 || '-01')::date + interval '1 month')
    ORDER BY ss.work_date,s.name
  `,[req.manager.establishment_id,month]);

  res.json(q.rows);
});

app.post('/api/manager/schedules',managerAuth,async(req,res)=>{
  const staffId=String(req.body.staff_id||'').trim();
  const date=String(req.body.date||'').trim();
  const plannedStart=String(req.body.planned_start||'').trim();
  const plannedEnd=String(req.body.planned_end||'').trim();

  if(!staffId || !validWorkDate(date) || !validClock(plannedStart) || !validClock(plannedEnd)){
    return res.status(400).json({error:'INVALID_SCHEDULE'});
  }

  if(plannedEnd<=plannedStart){
    return res.status(400).json({error:'BAD_SCHEDULE_RANGE'});
  }

  const employee=await pool.query(`
    SELECT id
    FROM staff
    WHERE id=$1
      AND establishment_id=$2
      AND active=true
    LIMIT 1
  `,[staffId,req.manager.establishment_id]);

  if(!employee.rows[0]){
    return res.status(404).json({error:'STAFF_NOT_FOUND'});
  }

  const q=await pool.query(`
    INSERT INTO staff_schedules(
      id,staff_id,establishment_id,work_date,planned_start,planned_end
    )
    VALUES($1,$2,$3,$4,$5,$6)
    ON CONFLICT(staff_id,work_date)
    DO UPDATE SET
      establishment_id=EXCLUDED.establishment_id,
      planned_start=EXCLUDED.planned_start,
      planned_end=EXCLUDED.planned_end,
      updated_at=now()
    RETURNING
      id,
      staff_id,
      work_date::text AS date,
      to_char(planned_start,'HH24:MI') AS planned_start,
      to_char(planned_end,'HH24:MI') AS planned_end
  `,[
    crypto.randomUUID(),
    staffId,
    req.manager.establishment_id,
    date,
    plannedStart,
    plannedEnd
  ]);

  res.json({ok:true,schedule:q.rows[0]});
});

app.delete('/api/manager/schedules/:staffId/:date',managerAuth,async(req,res)=>{
  const staffId=String(req.params.staffId||'').trim();
  const date=String(req.params.date||'').trim();

  if(!staffId || !validWorkDate(date)){
    return res.status(400).json({error:'INVALID_SCHEDULE'});
  }

  const q=await pool.query(`
    DELETE FROM staff_schedules
    WHERE staff_id=$1
      AND work_date=$2::date
      AND establishment_id=$3
    RETURNING id
  `,[staffId,date,req.manager.establishment_id]);

  if(!q.rows[0]){
    return res.status(404).json({error:'SCHEDULE_NOT_FOUND'});
  }

  res.json({ok:true});
});

app.get('/api/status',async(req,res)=>{let r=await settings();res.json({adminSetup:!!r.admin_pin_hash,company:r.company})});
app.post('/api/setup',async(req,res)=>{let r=await settings();if(r.admin_pin_hash)return res.status(409).json({error:'ALREADY'});let pin=String(req.body.pin||'');if(pin.length<4)return res.status(400).json({error:'PIN'});let p=mk(pin);await pool.query('update settings set company=$1,admin_pin_salt=$2,admin_pin_hash=$3 where id=1',[req.body.company||'Mon entreprise',p.salt,p.hash]);res.json({ok:true})});
app.get('/api/qr',auth,(req,res)=>res.json({token:token(),expiresIn:60-(Math.floor(Date.now()/1000)%60)}));
app.get('/api/staff/inactive',auth,async(req,res)=>{

  const q=await pool.query(`
    SELECT id,name,code,role,active,national_number,punch_mode
    FROM staff
    WHERE active=false
    ORDER BY name
  `);

  res.json(q.rows);
});


app.patch('/api/staff/:id/reactivate',auth,async(req,res)=>{

  const q=await pool.query(`
    UPDATE staff
    SET active=true
    WHERE id=$1
      AND active=false
    RETURNING id,name,code,role,active,national_number,punch_mode
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
 app.get('/api/staff',auth,async(req,res)=>
  res.json(
    (
      await pool.query(`
        SELECT id,name,code,role,active,national_number,punch_mode
        FROM staff
        WHERE active=true
        ORDER BY name
      `)
    ).rows
  )
);
app.post('/api/staff',auth,async(req,res)=>{

  const name=String(req.body.name||'').trim();
  const code=String(req.body.code||'').trim();
  const role=String(req.body.role||'Employé').trim();
  const pin=String(req.body.pin||'');
  const nationalNumber=normalizeNationalNumber(req.body.national_number);
  const punchMode=normalizePunchMode(req.body.punch_mode);
  const establishmentId=
    String(req.body.establishment_id||'').trim();

  if(!name || !code || pin.length<4 || !punchMode){
    return res.status(400).json({
      error:'INVALID'
    });
  }

  if(nationalNumber && !validNationalNumber(nationalNumber)){
    return res.status(400).json({error:'BAD_NISS'});
  }

  if(!establishmentId){
    return res.status(400).json({
      error:'ESTABLISHMENT_REQUIRED'
    });
  }

  const est=await pool.query(`
    SELECT id
    FROM establishments
    WHERE id=$1
      AND active=true
    LIMIT 1
  `,[establishmentId]);

  if(!est.rows[0]){
    return res.status(404).json({
      error:'ESTABLISHMENT_NOT_FOUND'
    });
  }

  const p=mk(pin);

  try{

    const q=await pool.query(`
      INSERT INTO staff(
        id,
        name,
        code,
        role,
        pin_salt,
        pin_hash,
        establishment_id,
        national_number,
        punch_mode
      )
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING
        id,
        name,
        code,
        role,
        establishment_id,
        national_number,
        punch_mode,
        active
    `,[
      crypto.randomUUID(),
      name,
      code,
      role,
      p.salt,
      p.hash,
      establishmentId,
      nationalNumber || null,
      punchMode
    ]);

    res.json({
      ok:true,
      staff:q.rows[0]
    });

  }catch(e){

    if(uniqueStaffError(res,e)){
      return;
    }

    console.error(e);

    res.status(500).json({
      error:'SERVER_ERROR'
    });
  }
});
app.patch('/api/staff/:id',auth,async(req,res)=>{
  let id=req.params.id;
  let name=String(req.body.name||'').trim();
  let code=String(req.body.code||'').trim();
  let role=String(req.body.role||'Employé').trim();
  let pin=String(req.body.pin||'');

  const currentQ=await pool.query('SELECT national_number,punch_mode FROM staff WHERE id=$1 LIMIT 1',[id]);
  if(!currentQ.rows[0]) return res.status(404).json({error:'NOT_FOUND'});

  const hasNationalNumber=Object.prototype.hasOwnProperty.call(req.body,'national_number');
  let nationalNumber=hasNationalNumber
    ? normalizeNationalNumber(req.body.national_number)
    : String(currentQ.rows[0].national_number||'');
  let punchMode=normalizePunchMode(req.body.punch_mode || currentQ.rows[0].punch_mode || 'onsite');

  if(!name||!code||!punchMode) return res.status(400).json({error:'INVALID'});

  if(nationalNumber && !validNationalNumber(nationalNumber)){
    return res.status(400).json({error:'BAD_NISS'});
  }

  try{
    if(pin){
      if(pin.length<4) return res.status(400).json({error:'PIN'});
      let p=mk(pin);
      await pool.query(
        'update staff set name=$1,code=$2,role=$3,pin_salt=$4,pin_hash=$5,national_number=$6,punch_mode=$7 where id=$8',
        [name,code,role,p.salt,p.hash,nationalNumber || null,punchMode,id]
      );
    }else{
      await pool.query(
        'update staff set name=$1,code=$2,role=$3,national_number=$4,punch_mode=$5 where id=$6',
        [name,code,role,nationalNumber || null,punchMode,id]
      );
    }
    res.json({ok:true});
  }catch(e){
    if(uniqueStaffError(res,e)){
      return;
    }
    res.status(500).json({error:'SERVER_ERROR'});
  }
});

app.delete('/api/staff/:id',auth,async(req,res)=>{

  const staffId=req.params.id;

  const employee=await pool.query(`
    SELECT id,name,code
    FROM staff
    WHERE id=$1
      AND active=true
    LIMIT 1
  `,[staffId]);

  if(!employee.rows[0]){
    return res.status(404).json({
      error:'NOT_FOUND'
    });
  }

  const last=await pool.query(`
    SELECT type,time
    FROM punches
    WHERE staff_id=$1
    ORDER BY time DESC
    LIMIT 1
  `,[staffId]);

  if(
    last.rows[0] &&
    last.rows[0].type!=='out'
  ){
    return res.status(409).json({
      error:'STAFF_CLOCKED_IN'
    });
  }

  const q=await pool.query(`
    UPDATE staff
    SET active=false
    WHERE id=$1
      AND active=true
    RETURNING id,name,code
  `,[staffId]);

  res.json({
    ok:true,
    staff:q.rows[0]
  });
});
app.post('/api/login',async(req,res)=>{
  let s=await staff(String(req.body.code||''));

  if(!s || !ok(req.body.pin||'',s)){
    return res.status(401).json({
      error:'BAD_LOGIN'
    });
  }

  const est=s.establishment_id
    ? (await pool.query(`
        SELECT id,name,mileage_rate,travel_measurement
        FROM establishments
        WHERE id=$1
        LIMIT 1
      `,[s.establishment_id])).rows[0]
    : null;

  const openTrip=s.punch_mode==='construction'
    ? (await pool.query(`
        SELECT id,trip_type,start_time,start_odometer_km
        FROM travel_sessions
        WHERE staff_id=$1 AND status='open'
        ORDER BY start_time DESC
        LIMIT 1
      `,[s.id])).rows[0] || null
    : null;

  res.json({
    ok:true,
    staff:{
      name:s.name,
      role:s.role,
      punch_mode:s.punch_mode || 'onsite',
      punch_mode_label:punchModeLabel(s.punch_mode || 'onsite'),
      establishment_id:s.establishment_id || null,
      establishment_name:est ? est.name : '',
      mileage_rate:est ? Number(est.mileage_rate||0) : 0,
      travel_measurement:est ? est.travel_measurement : 'both',
      open_trip:openTrip
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


  // Première entrée de la journée.
  // Sécurité pour les anciennes données : si elle est introuvable,
  // on utilise le début du service actuel au lieu de laisser le service ouvert.
  const firstInFound=
    await firstInOfDay(
      s.id,
      shiftStart
    );

  const firstIn=
    firstInFound || shiftStart;


  const rawDayLimit=
    new Date(
      firstIn.getTime()+
      Number(rules.max_day_span_minutes)*60000
    );

  const dayLimit=
    new Date(
      Math.max(
        rawDayLimit.getTime(),
        shiftStart.getTime()
      )
    );


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
  const candidates=[];


  // Ces deux limites suffisent déjà à fermer un ancien service oublié.
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


  // La limite hebdomadaire reste prise en compte, mais une erreur de calcul
  // ne doit jamais empêcher la fermeture d'un ancien service déjà dépassé.
  try{

    const hardUntil=new Date(
      Math.min(
        now.getTime(),
        dayLimit.getTime(),
        closingLimit.getTime()
      )
    );

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

    if(
      weeklyLimitTime &&
      weeklyLimitTime<=now
    ){
      candidates.push({
        time:weeklyLimitTime,
        reason:'MAX_SEMAINE'
      });
    }

  }catch(e){
    console.error(
      'WEEK LIMIT AUTO EXIT',
      s.id,
      e
    );
  }


  if(!candidates.length){
    return null;
  }


  candidates.sort(
    (a,b)=>a.time-b.time
  );

  const exit=candidates[0];


  // Vérification supplémentaire pour éviter une double sortie automatique.
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

  const s=await staff(String(req.body.code||''));

  if(!s || !ok(req.body.pin||'',s)){
    return res.status(401).json({error:'BAD_LOGIN'});
  }

  const action=String(req.body.action||'');

  if(!['in','pause_start','pause_end','out'].includes(action)){
    return res.status(400).json({error:'BAD_ACTION'});
  }

  const punchMode=normalizePunchMode(s.punch_mode) || 'onsite';

  // La position est conservée pour tous les modes. En mode sur place elle sert
  // aussi à contrôler le rayon de l'établissement.
  const latitude=Number(req.body.latitude);
  const longitude=Number(req.body.longitude);
  const accuracy=Number(req.body.accuracy);

  if(!Number.isFinite(latitude) || !Number.isFinite(longitude)){
    return res.status(400).json({error:'GPS_REQUIRED'});
  }

  if(Number.isFinite(accuracy) && accuracy>100){
    return res.status(400).json({error:'GPS_INACCURATE',accuracy});
  }

  let establishmentId=s.establishment_id || null;
  let distance=null;
  let radius=null;

  if(punchMode==='onsite'){
    const qrEstablishmentId=readPermanentQR(req.body.token);

    if(!qrEstablishmentId){
      return res.status(400).json({error:'BAD_QR'});
    }

    if(!s.establishment_id || String(s.establishment_id)!==String(qrEstablishmentId)){
      return res.status(403).json({error:'WRONG_ESTABLISHMENT'});
    }

    establishmentId=qrEstablishmentId;

    const estQ=await pool.query(`
      SELECT id,latitude,longitude,radius_m
      FROM establishments
      WHERE id=$1 AND active=true
      LIMIT 1
    `,[qrEstablishmentId]);

    const establishment=estQ.rows[0];

    if(!establishment){
      return res.status(404).json({error:'ESTABLISHMENT_NOT_FOUND'});
    }

    if(establishment.latitude==null || establishment.longitude==null){
      return res.status(409).json({error:'GPS_NOT_CONFIGURED'});
    }

    distance=distanceMeters(
      latitude,
      longitude,
      Number(establishment.latitude),
      Number(establishment.longitude)
    );

    radius=Number(establishment.radius_m || 30);

    if(distance>radius){
      return res.status(403).json({
        error:'TOO_FAR',
        distance:Math.round(distance),
        radius
      });
    }
  }

  // Vérifie les sorties automatiques avant chaque nouveau pointage.
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
    if(last && last.type==='out' && last.automatic){
      return res.status(409).json({
        error:'AUTO_CLOSED',
        reason:last.auto_reason,
        time:last.time
      });
    }
    return res.status(409).json({error:'INVALID_SEQUENCE'});
  }

  const rules=await establishmentRules(s);

  if(action==='in' && rules){
    const now=new Date();

    // L'heure de fermeture concerne le personnel qui pointe physiquement
    // dans l'établissement. Les commerciaux et chantiers peuvent travailler
    // hors des heures d'ouverture.
    if(punchMode==='onsite'){
      const localTime=await pool.query(`
        SELECT (
          $1::timestamptz AT TIME ZONE 'Europe/Brussels'
        )::time >= $2::time AS closed
      `,[now,rules.closing_time]);

      if(localTime.rows[0].closed){
        return res.status(409).json({error:'ESTABLISHMENT_CLOSED'});
      }
    }

    const firstIn=await firstInOfDay(s.id,now);

    if(firstIn){
      const dayDeadline=new Date(
        firstIn.getTime()+Number(rules.max_day_span_minutes)*60000
      );
      if(now>=dayDeadline){
        return res.status(409).json({error:'DAY_LIMIT'});
      }
    }

    const weekMs=await weeklyWorkedMs(s.id,now,now);
    const weekLimitMs=Number(rules.weekly_max_minutes)*60000;

    if(weekMs>=weekLimitMs){
      return res.status(409).json({error:'WEEK_LIMIT'});
    }
  }

  const workSiteName=punchMode==='construction'
    ? String(req.body.work_site_name||'').trim().slice(0,160)
    : null;

  const q=await pool.query(`
    INSERT INTO punches(
      id,staff_id,establishment_id,type,
      latitude,longitude,accuracy,work_site_name
    )
    VALUES($1,$2,$3,$4,$5,$6,$7,$8)
    RETURNING time
  `,[
    crypto.randomUUID(),
    s.id,
    establishmentId,
    action,
    latitude,
    longitude,
    Number.isFinite(accuracy) ? accuracy : null,
    workSiteName || null
  ]);

  res.json({
    ok:true,
    type:action,
    time:q.rows[0].time,
    name:s.name,
    punch_mode:punchMode,
    work_site_name:workSiteName || '',
    distance:distance==null ? null : Math.round(distance),
    radius
  });
});


// ===== TRAJETS / KILOMETRES (MODE CONSTRUCTION) =====

function validTripType(value){
  return ['depot_to_site','site_to_site','site_to_depot'].includes(String(value||''));
}

function validCoordinate(lat,lon){
  return Number.isFinite(lat) && Number.isFinite(lon) &&
    lat>=-90 && lat<=90 && lon>=-180 && lon<=180;
}

async function establishmentTravelSettings(establishmentId){
  if(!establishmentId) return null;
  const q=await pool.query(`
    SELECT id,name,latitude,longitude,radius_m,mileage_rate,travel_measurement
    FROM establishments
    WHERE id=$1 AND active=true
    LIMIT 1
  `,[establishmentId]);
  return q.rows[0] || null;
}

app.post('/api/travel/status',async(req,res)=>{
  const s=await staff(String(req.body.code||''));
  if(!s || !ok(req.body.pin||'',s)){
    return res.status(401).json({error:'BAD_LOGIN'});
  }
  if((s.punch_mode||'onsite')!=='construction'){
    return res.status(403).json({error:'NOT_CONSTRUCTION_MODE'});
  }

  const q=await pool.query(`
    SELECT id,trip_type,start_time,start_odometer_km,status
    FROM travel_sessions
    WHERE staff_id=$1 AND status='open'
    ORDER BY start_time DESC
    LIMIT 1
  `,[s.id]);

  res.json({ok:true,open_trip:q.rows[0]||null});
});

app.post('/api/travel/start',async(req,res)=>{
  const s=await staff(String(req.body.code||''));
  if(!s || !ok(req.body.pin||'',s)){
    return res.status(401).json({error:'BAD_LOGIN'});
  }
  if((s.punch_mode||'onsite')!=='construction'){
    return res.status(403).json({error:'NOT_CONSTRUCTION_MODE'});
  }

  const tripType=String(req.body.trip_type||'');
  if(!validTripType(tripType)){
    return res.status(400).json({error:'BAD_TRIP_TYPE'});
  }

  const startOdo=Number(req.body.start_odometer_km);
  if(!Number.isFinite(startOdo) || startOdo<0 || startOdo>5000000){
    return res.status(400).json({error:'BAD_ODOMETER'});
  }

  const photo=cleanPhotoBase64(req.body.start_photo_base64);
  if(!photo){
    return res.status(400).json({error:'START_PHOTO_REQUIRED'});
  }

  const latitude=Number(req.body.latitude);
  const longitude=Number(req.body.longitude);
  const accuracy=Number(req.body.accuracy);

  if(!validCoordinate(latitude,longitude)){
    return res.status(400).json({error:'GPS_REQUIRED'});
  }
  if(Number.isFinite(accuracy) && accuracy>100){
    return res.status(400).json({error:'GPS_INACCURATE',accuracy});
  }

  const settings=await establishmentTravelSettings(s.establishment_id);
  if(!settings){
    return res.status(404).json({error:'ESTABLISHMENT_NOT_FOUND'});
  }

  if(tripType==='depot_to_site'){
    if(settings.latitude==null || settings.longitude==null){
      return res.status(409).json({error:'DEPOT_GPS_NOT_CONFIGURED'});
    }
    const distance=distanceMeters(
      latitude,longitude,
      Number(settings.latitude),Number(settings.longitude)
    );
    if(distance>Number(settings.radius_m||30)){
      return res.status(403).json({
        error:'NOT_AT_DEPOT',
        distance:Math.round(distance),
        radius:Number(settings.radius_m||30)
      });
    }
  }

  const open=await pool.query(`
    SELECT id FROM travel_sessions
    WHERE staff_id=$1 AND status='open'
    LIMIT 1
  `,[s.id]);
  if(open.rows[0]){
    return res.status(409).json({error:'TRIP_ALREADY_OPEN',trip_id:open.rows[0].id});
  }

  const id=crypto.randomUUID();
  const q=await pool.query(`
    INSERT INTO travel_sessions(
      id,staff_id,establishment_id,trip_type,
      start_latitude,start_longitude,start_accuracy,
      start_odometer_km,mileage_rate,start_photo,start_photo_mime
    )
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    RETURNING id,trip_type,start_time,start_odometer_km,mileage_rate,status
  `,[
    id,s.id,s.establishment_id,tripType,
    latitude,longitude,Number.isFinite(accuracy)?accuracy:null,
    startOdo,Number(settings.mileage_rate||0),photo,
    String(req.body.start_photo_mime||'image/jpeg').slice(0,80)
  ]);

  res.json({ok:true,trip:q.rows[0]});
});

app.post('/api/travel/end',async(req,res)=>{
  const s=await staff(String(req.body.code||''));
  if(!s || !ok(req.body.pin||'',s)){
    return res.status(401).json({error:'BAD_LOGIN'});
  }
  if((s.punch_mode||'onsite')!=='construction'){
    return res.status(403).json({error:'NOT_CONSTRUCTION_MODE'});
  }

  const tripId=String(req.body.trip_id||'').trim();
  const tripQ=await pool.query(`
    SELECT * FROM travel_sessions
    WHERE id=$1 AND staff_id=$2 AND status='open'
    LIMIT 1
  `,[tripId,s.id]);
  const trip=tripQ.rows[0];
  if(!trip){
    return res.status(404).json({error:'OPEN_TRIP_NOT_FOUND'});
  }

  const endOdo=Number(req.body.end_odometer_km);
  const startOdo=Number(trip.start_odometer_km);
  if(!Number.isFinite(endOdo) || endOdo<startOdo || endOdo>5000000){
    return res.status(400).json({error:'BAD_ODOMETER'});
  }

  const photo=cleanPhotoBase64(req.body.end_photo_base64);
  if(!photo){
    return res.status(400).json({error:'END_PHOTO_REQUIRED'});
  }

  const latitude=Number(req.body.latitude);
  const longitude=Number(req.body.longitude);
  const accuracy=Number(req.body.accuracy);
  if(!validCoordinate(latitude,longitude)){
    return res.status(400).json({error:'GPS_REQUIRED'});
  }
  if(Number.isFinite(accuracy) && accuracy>100){
    return res.status(400).json({error:'GPS_INACCURATE',accuracy});
  }

  const settings=await establishmentTravelSettings(s.establishment_id);
  if(!settings){
    return res.status(404).json({error:'ESTABLISHMENT_NOT_FOUND'});
  }

  if(trip.trip_type==='site_to_depot'){
    if(settings.latitude==null || settings.longitude==null){
      return res.status(409).json({error:'DEPOT_GPS_NOT_CONFIGURED'});
    }
    const distance=distanceMeters(
      latitude,longitude,
      Number(settings.latitude),Number(settings.longitude)
    );
    if(distance>Number(settings.radius_m||30)){
      return res.status(403).json({
        error:'NOT_AT_DEPOT',
        distance:Math.round(distance),
        radius:Number(settings.radius_m||30)
      });
    }
  }

  const gpsKm=Number(req.body.gps_km||0);
  if(!Number.isFinite(gpsKm) || gpsKm<0 || gpsKm>5000){
    return res.status(400).json({error:'BAD_GPS_DISTANCE'});
  }

  const points=Array.isArray(req.body.gps_points) ? req.body.gps_points : [];
  if(points.length>5000){
    return res.status(400).json({error:'TOO_MANY_GPS_POINTS'});
  }

  const odometerKm=Number((endOdo-startOdo).toFixed(1));
  const client=await pool.connect();

  try{
    await client.query('BEGIN');

    const updated=await client.query(`
      UPDATE travel_sessions
      SET end_time=now(),
          end_latitude=$1,end_longitude=$2,end_accuracy=$3,
          end_odometer_km=$4,odometer_km=$5,gps_km=$6,
          end_photo=$7,end_photo_mime=$8,status='pending',updated_at=now()
      WHERE id=$9 AND staff_id=$10 AND status='open'
      RETURNING id,trip_type,start_time,end_time,start_odometer_km,end_odometer_km,
                odometer_km,gps_km,mileage_rate,status
    `,[
      latitude,longitude,Number.isFinite(accuracy)?accuracy:null,
      endOdo,odometerKm,gpsKm,photo,
      String(req.body.end_photo_mime||'image/jpeg').slice(0,80),
      tripId,s.id
    ]);

    for(const point of points){
      const lat=Number(point.latitude);
      const lon=Number(point.longitude);
      const acc=Number(point.accuracy);
      const t=new Date(point.time || point.captured_at || Date.now());
      if(!validCoordinate(lat,lon) || Number.isNaN(t.getTime())) continue;
      await client.query(`
        INSERT INTO travel_gps_points(trip_id,captured_at,latitude,longitude,accuracy)
        VALUES($1,$2,$3,$4,$5)
      `,[tripId,t,lat,lon,Number.isFinite(acc)?acc:null]);
    }

    await client.query('COMMIT');
    res.json({ok:true,trip:updated.rows[0]});
  }catch(e){
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({error:'SERVER_ERROR'});
  }finally{
    client.release();
  }
});

app.get('/api/manager/travel',managerAuth,async(req,res)=>{
  const month=String(req.query.month||new Date().toISOString().slice(0,7));
  if(!/^\d{4}-\d{2}$/.test(month)){
    return res.status(400).json({error:'BAD_MONTH'});
  }

  const q=await pool.query(`
    SELECT
      t.id,t.trip_type,t.start_time,t.end_time,
      t.start_odometer_km,t.end_odometer_km,t.odometer_km,t.gps_km,
      t.approved_km,t.mileage_rate,t.status,
      s.id AS staff_id,s.name,s.code
    FROM travel_sessions t
    JOIN staff s ON s.id=t.staff_id
    WHERE t.establishment_id=$1
      AND (t.start_time AT TIME ZONE 'Europe/Brussels')::date >= ($2||'-01')::date
      AND (t.start_time AT TIME ZONE 'Europe/Brussels')::date < (($2||'-01')::date + interval '1 month')
    ORDER BY t.start_time DESC
  `,[req.manager.establishment_id,month]);

  res.json(q.rows.map(row=>({
    ...row,
    odometer_km:row.odometer_km==null?null:Number(row.odometer_km),
    gps_km:row.gps_km==null?null:Number(row.gps_km),
    approved_km:row.approved_km==null?null:Number(row.approved_km),
    mileage_rate:Number(row.mileage_rate||0),
    amount_eur:Number(((row.approved_km==null?row.odometer_km:row.approved_km)||0)*Number(row.mileage_rate||0)).toFixed(2)
  })));
});

app.patch('/api/manager/travel/:id/approve',managerAuth,async(req,res)=>{
  const approvedKm=Number(req.body.approved_km);
  if(!Number.isFinite(approvedKm) || approvedKm<0 || approvedKm>5000){
    return res.status(400).json({error:'BAD_KM'});
  }

  const q=await pool.query(`
    UPDATE travel_sessions
    SET approved_km=$1,status='approved',updated_at=now()
    WHERE id=$2 AND establishment_id=$3 AND status IN ('pending','approved')
    RETURNING id,approved_km,mileage_rate,status
  `,[approvedKm,req.params.id,req.manager.establishment_id]);

  if(!q.rows[0]) return res.status(404).json({error:'TRIP_NOT_FOUND'});
  res.json({ok:true,trip:q.rows[0]});
});

app.patch('/api/manager/travel/:id/reject',managerAuth,async(req,res)=>{
  const q=await pool.query(`
    UPDATE travel_sessions
    SET status='rejected',updated_at=now()
    WHERE id=$1 AND establishment_id=$2 AND status IN ('pending','approved')
    RETURNING id,status
  `,[req.params.id,req.manager.establishment_id]);
  if(!q.rows[0]) return res.status(404).json({error:'TRIP_NOT_FOUND'});
  res.json({ok:true,trip:q.rows[0]});
});

app.get('/api/manager/travel/:id/photo/:which',managerAuth,async(req,res)=>{
  const which=req.params.which==='start' ? 'start' : req.params.which==='end' ? 'end' : '';
  if(!which) return res.status(400).end();

  const q=await pool.query(`
    SELECT start_photo,start_photo_mime,end_photo,end_photo_mime
    FROM travel_sessions
    WHERE id=$1 AND establishment_id=$2
    LIMIT 1
  `,[req.params.id,req.manager.establishment_id]);
  if(!q.rows[0]) return res.status(404).end();

  const data=which==='start' ? q.rows[0].start_photo : q.rows[0].end_photo;
  const mime=which==='start' ? q.rows[0].start_photo_mime : q.rows[0].end_photo_mime;
  if(!data) return res.status(404).end();
  res.type(mime||'image/jpeg').send(data);
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
    s.id,
    s.name,
    s.code,
    s.national_number,
    s.establishment_id,
    s.active,
    e.name AS establishment_name

  FROM staff s

  LEFT JOIN establishments e
    ON e.id=s.establishment_id

  WHERE 1=1
`;

  const staffParams=[];

  if(establishmentId){
    staffParams.push(establishmentId);

    staffSql+=`
     AND s.establishment_id=$1
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

  // Important : on vérifie aussi les employés désactivés.
  // Une ancienne entrée restée ouverte doit être clôturée même si
  // l'employé a été désactivé depuis.
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
        p.auto_reason,
        p.latitude,
        p.longitude,
        p.accuracy,
        p.work_site_name

      FROM punches p

     JOIN staff s
  ON s.id=p.staff_id

WHERE
  1=1

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

    // Règles nécessaires aussi pour réparer un ancien service
    // resté ouvert dans les données historiques.
    const personRules=
      await establishmentRules(person);

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
  reasons:new Set(),
  timeline:[]
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
d.timeline.push(...shift.timeline);

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
  reasons:new Set(),

  timeline:[
    {
      type:'in',
      time:time.toISOString(),
      automatic:false,
      latitude:event.latitude,
      longitude:event.longitude,
      accuracy:event.accuracy,
      work_site_name:event.work_site_name || ''
    }
  ]
};

        continue;
      }


      if(!shift){
        continue;
      }
shift.timeline.push({
  type:event.type,
  time:time.toISOString(),
  automatic:!!event.automatic,
  latitude:event.latitude,
  longitude:event.longitude,
  accuracy:event.accuracy,
  work_site_name:event.work_site_name || ''
});

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


    // Service encore ouvert à la fin des événements.
    // S'il date d'un jour précédent, on le clôture ici également.
    // Cette sécurité garantit que le rapport ne reste jamais bloqué sur
    // « Service en cours » pour un ancien pointage oublié.
    if(shift){

      const now=new Date();
      const isToday=
        reportDayKey(now)===shift.day;

      if(isToday){

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

        shift.open=true;

      }else{

        const firstIn=shift.firstIn;
        const maxDayMinutes=
          Number(
            personRules &&
            personRules.max_day_span_minutes
              ? personRules.max_day_span_minutes
              : 660
          );

        const dayLimit=new Date(
          firstIn.getTime()+
          maxDayMinutes*60000
        );

        let closingLimit=dayLimit;

        try{
          const rawClosing=
            await closingDate(
              firstIn,
              personRules && personRules.closing_time
                ? personRules.closing_time
                : '23:30'
            );

          closingLimit=new Date(
            Math.max(
              rawClosing.getTime(),
              firstIn.getTime()
            )
          );
        }catch(e){
          console.error(
            'STALE SHIFT CLOSING TIME',
            person.id,
            e
          );
        }

        const candidates=[
          {time:dayLimit,reason:'MAX_JOUR'},
          {time:closingLimit,reason:'FERMETURE_ETABLISSEMENT'}
        ].sort((a,b)=>a.time-b.time);

        const automaticExit=candidates[0];
        const exitTime=new Date(
          Math.min(
            automaticExit.time.getTime(),
            now.getTime()
          )
        );

        if(shift.activeStart){
          shift.workMs+=
            Math.max(0,exitTime-shift.activeStart);
          shift.activeStart=null;
        }

        if(shift.pauseStart){
          shift.pauseMs+=
            Math.max(0,exitTime-shift.pauseStart);
          shift.pauseStart=null;
        }

        shift.lastOut=exitTime;
        shift.open=false;
        shift.automatic=true;
        shift.reasons.add(automaticExit.reason);
        shift.timeline.push({
          type:'out',
          time:exitTime.toISOString(),
          automatic:true
        });
        shift.events++;

        // On répare aussi la base pour que les prochains rapports
        // et exports retrouvent directement cette sortie automatique.
        try{
          const latest=await pool.query(`
            SELECT type,time
            FROM punches
            WHERE staff_id=$1
            ORDER BY time DESC
            LIMIT 1
          `,[person.id]);

          if(
            latest.rows[0] &&
            latest.rows[0].type!=='out' &&
            new Date(latest.rows[0].time).getTime()===firstIn.getTime()
          ){
            await pool.query(`
              INSERT INTO punches(
                id,staff_id,establishment_id,type,time,automatic,auto_reason
              )
              VALUES($1,$2,$3,'out',$4,true,$5)
            `,[
              crypto.randomUUID(),
              person.id,
              person.establishment_id,
              exitTime,
              automaticExit.reason
            ]);
          }
        }catch(e){
          console.error(
            'STALE SHIFT DB REPAIR',
            person.id,
            e
          );
        }
      }

      saveShift();
    }


    for(const [date,d] of Object.entries(days)){

      daily.push({
        staff_id:person.id,
        name:person.name,
        code:person.code,
        national_number:formatNationalNumber(person.national_number),
establishment_id:
  person.establishment_id,

establishment_name:
  person.establishment_name || 'Non attribué',
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
  Array.from(d.reasons),

timeline:d.timeline
      });
    }
  }


  // ===== HORAIRES PREVUS DU MOIS =====

  const scheduleParams=[month];
  let scheduleEstablishmentFilter='';

  if(establishmentId){
    scheduleParams.push(establishmentId);
    scheduleEstablishmentFilter=`
      AND ss.establishment_id=$2
    `;
  }

  const scheduleRows=(await pool.query(`
    SELECT
      ss.staff_id,
      ss.work_date::text AS date,
      to_char(ss.planned_start,'HH24:MI') AS planned_start,
      to_char(ss.planned_end,'HH24:MI') AS planned_end,
      ((ss.work_date + ss.planned_start) AT TIME ZONE 'Europe/Brussels') AS planned_start_at,
      ((ss.work_date + ss.planned_end) AT TIME ZONE 'Europe/Brussels') AS planned_end_at
    FROM staff_schedules ss
    JOIN staff s ON s.id=ss.staff_id
    WHERE ss.work_date >= ($1 || '-01')::date
      AND ss.work_date < (($1 || '-01')::date + interval '1 month')
      ${scheduleEstablishmentFilter}
    ORDER BY ss.work_date,ss.staff_id
  `,scheduleParams)).rows;

  const scheduleByKey=new Map();

  for(const schedule of scheduleRows){
    scheduleByKey.set(
      schedule.staff_id+'|'+schedule.date,
      schedule
    );
  }

  function addScheduleComparison(day,schedule){
    day.scheduled=!!schedule;
    day.planned_start=schedule ? schedule.planned_start : null;
    day.planned_end=schedule ? schedule.planned_end : null;
    day.late_minutes=null;
    day.overtime_minutes=null;
    day.early_leave_minutes=null;
    day.absent=false;

    if(!schedule){
      return;
    }

    const plannedStartAt=new Date(schedule.planned_start_at);
    const plannedEndAt=new Date(schedule.planned_end_at);

    if(day.first_in){
      day.late_minutes=Math.max(
        0,
        Math.round((new Date(day.first_in)-plannedStartAt)/60000)
      );
    }

    if(day.last_out){
      const actualOut=new Date(day.last_out);

      day.overtime_minutes=Math.max(
        0,
        Math.round((actualOut-plannedEndAt)/60000)
      );

      day.early_leave_minutes=Math.max(
        0,
        Math.round((plannedEndAt-actualOut)/60000)
      );
    }
  }

  for(const day of daily){
    addScheduleComparison(
      day,
      scheduleByKey.get(day.staff_id+'|'+day.date) || null
    );
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
        national_number:d.national_number || '',
establishment_id:
  d.establishment_id,

establishment_name:
  d.establishment_name || 'Non attribué',
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
  national_number:formatNationalNumber(person.national_number),

  establishment_id:
    person.establishment_id,

  establishment_name:
    person.establishment_name || 'Non attribué',

  active:person.active,

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
  Object.values(monthlyMap).filter(
    m =>
      m.active ||
      m.work_minutes>0 ||
      m.events>0
  );


  // Compatibilité avec votre ancien écran
  const employees=
    monthly.map(m=>({

      name:m.name,

      code:m.code,
      national_number:m.national_number || '',

      hours:
        Number(
          (
            m.work_minutes/60
          ).toFixed(2)
        ),

      events:m.events
    }));


  // Ajoute au détail les jours planifiés sans aucun pointage.
  // Ils n'augmentent pas les totaux de jours/heures travaillés.
  const dailyKeys=new Set(
    daily.map(d=>d.staff_id+'|'+d.date)
  );

  const staffById=new Map(
    staffRows.map(person=>[person.id,person])
  );

  for(const schedule of scheduleRows){
    const key=schedule.staff_id+'|'+schedule.date;

    if(dailyKeys.has(key)){
      continue;
    }

    const person=staffById.get(schedule.staff_id);

    if(!person){
      continue;
    }

    const now=new Date();
    const plannedStartAt=new Date(schedule.planned_start_at);
    const plannedEndAt=new Date(schedule.planned_end_at);

    // Avant l'heure prévue : pas absent, pas en retard.
    // Entre l'entrée et la sortie prévues : retard en cours.
    // Après l'heure de sortie prévue sans aucun pointage : absent.
    const absent=now>=plannedEndAt;

    const lateMinutes=
      !absent && now>=plannedStartAt
        ? Math.max(
            0,
            Math.floor((now-plannedStartAt)/60000)
          )
        : 0;

    daily.push({
      staff_id:person.id,
      name:person.name,
      code:person.code,
      national_number:formatNationalNumber(person.national_number),
      establishment_id:person.establishment_id,
      establishment_name:person.establishment_name || 'Non attribué',
      date:schedule.date,
      work_minutes:0,
      pause_minutes:0,
      events:0,
      first_in:null,
      last_out:null,
      open:false,
      automatic_exits:0,
      auto_reasons:[],
      timeline:[],
      scheduled:true,
      planned_start:schedule.planned_start,
      planned_end:schedule.planned_end,
      late_minutes:lateMinutes,
      overtime_minutes:0,
      early_leave_minutes:0,
      absent:absent
    });
  }

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

    const establishmentId=
      String(
        req.query.establishment_id || ''
      ).trim() || null;

    res.json(
      await buildHoursReport(
        month,
        establishmentId
      )
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


app.get('/api/export.csv',auth,async(req,res)=>{

  try{

    const m=String(
      req.query.month ||
      new Date().toISOString().slice(0,7)
    );

    const establishmentId=
      String(
        req.query.establishment_id || ''
      ).trim() || null;


    const params=[m];

    let establishmentFilter='';

    if(establishmentId){

      params.push(establishmentId);

      establishmentFilter=`
        AND s.establishment_id=$2
      `;
    }


    // ===== DETAIL DES POINTAGES =====

    const rows=
      (await pool.query(`

        SELECT
          s.name,
          s.code,
          s.national_number,
          s.active,
          e.name AS establishment_name,
          p.type,
          p.time,
          p.automatic,
          p.auto_reason

        FROM punches p

        JOIN staff s
          ON s.id=p.staff_id

        LEFT JOIN establishments e
          ON e.id=s.establishment_id

        WHERE
          (
            p.time
            AT TIME ZONE 'Europe/Brussels'
          )::date
          >= ($1 || '-01')::date

          AND
          (
            p.time
            AT TIME ZONE 'Europe/Brussels'
          )::date
          <
          (
            ($1 || '-01')::date
            + interval '1 month'
          )

          ${establishmentFilter}

        ORDER BY
          e.name,
          s.name,
          p.time

      `,params)).rows;


    // Utilise le même calcul que le rapport écran
    const report=
      await buildHoursReport(
        m,
        establishmentId
      );


    const actions={
      in:'Entrée',
      pause_start:'Début pause',
      pause_end:'Fin pause',
      out:'Sortie'
    };


    const reasons={
      MAX_JOUR:'Limite 11 h',
      MAX_SEMAINE:'Limite 50 h',
      FERMETURE_ETABLISSEMENT:
        'Fermeture établissement'
    };


    function cell(value){

      return `"${String(value ?? '')
        .replaceAll('"','""')}"`;
    }


    function minutesText(value){

      const total=
        Math.max(
          0,
          Number(value)||0
        );

      const h=Math.floor(total/60);

      const min=Math.round(total%60);

      return (
        h+
        ' h '+
        String(min).padStart(2,'0')
      );
    }


    function decimalHours(value){

      return (
        (Number(value)||0)/60
      )
      .toFixed(2)
      .replace('.',',');
    }


    const lines=[];


    // ===== SECTION 1 : DETAIL =====

    lines.push(
      [
        'Établissement',
        'Employé',
        'NISS / numéro national',
        'Code',
        'Action',
        'Date/heure',
        'Sortie automatique',
        'Raison'
      ]
      .map(cell)
      .join(';')
    );


    for(const r of rows){

      lines.push(
        [
          r.establishment_name ||
            'Non attribué',

          r.name,

          formatNationalNumber(r.national_number) || 'À compléter',

          r.code,

          actions[r.type] ||
            r.type,

          new Date(r.time)
            .toLocaleString(
              'fr-BE',
              {
                timeZone:
                  'Europe/Brussels'
              }
            ),

          r.automatic
            ? 'Oui'
            : 'Non',

          r.auto_reason
            ? (
                reasons[r.auto_reason] ||
                r.auto_reason
              )
            : ''

        ]
        .map(cell)
        .join(';')
      );
    }


    // Ligne vide
    lines.push('');


    // ===== SECTION 2 : RECAPITULATIF =====

    lines.push(
      cell(
        'RÉCAPITULATIF MENSUEL'
      )
    );


    lines.push(
      [
        'Employé',
        'NISS / numéro national',
        'Établissement',
        'Code',
        'Heures nettes',
        'Heures décimales',
        'Pauses',
        'Jours travaillés',
        'Pointages',
        'Sorties automatiques',
        'Statut'
      ]
      .map(cell)
      .join(';')
    );


    for(const e of report.monthly || []){

      lines.push(
        [
          e.name,

          e.national_number || 'À compléter',

          e.establishment_name ||
            'Non attribué',

          e.code,

          minutesText(
            e.work_minutes
          ),

          decimalHours(
            e.work_minutes
          ),

          minutesText(
            e.pause_minutes
          ),

          Number(e.days)||0,

          Number(e.events)||0,

          Number(
            e.automatic_exits
          )||0,

          e.active===false
            ? 'Désactivé'
            : 'Actif'

        ]
        .map(cell)
        .join(';')
      );
    }


    res.setHeader(
      'Content-Type',
      'text/csv; charset=utf-8'
    );

    res.setHeader(
      'Content-Disposition',
      `attachment; filename="pointage-${m}.csv"`
    );

    res.send(
      '\ufeff'+
      lines.join('\n')
    );


  }catch(e){

    console.error(
      'EXPORT CSV',
      e
    );

    res.status(500).json({
      error:'EXPORT_ERROR'
    });
  }
});


init()
  .then(() => app.listen(PORT, () => console.log('Pointage Pro v3 prêt')))

  .catch(e => {
    console.error(e);
    process.exit(1);
  });
