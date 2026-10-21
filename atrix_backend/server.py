import os, hmac, hashlib, secrets, time
from datetime import datetime, timedelta, timezone
from typing import Optional
import httpx
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, DateTime, Text, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

DATABASE_URL=os.getenv('DATABASE_URL','sqlite:///./atrix.db')
connect_args={'check_same_thread':False} if DATABASE_URL.startswith('sqlite') else {}
engine=create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal=sessionmaker(bind=engine, autoflush=False, autocommit=False)
class Base(DeclarativeBase): pass
class User(Base):
    __tablename__='users'
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    username: Mapped[str]=mapped_column(String(80),unique=True,index=True)
    email: Mapped[str]=mapped_column(String(200),unique=True,index=True)
    salt: Mapped[str]=mapped_column(String(64))
    password_hash: Mapped[str]=mapped_column(String(128))
    plan: Mapped[str]=mapped_column(String(30),default='free')
    expires_at: Mapped[Optional[datetime]]=mapped_column(DateTime(timezone=True),nullable=True)
    active: Mapped[bool]=mapped_column(Boolean,default=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
class Activation(Base):
    __tablename__='activation_codes'
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    code_hash: Mapped[str]=mapped_column(String(128),unique=True,index=True)
    plan: Mapped[str]=mapped_column(String(30))
    days: Mapped[int]=mapped_column(Integer)
    used_by: Mapped[Optional[int]]=mapped_column(Integer,nullable=True)
    used_at: Mapped[Optional[datetime]]=mapped_column(DateTime(timezone=True),nullable=True)
class Event(Base):
    __tablename__='events'
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    user_id: Mapped[Optional[int]]=mapped_column(Integer,nullable=True)
    category: Mapped[str]=mapped_column(String(40))
    detail: Mapped[str]=mapped_column(Text,default='')
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
Base.metadata.create_all(engine)
app=FastAPI(title='ATRIX AI Backend',version='1.0.0')
origins=os.getenv('CORS_ORIGINS','*').split(',')
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_credentials=False,allow_methods=['*'],allow_headers=['*'])
def db():
    s=SessionLocal()
    try: yield s
    finally: s.close()
def now(): return datetime.now(timezone.utc)
def pw_hash(password,salt): return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),180000).hex()
def token_for(user_id):
    secret=os.getenv('TOKEN_SECRET')
    if not secret: raise HTTPException(503,'Backend TOKEN_SECRET is not configured')
    payload=f'{user_id}.{int(time.time())+86400}'
    sig=hmac.new(secret.encode(),payload.encode(),hashlib.sha256).hexdigest()
    return payload+'.'+sig
def current_user(authorization: str|None=Header(default=None), s:Session=Depends(db)):
    if not authorization or not authorization.lower().startswith('bearer '): raise HTTPException(401,'Please sign in')
    try:
        uid,exp,sig=authorization[7:].split('.',2); payload=f'{uid}.{exp}'
        expected=hmac.new(os.environ['TOKEN_SECRET'].encode(),payload.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig,expected) or int(exp)<int(time.time()): raise ValueError()
        user=s.get(User,int(uid))
        if not user or not user.active: raise ValueError()
        return user
    except Exception: raise HTTPException(401,'Session expired; please sign in again')
def admin_check(x_admin_key: str|None=Header(default=None)):
    secret=os.getenv('ADMIN_API_KEY')
    if not secret or not x_admin_key or not hmac.compare_digest(secret,x_admin_key): raise HTTPException(403,'Admin access denied')
class RegisterIn(BaseModel): username:str=Field(min_length=3,max_length=80); email:str; password:str=Field(min_length=8,max_length=200)
class LoginIn(BaseModel): email:str; password:str
class ChatIn(BaseModel): provider:str='gemini'; message:str=Field(min_length=1,max_length=12000); history:list[dict]=Field(default_factory=list); api_key:Optional[str]=None; language:str='ur-PK'
class ActivateIn(BaseModel): code:str
class CodeIn(BaseModel): plan:str='monthly'; days:int=Field(default=30,ge=7,le=3650); count:int=Field(default=1,ge=1,le=100)
@app.get('/health')
def health(): return {'ok':True,'service':'ATRIX AI Backend','time':now().isoformat()}
@app.post('/v1/auth/register')
def register(data:RegisterIn,s:Session=Depends(db)):
    email=data.email.strip().lower()
    if '@' not in email: raise HTTPException(400,'Enter a valid email')
    if s.query(User).filter((User.email==email)|(User.username==data.username)).first(): raise HTTPException(409,'Email or username already exists')
    salt=secrets.token_hex(16); u=User(username=data.username.strip(),email=email,salt=salt,password_hash=pw_hash(data.password,salt)); s.add(u); s.commit(); s.refresh(u)
    return {'token':token_for(u.id),'user':public_user(u)}
@app.post('/v1/auth/login')
def login(data:LoginIn,s:Session=Depends(db)):
    u=s.query(User).filter(User.email==data.email.strip().lower()).first()
    if not u or not hmac.compare_digest(u.password_hash,pw_hash(data.password,u.salt)) or not u.active: raise HTTPException(401,'Email or password incorrect')
    return {'token':token_for(u.id),'user':public_user(u)}
def public_user(u):
    exp=u.expires_at.isoformat() if u.expires_at else None
    expired=bool(u.expires_at and u.expires_at.replace(tzinfo=timezone.utc)<now())
    return {'id':u.id,'username':u.username,'email':u.email,'plan':u.plan,'expires_at':exp,'plan_expired':expired,'active':u.active}
@app.get('/v1/me')
def me(u:User=Depends(current_user)): return {'user':public_user(u)}
@app.post('/v1/license/activate')
def activate(data:ActivateIn,u:User=Depends(current_user),s:Session=Depends(db)):
    digest=hashlib.sha256(data.code.strip().encode()).hexdigest(); row=s.query(Activation).filter_by(code_hash=digest).first()
    if not row or row.used_by is not None: raise HTTPException(400,'Invalid or already used activation code')
    u.plan=row.plan; base=u.expires_at if u.expires_at and u.expires_at.replace(tzinfo=timezone.utc)>now() else now(); u.expires_at=base+timedelta(days=row.days); row.used_by=u.id; row.used_at=now(); s.add(Event(user_id=u.id,category='license_activated',detail=f'{row.plan}:{row.days} days')); s.commit()
    return {'ok':True,'user':public_user(u)}
@app.post('/v1/chat')
async def chat(data:ChatIn,u:User=Depends(current_user),s:Session=Depends(db)):
    if u.expires_at and u.expires_at.replace(tzinfo=timezone.utc)<now(): raise HTTPException(402,'Your plan has expired. Activate a plan to continue.')
    key=(data.api_key or '').strip()
    providers={'gemini':('GEMINI_API_KEY','https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent'), 'openai':('OPENAI_API_KEY','https://api.openai.com/v1/chat/completions'), 'openrouter':('OPENROUTER_API_KEY','https://openrouter.ai/api/v1/chat/completions')}
    provider=data.provider.lower()
    if provider not in providers: raise HTTPException(400,'Provider must be gemini, openrouter, or openai')
    env_key,url=providers[provider]; key=key or os.getenv(env_key,'')
    if not key: raise HTTPException(400,f'Configure the {provider} API key in Settings or backend environment')
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            if provider=='gemini':
                contents=[]
                for item in data.history[-12:]:
                    role='model' if item.get('role') in ('assistant','model') else 'user'; txt=str(item.get('content',''))[:6000]
                    if txt: contents.append({'role':role,'parts':[{'text':txt}]})
                contents.append({'role':'user','parts':[{'text':data.message}]})
                r=await client.post(url,params={'key':key},json={'systemInstruction':{'parts':[{'text':f'You are ATRIX AI. Respond naturally in {"Pakistani Urdu" if data.language=="ur-PK" else "English" if data.language=="en" else data.language}. Be honest when unsure.'}]},'contents':contents,'generationConfig':{'temperature':0.7}})
                obj=r.json(); r.raise_for_status(); answer=obj['candidates'][0]['content']['parts'][0]['text']
            else:
                msgs=[{'role':'system','content':f'You are ATRIX AI. Respond naturally in {"Pakistani Urdu" if data.language=="ur-PK" else "English" if data.language=="en" else data.language}. Be honest when unsure.'}]
                msgs += [{'role':('assistant' if x.get('role') in ('assistant','model') else 'user'),'content':str(x.get('content',''))[:6000]} for x in data.history[-12:]]
                msgs.append({'role':'user','content':data.message})
                headers={'Authorization':f'Bearer {key}','Content-Type':'application/json'}
                if provider=='openrouter': headers.update({'HTTP-Referer':os.getenv('APP_URL','https://example.com'),'X-Title':'ATRIX AI'})
                model=os.getenv('OPENAI_MODEL','gpt-4o-mini') if provider=='openai' else os.getenv('OPENROUTER_MODEL','openai/gpt-4o-mini')
                r=await client.post(url,headers=headers,json={'model':model,'messages':msgs}); r.raise_for_status(); answer=r.json()['choices'][0]['message']['content']
        s.add(Event(user_id=u.id,category='chat',detail=f'provider={provider};chars={len(data.message)}')); s.commit()
        return {'answer':answer,'provider':provider,'language':data.language}
    except httpx.HTTPStatusError as e: raise HTTPException(502,f'{provider} API returned HTTP {e.response.status_code}; check the API key and model settings')
    except Exception as e: raise HTTPException(502,f'AI provider request failed: {type(e).__name__}')
@app.post('/v1/admin/activation-codes',dependencies=[Depends(admin_check)])
def make_codes(data:CodeIn,s:Session=Depends(db)):
    result=[]
    for _ in range(data.count):
        code='ATRIX-'+secrets.token_hex(4).upper()+'-'+secrets.token_hex(3).upper()
        s.add(Activation(code_hash=hashlib.sha256(code.encode()).hexdigest(),plan=data.plan,days=data.days)); result.append(code)
    s.commit(); return {'codes':result,'warning':'Save these codes now; they are not stored in readable form.'}
@app.get('/v1/admin/users',dependencies=[Depends(admin_check)])
def admin_users(s:Session=Depends(db)):
    return {'users':[public_user(x) for x in s.query(User).order_by(User.id.desc()).limit(500).all()]}
@app.post('/v1/admin/users/{user_id}/suspend',dependencies=[Depends(admin_check)])
def suspend(user_id:int,s:Session=Depends(db)):
    u=s.get(User,user_id)
    if not u: raise HTTPException(404,'User not found')
    u.active=False; s.commit(); return {'ok':True}
