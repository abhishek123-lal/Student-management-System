const express=require("express"),crypto=require("crypto"),fs=require("fs"),path=require("path");
const app=express(),DB=path.join(__dirname,"data.json"),PORT=process.env.PORT||3000;
app.use(express.json());app.use(express.static(path.join(__dirname,"public")));

const hash=(p,s)=>crypto.scryptSync(p,s,32).toString("hex");
const mk=(name,pw,role)=>{const salt=crypto.randomBytes(16).toString("hex");return{name,role,salt,hash:hash(pw,salt)}};
let db;try{db=JSON.parse(fs.readFileSync(DB,"utf8"))}catch(e){
  db={users:{admin:mk("Admin","admin123","admin"),teacher:mk("Teacher","teach123","teacher")},logins:[]}}
const save=()=>fs.writeFileSync(DB,JSON.stringify(db,null,2));save();
const tokens=new Map();

function start(u,req,res){            // record the login + issue a session token
  const x=db.users[u];
  db.logins.push({username:u,name:x.name,role:x.role,time:new Date().toISOString(),ip:req.ip});save();
  const token=crypto.randomBytes(24).toString("hex");tokens.set(token,u);
  res.json({token,name:x.name,role:x.role});
}
app.post("/api/signup",(req,res)=>{
  const u=String(req.body.username||"").toLowerCase(),p=String(req.body.password||""),n=String(req.body.name||"").trim()||u;
  if(!/^[a-z0-9_.]{3,20}$/.test(u))return res.status(400).json({error:"Username: 3-20 letters, numbers, . or _"});
  if(p.length<6)return res.status(400).json({error:"Password must be at least 6 characters."});
  if(db.users[u])return res.status(409).json({error:"That username is taken."});
  db.users[u]=mk(n.slice(0,40),p,"student");save();start(u,req,res);
});
app.post("/api/login",(req,res)=>{
  const u=String(req.body.username||"").toLowerCase(),p=String(req.body.password||""),x=db.users[u];
  const good=x&&crypto.timingSafeEqual(Buffer.from(hash(p,x.salt)),Buffer.from(x.hash));
  if(!good)return res.status(401).json({error:"Wrong username or password."});
  start(u,req,res);
});
app.get("/api/logins",(req,res)=>{   // teachers/admins only
  const u=tokens.get((req.headers.authorization||"").replace("Bearer ",""));
  if(!u||!["admin","teacher"].includes(db.users[u].role))return res.status(403).json({error:"Not allowed"});
  res.json(db.logins.slice(-200).reverse());
});
app.listen(PORT,()=>console.log("EduMind running at http://localhost:"+PORT));
