package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "errors"
 "regexp"
 "strings"
)

const MaxAuthFields=16
const MaxAuthActions=12
const MaxAuthLinks=6
// AuthSnapshot contains only classified form metadata; it intentionally
// excludes field contents, cookies, page text, raw URLs and PII.
type AuthSnapshot struct {
 Fields []AuthField `json:"fields"`
 Actions []AuthAction `json:"actions"`
 Links []AuthLink `json:"links"`
 Challenge string `json:"challenge,omitempty"`
 SignedIn bool `json:"signed_in"`
}
type AuthField struct {
 Selector string `json:"selector"`
 Kind string `json:"kind"`
}
type AuthAction struct {
 Selector string `json:"selector"`
 Kind string `json:"kind"`
}
type AuthLink struct {
 Path string `json:"path"`
 Kind string `json:"kind"`
}
type AuthInspector interface {
 InspectAuth(context.Context)(AuthSnapshot,error)
}
// DOM source describes only structural/form categories. Labels are read
// inside the page to infer input roles, but never leave the browser.
const authDiscoveryJS = `(() => {
 const visible = e => {
  const r=e.getBoundingClientRect(),s=getComputedStyle(e);
  return r.width>0 && r.height>0 && s.display!=='none' && s.visibility!=='hidden' && !e.disabled;
 };
 const safeId=id=> /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(id);
 const selector=e=>{
  if(e.id&&safeId(e.id))return '#'+e.id;
  let parts=[],at=e;
  while(at && at.nodeType===1 && at!==document.body && parts.length<9){
   let i=1,p=at.previousElementSibling;
   while(p){if(p.tagName===at.tagName)i++;p=p.previousElementSibling;}
   parts.unshift(at.tagName.toLowerCase()+':nth-of-type('+i+')');
   at=at.parentElement;
  }
  return 'body>'+parts.join('>');
 };
 const sem=e=>{
  let v=[e.type,e.name,e.id,e.autocomplete,e.placeholder,e.getAttribute('aria-label'),
   (e.labels&&e.labels[0]&&e.labels[0].textContent)||''].join(' ').toLowerCase();
  return v.slice(0,256);
 };
 const fieldKind=e=>{
  const t=(e.type||'text').toLowerCase(),s=sem(e);
  if(t==='hidden'||t==='checkbox'||t==='radio'||t==='file'||t==='submit')return '';
  if(t==='password')return /confirm|repeat|again/.test(s)?'confirm_password':'password';
  if(/one.time|verification|verify|otp|2fa|security.code|auth.code|pin|code/.test(s))return 'otp';
  if(t==='email'||/email|e.mail|mail.address/.test(s))return 'email';
  if(/username|user.name|account.name|login.id/.test(s))return 'username';
  return '';
 };
 const actionKind=e=>{
  const s=[e.textContent,e.getAttribute('aria-label'),e.value,e.id].join(' ').toLowerCase().slice(0,200);
  if(/verify|confirm code|submit code|check code/.test(s))return 'verify';
  if(/sign up|signup|register|create account|join now/.test(s))return 'signup';
  if(/sign in|log in|login|continue|submit/.test(s))return 'login';
  return '';
 };
 const fields=[...document.querySelectorAll('input')].filter(visible)
  .map(e=>({selector:selector(e),kind:fieldKind(e)})).filter(e=>e.kind).slice(0,16);
 const actions=[...document.querySelectorAll('button,input[type=submit]')].filter(visible)
  .map(e=>({selector:selector(e),kind:actionKind(e)})).filter(e=>e.kind).slice(0,12);
 const links=[...document.querySelectorAll('a[href]')].filter(visible).flatMap(e=>{
  const s=[e.textContent,e.getAttribute('aria-label')].join(' ').toLowerCase().slice(0,150);
  const k=/sign up|register|create account/.test(s)?'signup':/sign in|log in|login/.test(s)?'login':'';
  if(!k)return [];
  try{
   const u=new URL(e.href,location.href);
   if(u.origin!==location.origin||u.search||u.hash||u.username||u.password)return [];
   if(!/^/[a-zA-Z0-9_./%-]{0,255}$/.test(u.pathname))return [];
   return [{kind:k,path:u.pathname}];
  }catch{return [];}
 }).slice(0,6);
 const challenge=!!document.querySelector('iframe[src*="captcha"],iframe[src*="turnstile"],[class*="captcha"],[id*="captcha"],[data-sitekey]')
  ?'anti_bot':'';
 const signedIn=!fields.some(f=>f.kind==='password') &&
  [...document.querySelectorAll('a,button')].filter(visible)
  .some(e=>/^(log out|logout|sign out)$/i.test((e.textContent||'').trim().slice(0,40)));
 return JSON.stringify({fields,actions,links,challenge,signed_in:signedIn});
})()`
var kindField=map[string]bool{"email":true,"username":true,"password":true,"confirm_password":true,"otp":true}
var kindAction=map[string]bool{"login":true,"signup":true,"verify":true}
var safeDiscoveredSelector=regexp.MustCompile(`^(?:#[a-zA-Z][a-zA-Z0-9_-]{0,63}|body>(?:[a-z]+:nth-of-type[(][1-9][0-9]{0,3}[)]>){0,8}[a-z]+:nth-of-type[(][1-9][0-9]{0,3}[)])package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "errors"
 "regexp"
 "strings"
)

const MaxAuthFields=16
const MaxAuthActions=12
const MaxAuthLinks=6
// AuthSnapshot contains only classified form metadata; it intentionally
// excludes field contents, cookies, page text, raw URLs and PII.
type AuthSnapshot struct {
 Fields []AuthField `json:"fields"`
 Actions []AuthAction `json:"actions"`
 Links []AuthLink `json:"links"`
 Challenge string `json:"challenge,omitempty"`
 SignedIn bool `json:"signed_in"`
}
type AuthField struct {
 Selector string `json:"selector"`
 Kind string `json:"kind"`
}
type AuthAction struct {
 Selector string `json:"selector"`
 Kind string `json:"kind"`
}
type AuthLink struct {
 Path string `json:"path"`
 Kind string `json:"kind"`
}
type AuthInspector interface {
 InspectAuth(context.Context)(AuthSnapshot,error)
}
// DOM source describes only structural/form categories. Labels are read
// inside the page to infer input roles, but never leave the browser.
const authDiscoveryJS = `(() => {
 const visible = e => {
  const r=e.getBoundingClientRect(),s=getComputedStyle(e);
  return r.width>0 && r.height>0 && s.display!=='none' && s.visibility!=='hidden' && !e.disabled;
 };
 const safeId=id=> /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(id);
 const selector=e=>{
  if(e.id&&safeId(e.id))return '#'+e.id;
  let parts=[],at=e;
  while(at && at.nodeType===1 && at!==document.body && parts.length<9){
   let i=1,p=at.previousElementSibling;
   while(p){if(p.tagName===at.tagName)i++;p=p.previousElementSibling;}
   parts.unshift(at.tagName.toLowerCase()+':nth-of-type('+i+')');
   at=at.parentElement;
  }
  return 'body>'+parts.join('>');
 };
 const sem=e=>{
  let v=[e.type,e.name,e.id,e.autocomplete,e.placeholder,e.getAttribute('aria-label'),
   (e.labels&&e.labels[0]&&e.labels[0].textContent)||''].join(' ').toLowerCase();
  return v.slice(0,256);
 };
 const fieldKind=e=>{
  const t=(e.type||'text').toLowerCase(),s=sem(e);
  if(t==='hidden'||t==='checkbox'||t==='radio'||t==='file'||t==='submit')return '';
  if(t==='password')return /confirm|repeat|again/.test(s)?'confirm_password':'password';
  if(/one.time|verification|verify|otp|2fa|security.code|auth.code|pin/.test(s))return 'otp';
  if(t==='email'||/email|e.mail|mail.address/.test(s))return 'email';
  if(/username|user.name|account.name|login.id/.test(s))return 'username';
  return '';
 };
 const actionKind=e=>{
  const s=[e.textContent,e.getAttribute('aria-label'),e.value,e.id].join(' ').toLowerCase().slice(0,200);
  if(/verify|confirm code|submit code|check code/.test(s))return 'verify';
  if(/sign up|signup|register|create account|join now/.test(s))return 'signup';
  if(/sign in|log in|login|continue|submit/.test(s))return 'login';
  return '';
 };
 const fields=[...document.querySelectorAll('input')].filter(visible)
  .map(e=>({selector:selector(e),kind:fieldKind(e)})).filter(e=>e.kind).slice(0,16);
 const actions=[...document.querySelectorAll('button,input[type=submit]')].filter(visible)
  .map(e=>({selector:selector(e),kind:actionKind(e)})).filter(e=>e.kind).slice(0,12);
 const links=[...document.querySelectorAll('a[href]')].filter(visible).flatMap(e=>{
  const s=[e.textContent,e.getAttribute('aria-label')].join(' ').toLowerCase().slice(0,150);
  const k=/sign up|register|create account/.test(s)?'signup':/sign in|log in|login/.test(s)?'login':'';
  if(!k)return [];
  try{
   const u=new URL(e.href,location.href);
   if(u.origin!==location.origin||u.search||u.hash||u.username||u.password)return [];
   if(!/^/[a-zA-Z0-9_./%-]{0,255}$/.test(u.pathname))return [];
   return [{kind:k,path:u.pathname}];
  }catch{return [];}
 }).slice(0,6);
 const challenge=!!document.querySelector('iframe[src*="captcha"],iframe[src*="turnstile"],[class*="captcha"],[id*="captcha"],[data-sitekey]')
  ?'anti_bot':'';
 const signedIn=[...document.querySelectorAll('a,button')].filter(visible)
  .some(e=>/^(log out|logout|sign out)$/i.test((e.textContent||'').trim().slice(0,40)));
 return JSON.stringify({fields,actions,links,challenge,signed_in:signedIn});
})()`
var kindField=map[string]bool{"email":true,"username":true,"password":true,"confirm_password":true,"otp":true}
var kindAction=map[string]bool{"login":true,"signup":true,"verify":true}
)
func validateAuthSnapshot(s AuthSnapshot)error{
 if len(s.Fields)>MaxAuthFields||len(s.Actions)>MaxAuthActions||len(s.Links)>MaxAuthLinks{return errors.New("auth snapshot exceeds limits")}
 if s.Challenge!=""&&s.Challenge!="anti_bot"&&s.Challenge!="mfa"&&s.Challenge!="passkey"{return errors.New("invalid challenge")}
 for _,f:=range s.Fields{if !kindField[f.Kind]||!safeDiscoveredSelector.MatchString(f.Selector){return errors.New("unsafe form field")}}
 for _,a:=range s.Actions{if !kindAction[a.Kind]||!safeDiscoveredSelector.MatchString(a.Selector){return errors.New("unsafe form button")}}
 for _,l:=range s.Links{if !kindAction[l.Kind]||l.Kind=="verify"||!safePath(l.Path){return errors.New("unsafe authentication link")}}
 return nil
}
func (d *chromeDriver) InspectAuth(ctx context.Context)(AuthSnapshot,error){
 raw,err:=d.session.EvalString(ctx,authDiscoveryJS)
 if err!=nil||len(raw)>16*1024{return AuthSnapshot{},errors.New("could not inspect approved authentication page")}
 var snapshot AuthSnapshot
 decoder:=json.NewDecoder(strings.NewReader(raw))
 decoder.DisallowUnknownFields()
 if err:=decoder.Decode(&snapshot);err!=nil{return AuthSnapshot{},errors.New("authentication form data invalid")}
 if err:=validateAuthSnapshot(snapshot);err!=nil{return AuthSnapshot{},err}
 return snapshot,nil
}
