package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "errors"
 "strings"

 "github.com/enowdev/antares/internal/browser"
)

// This script returns only enumerated roles and bounded synthetic selectors.
// It never returns input values, displayed text, page content or secret data.
const authDiscoveryScript = `(() => {
 const scopedOrigins = new Set(__SCOPED_ORIGINS__);
 const visible = el => !!el && !el.disabled && el.getClientRects().length > 0 &&
   getComputedStyle(el).visibility !== 'hidden';
 // Bounded traversal of open shadow roots and accessible same-origin frames.
 const collect = (selector) => {
   const out = [];
   const scan = (root,depth) => {
     if (!root || depth > 3 || out.length >= 128) return;
     for (const el of Array.from(root.querySelectorAll(selector)).slice(0,128-out.length)) out.push(el);
     if (depth < 3) {
       for (const el of Array.from(root.querySelectorAll('*')).slice(0,80)) {
         if (el.shadowRoot) scan(el.shadowRoot,depth+1);
         if (el.tagName === 'IFRAME') {
           try { if (el.contentDocument && el.contentDocument.location.origin === location.origin)
             scan(el.contentDocument,depth+1);
           } catch (_) {}
         }
       }
     }
   };
   scan(document,0);
   return out.slice(0,128);
 };
 window.__bmAuthRefs = Object.create(null);
 const safeRef = (el,kind,index) => {
   const token = 'bm-auto-' + kind + '-' + index;
   const selector = '[data-bm-auth="' + token + '"]';
   if (window.__bmAuthRefs[token] && window.__bmAuthRefs[token]!==el) return '';
   el.setAttribute('data-bm-auth',token);
   window.__bmAuthRefs[token]=el;
   return selector;
 };
 const fields = [];
 const kinds = {};
 const elements = collect('input').filter(visible).slice(0,48);
 let passwordCount = 0;
 for (const el of elements) {
   const type = (el.type || 'text').toLowerCase();
   const clue = [el.name || '', el.id || '', el.getAttribute('autocomplete') || '',
     el.getAttribute('aria-label') || ''].join(' ').toLowerCase().slice(0,160);
   let role = '';
   if (type === 'password') {
     role = passwordCount++ === 0 ? 'password' : 'password_confirm';
   } else if (type === 'email' || /email|e-mail/.test(clue)) {
     role = 'email';
   } else if (/(one-time-code|otp|verify|verification|passcode|auth.code|pin|2fa)/.test(clue)) {
     role = 'otp';
   } else if ((type === 'text' || type === 'tel') && /user|account|login|phone/.test(clue)) {
     role = 'username';
   }
   if (!role || kinds[role]) continue;
   const selector = safeRef(el,'field',fields.length + 1);
   if (!selector) continue;
   fields.push({selector,role});
   kinds[role] = true;
   if (fields.length >= 8) break;
 }
 const controls = collect('button,input[type=submit]')
   .filter(visible).slice(0,32);
 let submit = '';
 let candidates = 0;
 for (const el of controls) {
   const descriptor = [(el.innerText || ''),(el.value || ''),el.getAttribute('aria-label') || '']
     .join(' ').trim().toLowerCase().slice(0,100);
   if (el.type === 'submit' || /(sign.?in|log.?in|continue|submit|register|sign.?up|create account|verify|confirm)/.test(descriptor)) {
     candidates++;
     if (candidates === 1) submit = safeRef(el,'submit',1);
   }
 }
 let passkeySelector = '';
 let passkeyCandidates=0;
 for (const el of controls) {
   const descriptor=((el.innerText||'')+' '+(el.getAttribute('aria-label')||'')).trim().toLowerCase().slice(0,100);
   if (/(passkey|security key|windows hello|touch.?id|face.?id)/.test(descriptor)) {
     passkeyCandidates++;
     if (passkeyCandidates===1) passkeySelector=safeRef(el,'passkey',1);
   }
 }
 const challenged = !!document.querySelector('iframe[src*="captcha"], iframe[src*="turnstile"], .g-recaptcha, [data-sitekey]');
 let challenge = challenged ? 'anti_bot' : '';
 // These are official public *test* sitekeys, not a CAPTCHA bypass.
 const testSitekeys = new Set([
   '1x00000000000000000000AA','1x00000000000000000000BB',
   '2x00000000000000000000AB','2x00000000000000000000BB',
   '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'
 ]);
 const testWidgets = collect('[data-sitekey]').slice(0,16);
 const captchaTestKey = !!challenge && testWidgets.length>0 &&
   testWidgets.every(el => testSitekeys.has(el.getAttribute('data-sitekey')||''));
 const tokenFields=collect('[name="cf-turnstile-response"],[name="g-recaptcha-response"]');
 const captchaReady=!!challenge && tokenFields.some(el=>typeof el.value==='string'&&el.value.length>10);


 if (!challenge && document.querySelector('input[autocomplete="webauthn"]')) challenge='passkey';
 let kind = 'unknown';
 if (challenge) kind = 'challenge';
 else if (kinds.otp && !kinds.password) kind='verification';
 else if (kinds.password && (kinds.email || kinds.username)) {
   const pageHint = ((document.title || '')+' '+Array.from(controls).map(el=>(el.innerText || '').slice(0,50)).join(' ')).toLowerCase();
   kind = /(register|sign.?up|create account)/.test(pageHint) || !!kinds.password_confirm ? 'signup' : 'login';
 } else if (kinds.email || kinds.username) kind='login';
 let signupPath = '';
 let loginPath = '';
 for (const el of collect('a[href]').slice(0,64)) {
   if (!visible(el)) continue;
   const caption = (el.innerText || '').trim().toLowerCase().slice(0,70);
   const signup = /(create account|register|sign.?up)/.test(caption);
   const login = /(sign.?in|log.?in)/.test(caption);
   if (!signup && !login) continue;
   try {
     const uri = new URL(el.href, location.href);
     if (uri.origin === location.origin && !uri.search && !uri.hash &&
         /^\/[A-Za-z0-9_./%-]*$/.test(uri.pathname) &&
         !uri.pathname.includes('..') && !uri.pathname.includes('%')) {
       if (signup && !signupPath) signupPath = uri.pathname;
       if (login && !loginPath) loginPath = uri.pathname;
       if (signupPath && loginPath) break;
     }
   } catch (_) {}
 }
 let providerSelector = '';
 let providers = 0;
 for (const el of collect('a[href]').slice(0,64)) {
   if (!visible(el)) continue;
   const caption=(el.innerText||el.getAttribute('aria-label')||'').trim().toLowerCase().slice(0,100);
   if (!/(continue with|sign in with|login with|sso|single sign.on|microsoft|google|okta|keycloak)/.test(caption)) continue;
   try {
     const link=new URL(el.href,location.href);
     if (link.protocol!=='https:' || !scopedOrigins.has(link.origin) ||
         link.origin===location.origin || link.username || link.password) continue;
     providers++;
     if (providers===1) providerSelector=safeRef(el,'provider',1);
   } catch (_) {}
 }
 return {kind,fields,submit_selector:submit,ambiguous:candidates>1||providers>1,
   challenge,signup_path:signupPath,login_path:loginPath,
   provider_selector:providerSelector,passkey_selector:passkeyCandidates===1?passkeySelector:'',captcha_test_key:captchaTestKey,captcha_ready:captchaReady};
})()`

func (d *chromeDriver) DiscoverAuth(ctx context.Context)(AuthPageState,error){
 return d.DiscoverAuthScoped(ctx,nil)
}
func (d *chromeDriver) DiscoverAuthScoped(ctx context.Context,origins []string)(AuthPageState,error){
 if len(origins)>32{return AuthPageState{},errors.New("too many scoped identity providers")}
 allow:=make([]string,0,len(origins))
 for _,origin:=range origins {
  normalized,err:=strictOrigin(origin)
  if err!=nil{return AuthPageState{},errors.New("unapproved identity provider origin")}
  allow=append(allow,normalized)
 }
 encoded,err:=json.Marshal(allow)
 if err!=nil{return AuthPageState{},errors.New("cannot encode scope")}
 script:=strings.Replace(authDiscoveryScript,"__SCOPED_ORIGINS__",string(encoded),1)
 raw,err:=d.session.Eval(ctx,script)
 if err!=nil{return AuthPageState{},errors.New("auth form inspection failed")}
 var state AuthPageState
 if err:=json.Unmarshal(raw,&state);err!=nil{return AuthPageState{},errors.New("invalid browser discovery result")}
 if err:=validateDiscovery(state);err!=nil{return AuthPageState{},err}
 return state,nil
}

// Keep interface satisfied only by Chrome-driven browsers; deterministic
// mocked browser tests can implement the same narrow discovery method.
var _ DiscoveryBrowser = (*chromeDriver)(nil)
var _ = browser.New
