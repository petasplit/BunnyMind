package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "errors"

 "github.com/enowdev/antares/internal/browser"
)

// This script returns only enumerated roles and bounded synthetic selectors.
// It never returns input values, displayed text, page content or secret data.
const authDiscoveryScript = `(() => {
 const visible = el => !!el && !el.disabled && el.getClientRects().length > 0 &&
   getComputedStyle(el).visibility !== 'hidden';
 const safeRef = (el,kind,index) => {
   const token = 'bm-auto-' + kind + '-' + index;
   const selector = '[data-bm-auth="' + token + '"]';
   const previous = document.querySelector(selector);
   if (previous && previous !== el) return '';
   el.setAttribute('data-bm-auth',token);
   return selector;
 };
 const fields = [];
 const kinds = {};
 const elements = Array.from(document.querySelectorAll('input')).filter(visible).slice(0,48);
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
 const controls = Array.from(document.querySelectorAll('button,input[type=submit]'))
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
 const challenged = !!document.querySelector('iframe[src*="captcha"], iframe[src*="turnstile"], .g-recaptcha, [data-sitekey]');
 let challenge = challenged ? 'anti_bot' : '';
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
 for (const el of Array.from(document.querySelectorAll('a[href]')).slice(0,64)) {
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
 return {kind,fields,submit_selector:submit,ambiguous:candidates>1,challenge,signup_path:signupPath,login_path:loginPath};
})()`

func (d *chromeDriver) DiscoverAuth(ctx context.Context)(AuthPageState,error){
 raw,err:=d.session.Eval(ctx,authDiscoveryScript)
 if err!=nil{return AuthPageState{},errors.New("auth form inspection failed")}
 var result AuthPageState
 if err:=json.Unmarshal(raw,&result);err!=nil{return AuthPageState{},errors.New("invalid browser discovery result")}
 if err:=validateDiscovery(result);err!=nil{return AuthPageState{},err}
 return result,nil
}

// Keep interface satisfied only by Chrome-driven browsers; deterministic
// mocked browser tests can implement the same narrow discovery method.
var _ DiscoveryBrowser = (*chromeDriver)(nil)
var _ = browser.New
