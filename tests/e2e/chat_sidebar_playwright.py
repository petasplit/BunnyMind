#!/usr/bin/env python3
"""End-to-end browser regression of the *real embedded BunnyMind UI*.

The tested React/JS bundle is served by the compiled Windows app.
Only /api/* calls are stubbed in the browser to make streaming deterministic.
No real model, personal account, bug bounty target, or external website is used.
"""
import argparse
import json
import pathlib
import sys
import time
from playwright.sync_api import sync_playwright, expect

MOCK_API = r"""
(() => {
 const original=window.fetch.bind(window);
 const jsonResponse=(v,status=200)=>new Response(JSON.stringify(v),{
   status,headers:{"content-type":"application/json"}});
 const session=(id)=>({session:{
    id,title:"Synthetic UI session",provider:"fixture",model:"fixture-model",
    meta:id==="ui-project"?{project_dir:"C:/BunnyMind/UIFixture"}:{}
   },messages:id==="ui-project"?[
     {id:"u0",role:"user",content:"Synthetic project message",created_at:"",tokens_in:0,tokens_out:0},
     {id:"a0",role:"assistant",content:"Synthetic project answer",created_at:"",tokens_in:0,tokens_out:0}
   ]:[
     {id:"u1",role:"user",content:window.__bmLastPrompt||"Synthetic user prompt",created_at:"",tokens_in:0,tokens_out:0},
     {id:"a1",role:"assistant",content:window.__bmFinalText||"",created_at:"",tokens_in:0,tokens_out:0}
   ]});
 function fakeStream(){
   const chunks=[
     {type:"session",id:"ui-live-session",title:"Synthetic UI conversation"},
     {type:"text",delta:"FIRST_STREAM_CHUNK. "},
     ...Array.from({length:12},(_,i)=>({type:"text",delta:"Streaming line "+i+" ".repeat(65)+"\n"})),
     {type:"text",delta:"FINAL_STREAM_CHUNK."},
     {type:"done"}
   ];
   const encoder=new TextEncoder();
   let timer=null,index=0;
   const stream=new ReadableStream({
     start(controller){
       function send(){
         if(index>=chunks.length){controller.close();return;}
         const ev=chunks[index++];
         if(ev.type==="text")window.__bmFinalText=(window.__bmFinalText||"")+ev.delta;
         controller.enqueue(encoder.encode("data: "+JSON.stringify(ev)+"\n\n"));
         timer=setTimeout(send,220);
       }
       timer=setTimeout(send,120);
     },
     cancel(){ if(timer!==null)clearTimeout(timer); }
   });
   return new Response(stream,{status:200,headers:{"content-type":"text/event-stream"}});
 }
 window.fetch=async function(input,init={}){
   const url=new URL(typeof input==="string"?input:input.url,location.href);
   if(!url.pathname.startsWith("/api/"))return original(input,init);
   const endpoint=url.pathname.slice(4);
   const method=(init.method||"GET").toUpperCase();
   if(endpoint==="/chat"&&method==="POST"){
     try{window.__bmLastPrompt=JSON.parse(init.body).message||"Synthetic user prompt";}catch(_){}
     window.__bmFinalText="";
     return fakeStream();
   }
   if(endpoint==="/status")return jsonResponse({needs_setup:false,ok:true,version:"ui-fixture",
     model:"fixture-model",provider:"fixture",provider_ready:true,database:"sqlite",
     uptime_seconds:20,active_sessions:1});
   if(endpoint==="/auth/status")return jsonResponse({password_required:false,authenticated:true});
   if(endpoint==="/ui/modules")return jsonResponse({modules:null,preset:"full"});
   if(endpoint==="/config")return jsonResponse({values:{display:{show_reasoning:false,max_live_reasoning_chars:2000}}});
   if(endpoint==="/context-window")return jsonResponse({context_window:32768});
   if(endpoint==="/model/options")return jsonResponse({active:{model:"fixture-model",provider:"fixture"}});
   if(endpoint==="/model/list-all")return jsonResponse({active:{model:"fixture-model",provider:"fixture"},models:[]});
   if(endpoint==="/roles")return jsonResponse({roles:[
     {name:"assistant",title:"Orchestrator",summary:"General",category:"general"},
     {name:"security",title:"Security Lead",summary:"Authorized",category:"security"}
   ]});
   if(endpoint.startsWith("/sessions/")&&endpoint.endsWith("/role"))return jsonResponse({role:""});
   if(endpoint.startsWith("/sessions/"))return jsonResponse(session(endpoint.split("/")[2]));
   if(endpoint==="/chat/interrupt")return jsonResponse({interrupted:true});
   if(endpoint==="/project/plan")return jsonResponse({steps:[]});
   if(endpoint==="/sessions")return jsonResponse({sessions:[]});
   if(endpoint==="/auth/session")return jsonResponse({authenticated:true});
   return jsonResponse({});
 };
})();
"""

def run(base: str, executable: str, artifact_dir: pathlib.Path) -> dict:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    checks = []
    errors = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, executable_path=executable if executable else None,
                                     channel=None if executable else "chrome",
                                     args=["--no-first-run","--no-default-browser-check"])
        try:
            ctx = browser.new_context(viewport={"width":1365,"height":850}, locale="en-US")
            ctx.add_init_script(script=MOCK_API)
            page = ctx.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(base+"/",wait_until="domcontentloaded")
            textarea=page.locator("textarea").first
            textarea.wait_for(state="visible",timeout=20000)
            checks.append("real React dashboard and composer rendered")

            sidebar=page.get_by_test_id("desktop-sidebar")
            expect(sidebar).to_be_visible()
            before=sidebar.bounding_box()["width"]
            rail=sidebar.locator('button[aria-expanded]').last
            rail.click()
            after=sidebar.bounding_box()["width"]
            assert after < before-80, f"desktop sidebar did not collapse: {before} -> {after}"
            rail.click()
            assert sidebar.bounding_box()["width"]>=before-4
            checks.append("desktop sidebar collapses and expands without route loss")

            prompt="Synthetic UI prompt\n"+("line from an intentionally long chat prompt\n"*52)
            textarea.fill(prompt)
            textarea.press("Enter")
            transcript=page.get_by_test_id("chat-transcript")
            transcript.wait_for(state="visible",timeout=12000)
            page.wait_for_function("document.querySelector('[data-testid=chat-transcript]')?.innerText.includes('Synthetic UI prompt')",timeout=10000)
            checks.append("user message appears before streamed assistant completion")
            page.wait_for_function("document.querySelector('[data-testid=chat-transcript]')?.innerText.includes('FIRST_STREAM_CHUNK')",timeout=10000)
            checks.append("first assistant token chunk renders during streaming")
            composer=page.get_by_test_id("chat-composer")
            top_before=composer.bounding_box()["y"]
            # The transcript is longer than the viewport. User scroll overrides autoscroll.
            transcript.evaluate("(el)=>{el.scrollTop=0; el.dispatchEvent(new Event('scroll'))}")
            time.sleep(0.15)
            at_top=transcript.evaluate("(el)=>el.scrollTop")
            assert at_top<35, f"unable to manually scroll to start: {at_top}"
            time.sleep(0.8)
            now_top=transcript.evaluate("(el)=>el.scrollTop")
            assert abs(now_top-at_top)<40, f"stream forcibly scrolled transcript ({at_top}->{now_top})"
            top_after=composer.bounding_box()["y"]
            assert abs(top_after-top_before)<2.5, f"composer bounced during stream {top_before}->{top_after}"
            checks.append("manual upward scroll wins and composer remains stable")
            page.wait_for_function("document.querySelector('[data-testid=chat-transcript]')?.innerText.includes('FINAL_STREAM_CHUNK')",timeout=20000)
            checks.append("assistant stream completes and final text remains visible")
            ctx.close()

            mobile=browser.new_context(viewport={"width":390,"height":844},locale="en-US")
            mobile.add_init_script(script=MOCK_API)
            p=mobile.new_page()
            p.on("pageerror",lambda error:errors.append(str(error)))
            p.goto(base+"/",wait_until="domcontentloaded")
            open_menu=p.locator('button[aria-controls="app-mobile-drawer"]').first
            open_menu.wait_for(state="visible",timeout=15000)
            open_menu.click()
            expect(p.locator("#app-mobile-drawer")).to_be_visible()
            assert p.evaluate("document.body.style.overflow")=="hidden","mobile drawer failed to lock background scroll"
            p.keyboard.press("Escape")
            expect(p.locator("#app-mobile-drawer")).to_have_count(0)
            assert p.evaluate("document.body.style.overflow")!="hidden","mobile drawer left body locked"
            checks.append("mobile navigation drawer Escape and body-scroll restoration")

            p.goto(base+"/c/ui-project",wait_until="domcontentloaded")
            p.get_by_text("Synthetic project message").wait_for(state="visible",timeout=15000)
            project_toggle=p.get_by_test_id("project-sidebar-toggle")
            project_toggle.wait_for(state="visible",timeout=12000)
            project_toggle.click()
            expect(p.get_by_test_id("project-sidebar-panel")).to_be_visible()
            p.keyboard.press("Escape")
            expect(p.get_by_test_id("project-sidebar-panel")).to_have_count(0)
            checks.append("mobile project sidebar opens and closes with Escape")
            mobile.close()
        finally:
            browser.close()
    if errors:
        # A broken React component or malformed runtime code must fail.
        raise AssertionError("Browser runtime errors: "+" | ".join(errors[:8]))
    return {"result":"passed","checks":checks,"model":"synthetic","network":"localhost only",
            "scope":"real bundled React UI, mocked /api/* calls"}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--base",default="http://127.0.0.1:18787")
    parser.add_argument("--chrome",default="")
    parser.add_argument("--artifacts",default="dist/ui-regression")
    args=parser.parse_args()
    dest=pathlib.Path(args.artifacts)
    try:
        result=run(args.base,args.chrome,dest)
    except Exception as exc:
        result={"result":"failed","error":str(exc)}
        (dest/"summary.json").parent.mkdir(parents=True,exist_ok=True)
        (dest/"summary.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
        print(json.dumps(result,indent=2))
        return 1
    (dest/"summary.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result,indent=2))
    return 0

if __name__=="__main__":
    sys.exit(main())
