// Local, static-only AST + ECMA-426 source-map analyzer.
// This program never evaluates third-party JavaScript or performs fetch.
// The only output is bounded, query-redacted candidate route metadata.
import ts from "typescript";
import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const MAX_SCRIPT=512*1024;
const MAX_MAP=1024*1024;
const MAX_SITES=160;
const forbidden=["/logout","/signout","/delete","/destroy","/unsubscribe",
 "/purchase","/payment","/checkout","/cancel","/reset","/terminate","/disable"];
const hex=(s)=>crypto.createHash("sha256").update(s).digest("hex");
function sanitize(input,origin){
 if(typeof input!=="string"||input.length<1||input.length>2048)return null;
 if(input.startsWith("//")||input.startsWith("data:")||input.startsWith("javascript:"))return null;
 let url;
 try{url=new URL(input,origin);}catch{return null;}
 if(url.origin!==origin||url.protocol!=="https:")return null;
 if(/%2e|%2f|%5c/i.test(url.pathname)||url.pathname.includes("..")||url.pathname.includes("\\"))return null;
 const pathname=url.pathname||"/";
 if(forbidden.some(word=>pathname.toLowerCase().includes(word)))return null;
 const segments=pathname.split("/").map(seg=>(seg.length>=24 || /^[0-9]{6,}$/.test(seg))?"{id}":seg);
 return segments.join("/");
}
function stringNode(n){
 if(!n)return null;
 if(ts.isStringLiteral(n)||ts.isNoSubstitutionTemplateLiteral(n))return n.text;
 // Never infer URLs from dynamic template/expression nodes.
 return null;
}
function callName(n){
 if(ts.isIdentifier(n))return n.text;
 if(ts.isPropertyAccessExpression(n)){
  const parent=callName(n.expression);
  return parent?parent+"."+n.name.text:"";
 }
 return "";
}
function extractJS(code,origin){
 if(typeof code!=="string"||Buffer.byteLength(code,"utf8")>MAX_SCRIPT)throw Error("oversized input script");
 const file=ts.createSourceFile("bundle.js",code,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
 const issues=file.parseDiagnostics.map(d=>String(ts.flattenDiagnosticMessageText(d.messageText," ")).slice(0,120));
 const entries=[],seen=new Set();
 let visited=0;
 function add(raw,method,source,node){
  const clean=sanitize(raw,origin);
  if(!clean)return;
  const loc=file.getLineAndCharacterOfPosition(node.getStart(file));
  const kind=method.toUpperCase();
  const key=kind+"|"+clean+"|"+source;
  if(seen.has(key)||entries.length>=MAX_SITES)return;
  seen.add(key);
  entries.push({path:clean,method:kind,source,line:loc.line+1,column:loc.character+1,
    reference_sha256:hex(code.slice(node.pos,Math.min(code.length,node.end)).slice(0,4096))});
 }
 const methods=new Set(["get","post","patch","put","delete","head"]);
 function visit(node){
  if(++visited>170000)return;
  if(ts.isCallExpression(node)){
   const name=callName(node.expression);
   const args=node.arguments;
   if((name==="fetch"||name==="window.fetch"||name==="import")&&args.length){
    const raw=stringNode(args[0]);if(raw)add(raw,"GET","ast_"+name,node);
   }
   if((name==="axios.get"||name==="axios.post"||name==="axios.patch"||
       name==="axios.put"||name==="axios.delete"||name==="axios.head")&&args.length){
    const raw=stringNode(args[0]);if(raw)add(raw,name.split(".").at(-1),"ast_axios",node);
   }
   if((name.endsWith(".open")||name==="open")&&args.length>=2){
    const method=stringNode(args[0]),raw=stringNode(args[1]);
    if(raw&&method&&/^(GET|POST|PUT|PATCH|DELETE|HEAD)$/i.test(method))add(raw,method,"ast_xhr_open",node);
   }
   if(name==="navigator.sendBeacon"&&args.length){
    const raw=stringNode(args[0]);if(raw)add(raw,"POST","ast_beacon",node);
   }
  }
  if(ts.isNewExpression(node)&&callName(node.expression)==="URL"&&node.arguments?.length){
   const raw=stringNode(node.arguments[0]);if(raw)add(raw,"GET","ast_url_ctor",node);
  }
  if(ts.isPropertyAssignment(node)){
   const name=ts.isIdentifier(node.name)?node.name.text:ts.isStringLiteral(node.name)?node.name.text:"";
   if(["endpoint","url","path","baseURL","route","api"].includes(name)){
    const raw=stringNode(node.initializer);if(raw)add(raw,"REFERENCE","ast_property",node);
   }
  }
  if(ts.isVariableDeclaration(node)&&ts.isIdentifier(node.name)&&
    /endpoint|apiUrl|routePath/i.test(node.name.text)){
   const raw=stringNode(node.initializer);if(raw)add(raw,"REFERENCE","ast_variable",node);
  }
  if(visited<=170000)ts.forEachChild(node,visit);
 }
 visit(file);
 entries.sort((a,b)=>a.path.localeCompare(b.path)||a.line-b.line||a.method.localeCompare(b.method));
 return {entries,diagnostics:issues.slice(0,12),nodes_visited:visited};
}
const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function segmentVLQ(raw){
 const result=[];
 let acc=0,shift=0;
 for(const char of raw){
  const digit=alphabet.indexOf(char);
  if(digit<0)throw Error("invalid source-map VLQ alphabet");
  acc+=(digit&31)*Math.pow(2,shift);
  if((digit&32)===0){
   const negative=(acc&1)!==0;
   const value=Math.floor(acc/2)*(negative?-1:1);
   if(!Number.isSafeInteger(value))throw Error("invalid source-map integer");
   result.push(value);acc=0;shift=0;
  }else{
   shift+=5;
   if(shift>35)throw Error("invalid source-map VLQ width");
  }
 }
 if(shift!==0)throw Error("truncated source-map VLQ");
 return result;
}
function decodeMappings(map){
 const rows=[];
 let src=0,originalLine=0,originalColumn=0,name=0,count=0;
 const lines=map.mappings.split(";");
 if(lines.length>350000)throw Error("source-map lines exceed limit");
 for(const line of lines){
  let generated=0;
  const row=[];
  for(const segment of line.split(",")){
   if(!segment)continue;
   if(++count>180000)throw Error("source-map segment cap exceeded");
   const values=segmentVLQ(segment);
   if(values.length!==1 && values.length!==4 && values.length!==5)throw Error("bad source-map segment");
   generated+=values[0];
   if(generated<0)throw Error("negative generated source column");
   if(values.length>=4){
    src+=values[1];originalLine+=values[2];originalColumn+=values[3];
    if(values.length===5)name+=values[4];
    if(src<0||src>=map.sources.length||originalLine<0||originalColumn<0)throw Error("map references invalid source");
    row.push({gen:generated,src,line:originalLine+1,col:originalColumn+1});
   }
  }
  rows.push(row);
 }
 return {rows,segments:count};
}
function analyzeSourceMap(raw,entries){
 if(Buffer.byteLength(raw,"utf8")>MAX_MAP)throw Error("source map too large");
 const map=JSON.parse(raw);
 if(!map||map.version!==3||!Array.isArray(map.sources)||
  map.sources.length>1000||typeof map.mappings!=="string"||
  map.mappings.length>MAX_MAP||typeof map.sourceRoot==="string"&&map.sourceRoot.length>1024){
  throw Error("invalid or unbounded ECMA-426 source map");
 }
 if(map.sources.some(x=>typeof x!=="string"||x.length>1024))throw Error("invalid map source name");
 // sourcesContent is untrusted code and is deliberately never returned.
 const {rows,segments}=decodeMappings(map);
 let attributed=0;
 for(const entry of entries){
  const row=rows[entry.line-1]||[];
  let best=null;
  for(const segment of row){
   if(segment.gen<=entry.column-1)best=segment;else break;
  }
  if(!best)continue;
  const source=map.sources[best.src]||"";
  entry.original={source_name:path.basename(source.replaceAll("\\","/")).slice(0,96),
    source_sha256:hex(source),line:best.line,column:best.col};
  attributed++;
 }
 return {status:"verified_map_metadata",map_sha256:hex(raw),
  sources_count:map.sources.length,mappings_segments:segments,attributed};
}
function localMapPath(file,source){
 const match=source.match(/[#@]\s*sourceMappingURL\s*=\s*([^\s]+)/g);
 if(!match?.length)return null;
 const candidate=match.at(-1).split("=").slice(1).join("=");
 if(!candidate.endsWith(".map")||candidate.includes("..")||candidate.includes("%")||
  candidate.includes(":")||candidate.startsWith("/")||candidate.startsWith("\\"))return null;
 const actual=path.resolve(path.dirname(file),candidate);
 if(path.dirname(actual)!==path.dirname(path.resolve(file)))return null;
 return actual;
}
export function inspect(source,origin,mapText=null){
 const url=new URL(origin);
 if(url.protocol!=="https:"||url.username||url.password||url.pathname!=="/"||url.search||url.hash)throw Error("exact HTTPS origin required");
 const result=extractJS(source,url.origin);
 let sm={status:"unavailable_no_local_map"};
 if(mapText!==null){
  try{sm=analyzeSourceMap(mapText,result.entries);}
  catch(e){sm={status:"invalid_map",reason:String(e.message).slice(0,120)};}
 }
 return {version:1,origin:url.origin,source_sha256:hex(source),
   parse_errors:result.diagnostics,ast_nodes_visited:result.nodes_visited,
   endpoints:result.entries,source_map:sm,
   limitation:"Static syntax candidates only; dynamic URL expressions and actual permissions are not inferred. No source contents or credentials are exported."};
}
async function main(){
 const args=process.argv.slice(2);
 const get=(key)=>{const at=args.indexOf(key);return at>=0?args[at+1]:null;};
 const file=get("--file"),origin=get("--origin");
 if(!file||!origin||args.length>6)throw Error("usage: BunnyMind-js-ast --file bundle.js --origin https://approved.example [--map local.map]");
 const stat=fs.lstatSync(file);
 if(!stat.isFile()||stat.size<1||stat.size>MAX_SCRIPT)throw Error("input script must be bounded regular file");
 const source=fs.readFileSync(file,"utf8");
 const mapFile=get("--map")||localMapPath(file,source);
 let map=null;
 if(mapFile&&fs.existsSync(mapFile)){
  const info=fs.lstatSync(mapFile);
  if(!info.isFile()||info.size>MAX_MAP)throw Error("untrusted or oversized local source map");
  map=fs.readFileSync(mapFile,"utf8");
 }
 const report=inspect(source,origin,map);
 process.stdout.write(JSON.stringify(report)+"\n");
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 main().catch(e=>{process.stderr.write(String(e.message).slice(0,180)+"\n");process.exit(1);});
}
