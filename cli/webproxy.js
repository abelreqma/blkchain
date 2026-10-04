'use strict';
const http = require('http');
const tls = require('tls');
const readline = require('readline');
const {wsServer} = require('/opt/blkchain-playwright/package/lib/utilsBundle.js');
let next = 0, requests = 0, inputBytes = 0;
const pending = new Map(), sockets = new Map();
let secureContext;
const emit = value => process.stdout.write(JSON.stringify(value) + '\n');
const headers = req => Object.fromEntries(Object.entries(req.headers).map(([k,v]) => [k, Array.isArray(v) ? v : [String(v)]]));
const target = (req, websocket) => {
  const scheme = req.socket.encrypted ? (websocket ? 'wss:' : 'https:') : (websocket ? 'ws:' : 'http:');
  let url = new URL(req.url, scheme + '//' + req.headers.host);
  url.protocol = scheme;
  return url.href;
};
const server = http.createServer({maxHeaderSize:65536}, (req,res) => {
  if (++requests > 500 || pending.size >= 16) { res.writeHead(429); res.end(); return; }
  const id = String(++next), parts = []; let bytes = 0;
  req.on('data', part => { bytes += part.length; inputBytes += part.length; if (bytes > 1048576 || inputBytes > 67108864) req.destroy(); else parts.push(part); });
  req.on('end', () => {
    let url; try { url = target(req, false); } catch { res.writeHead(400);res.end();return; }
    const timer = setTimeout(() => { pending.delete(id);res.destroy(); }, 30000);
    pending.set(id,{res,timer});
    emit({kind:'http',id,url,method:req.method,headers:headers(req),body:Buffer.concat(parts).toString('base64')});
  });
});
server.maxHeadersCount = 100; server.maxConnections = 32;
server.headersTimeout = 10000; server.requestTimeout = 30000;
server.on('clientError', (_, socket) => socket.destroy());
server.on('connect', (req,socket,head) => {
  if (!secureContext || head.length || ++requests > 500) { socket.destroy(); return; }
  socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  const connection = new tls.TLSSocket(socket,{isServer:true,secureContext});
  connection.on('error',()=>connection.destroy());
  connection.setTimeout(30000,()=>connection.destroy());
  server.emit('connection', connection);
});
const wss = new wsServer({noServer:true,maxPayload:262144,perMessageDeflate:false,handleProtocols:(_,req)=>req.selectedProtocol || false});
server.on('upgrade',(req,socket,head)=>{
  if (++requests > 500 || pending.size >= 16 || sockets.size >= 16) {socket.destroy();return;}
  let url;try{url=target(req,true);}catch{socket.destroy();return;}
  const id=String(++next),timer=setTimeout(()=>{pending.delete(id);socket.destroy();},15000);
  pending.set(id,{req,socket,head,timer});
  emit({kind:'open',id,url,headers:headers(req),protocols:(req.headers['sec-websocket-protocol'] || '').split(',').map(x=>x.trim()).filter(Boolean)});
});
const lines=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
lines.on('line',line=>{
  if(line.length>6000000){process.exit(1);return;}
  let value;try{value=JSON.parse(line);}catch{process.exit(1);return;}
  if(value.kind==='config'){
    secureContext=tls.createSecureContext({key:value.key,cert:value.cert});
    server.listen(0,'127.0.0.1',()=>emit({kind:'ready',port:server.address().port}));return;
  }
  const item=pending.get(value.id);
  if(value.kind==='http' && item){
    pending.delete(value.id);clearTimeout(item.timer);
    item.res.writeHead(value.status,value.headers || {});item.res.end(Buffer.from(value.body || '', 'base64'));return;
  }
  if(value.kind==='opened' && item){
    pending.delete(value.id);clearTimeout(item.timer);
    if(value.status!==101){item.socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');return;}
    item.req.selectedProtocol=value.protocol;
    wss.handleUpgrade(item.req,item.socket,item.head,ws=>{
      sockets.set(value.id,ws);let count=0;
      ws.on('message',(data,binary)=>{
        inputBytes+=data.length;
        if(++count>250 || inputBytes>67108864){ws.close(1009);emit({kind:'limit',id:value.id});return;}
        if(!emit({kind:'send',id:value.id,opcode:binary?2:1,body:data.toString('base64')})){
          ws.pause();process.stdout.once('drain',()=>{if(ws.readyState===1)ws.resume();});
        }
      });
      ws.on('error',()=>{emit({kind:'limit',id:value.id});ws.terminate();});
      ws.on('close',(code,reason)=>{sockets.delete(value.id);emit({kind:'close',id:value.id,code,body:reason.toString('base64')});});
    });return;
  }
  const ws=sockets.get(value.id);
  if(ws && value.kind==='message' && ws.readyState===1){ws.send(Buffer.from(value.body || '', 'base64'),{binary:value.opcode===2});}
  if(ws && value.kind==='closed'){ws.close(value.code || 1000);}
});
lines.on('close',()=>process.exit(0));
