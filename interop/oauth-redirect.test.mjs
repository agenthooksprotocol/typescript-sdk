import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {listen} from './common.mjs';
import {accessToken} from './security.mjs';
test('OAuth refuses redirects without forwarding client credentials to another origin',async()=>{
 let leakedRequests=0,issuerRequests=0,status=307;
 const target=createServer((req,res)=>{leakedRequests++;req.resume();res.end(JSON.stringify({access_token:'unexpected'}));});
 const targetEndpoint=await listen(target);
 const issuer=createServer(async(req,res)=>{
  issuerRequests++;let data='';for await(const chunk of req)data+=chunk;
  assert.equal(new URLSearchParams(data).get('client_secret'),'TEST-ONLY-redirect-secret');
  res.writeHead(status,{location:targetEndpoint+'/stolen'});res.end();
 });
 const endpoint=await listen(issuer);
 try {
  for(status of [301,302,303,307,308]) await assert.rejects(()=>accessToken({mode:'oauth',tokenEndpoint:endpoint+'/token',clientId:'test',clientSecret:'TEST-ONLY-redirect-secret'}));
  assert.equal(issuerRequests,5);assert.equal(leakedRequests,0);
 } finally {issuer.closeAllConnections();target.closeAllConnections();await Promise.all([new Promise(r=>issuer.close(r)),new Promise(r=>target.close(r))]);}
});
