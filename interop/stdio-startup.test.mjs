import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {waitForStdioReady} from './stdio-startup.mjs';

async function fixture(run){
 const dir=await mkdtemp('/tmp/ahp-stdio-startup-test-');
 const child=Object.assign(new EventEmitter(),{exitCode:null,signalCode:null});
 const ready=dir+'/ready.json', config=dir+'/config.json';
 try{await writeFile(config,JSON.stringify({readinessFile:ready,watchdog:1}));await run({child,ready,config})}finally{await rm(dir,{recursive:true,force:true})}
}
test('discovery begins only after bounded startup, not during compilation/relay readiness',()=>fixture(async({child,ready,config})=>{
 let discovered=false;
 const starting=waitForStdioReady(child,config).then(()=>{discovered=true});
 await delay(40);assert.equal(discovered,false);
 await writeFile(ready,JSON.stringify({controlEndpoint:'http://127.0.0.1:1'}));
 await starting;assert.equal(discovered,true);assert.equal(child.listenerCount('exit'),0);
}));
test('startup watchdog remains bounded',()=>fixture(async({child,ready,config})=>{
 await writeFile(config,JSON.stringify({readinessFile:ready,watchdog:0.03}));
 await assert.rejects(waitForStdioReady(child,config),/readiness watchdog/);
}));
test('startup process exit fails without sending discovery',()=>fixture(async({child,config})=>{
 const starting=waitForStdioReady(child,config);
 const rejected=assert.rejects(starting,/exited before readiness/);
 await delay(20);child.exitCode=1;child.emit('exit',1);await rejected;
}));
test('malformed readiness is not a successful handshake',()=>fixture(async({child,ready,config})=>{
 await writeFile(ready,'{}');await assert.rejects(waitForStdioReady(child,config),/Invalid readiness/);
}));
