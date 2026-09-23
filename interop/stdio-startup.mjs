import {readFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';

/** Server startup (including a compiler/relay) is not a protocol response wait.
 * Honor the controller's bounded startup watchdog before sending discovery.
 * No ready frame is injected into the canonical stdio stream. */
export async function waitForStdioReady(child, serverConfig) {
 const config=JSON.parse(await readFile(serverConfig,'utf8'));
 if(!config.readinessFile)return; // A bare peer can omit the test readiness binding.
 const seconds=config.watchdog ?? 120;
 if(!Number.isFinite(seconds)||seconds<=0)throw Error('Invalid startup watchdog');
 const deadline=Date.now()+seconds*1000;
 let failure;
 const failed=()=>{failure=Error('Server exited before readiness')};
 child.once('error',failed);child.once('exit',failed);
 try {
  for(;;){
   if(failure || child.exitCode!==null || child.signalCode!==null)throw failure ?? Error('Server exited before readiness');
   if(Date.now()>=deadline)throw Error('Server readiness watchdog');
   try {
    const ready=JSON.parse(await readFile(config.readinessFile,'utf8'));
    if(typeof ready.controlEndpoint!=='string'||!ready.controlEndpoint)throw Error('Invalid readiness');
    return;
   }catch(error){if(error.code!=='ENOENT')throw error}
   await delay(20);
  }
 } finally {child.removeListener('error',failed);child.removeListener('exit',failed)}
}
