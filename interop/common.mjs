import {readFile, writeFile, rename} from 'node:fs/promises';
export async function config() { const i = process.argv.indexOf('--config'); if(i < 0 || !process.argv[i+1]) throw Error('Missing --config'); return JSON.parse(await readFile(process.argv[i+1], 'utf8')); }
export async function atomic(path, value) { const temp = `${path}.${process.pid}.tmp`; await writeFile(temp, JSON.stringify(value)); await rename(temp, path); }
export async function scenarios(path) { const value = JSON.parse(await readFile(path, 'utf8')); if(value.version !== 1 || !Array.isArray(value.scenarios)) throw Error('Invalid scenario file'); return value.scenarios; }
export async function body(req) { let data = ''; for await (const chunk of req) { data += chunk; if(data.length > 4_194_304) throw Error('Oversized request'); } return JSON.parse(data); }
export function reply(res, status, value) { res.writeHead(status, {'content-type':'application/json'}); res.end(JSON.stringify(value)); }
export function listen(server, protocol='http') { return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(`${protocol}://127.0.0.1:${server.address().port}`))); }
export const discovery = {protocolVersion:'draft', effects:['deny','allow','ask','modify','message','return','flow','inject'], modify:{input:{replace:true,merge:true}}, transports:['http','stdio'], authentication:['none','bearer','oauth','workload','mtls'], flow:{operations:['stop','continue'],remainingContinuations:2,maxContinuations:2,continuationCount:0},inject:{context:{append:true,deliverAt:['now','next_turn']}},coverage:{events:['tool.before','turn.finish.before'],gaps:['No production harness mapping','Content upload and task changes are local semantic slices']}};

export const manifest = {
 transports:['http','stdio'],authentication:['bearer','oauth','workload','mtls'],toolPaths:['native'],contentCategories:['text','image','audio','video','reasoning','skill','native'],limits:{maxUploadBytes:52428800,maxContinuations:2},managedPolicy:{scopes:['user'],disableable:true},correlationIdentityFields:['id','source','call.id','parentEventId','items.id'],
 events:[{event:'tool.before',modes:['intercept'],capabilities:{...discovery,flow:{operations:['stop']}}},{event:'turn.finish.before',modes:['intercept'],capabilities:{effects:['flow','message'],flow:discovery.flow}}],
 gaps:[{path:'events.other',reason:'Synthetic adapter covers tool.before and turn.finish.before only'},{path:'production',reason:'Content upload, lineage and task changes are local semantic slices, not production host integration'}],
};
