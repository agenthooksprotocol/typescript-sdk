import {createRequire} from 'node:module';
import {schemas} from '../packages/sdk/dist/src/draft/schemas.js';
import {draftCodecs} from '../packages/sdk/dist/src/draft/index.js';
const require = createRequire(new URL('../packages/sdk/package.json', import.meta.url));
const {Ajv2020} = require('ajv/dist/2020.js');
const {fullFormats} = require('ajv-formats/dist/formats.js');
const ajv = new Ajv2020({strict:false,allErrors:true});
ajv.addFormat('uri',fullFormats.uri); ajv.addFormat('date-time',fullFormats['date-time']);
for (const schema of schemas) ajv.addSchema(schema);
export function validateCanonical(name,value,decoder){
 const validator=ajv.getSchema(`https://agenthooksprotocol.org/schemas/draft/${name}.schema.json`);
 if(!validator || !validator(value) || !decoder(value).ok)throw Error(`Invalid canonical ${name}: ${JSON.stringify(validator?.errors)}`);
}
export function validateObserve(value) {
  for (const [name, item, decoder] of [['observe-notification',value,draftCodecs.parseObserveNotification], ...(value.params?.event?.items ?? []).map(item=>['content-item',item,draftCodecs.parseContentItem])]) {
    const validate = ajv.getSchema(`https://agenthooksprotocol.org/schemas/draft/${name}.schema.json`);
    if (!validate(item) || !decoder(item).ok) throw Error(`Invalid canonical ${name}: ${JSON.stringify(validate.errors)}`);
  }
}
export async function http(endpoint,path,value) {
  const response = await fetch(new URL(path,endpoint), {method:value === undefined?'GET':'POST',headers:{'content-type':'application/json'},body:value === undefined?undefined:JSON.stringify(value),signal:AbortSignal.timeout(15000),redirect:'error'});
  const text = await response.text();
  return {status:response.status,value:text?JSON.parse(text):null};
}
export async function control(endpoint,path,value) {
  const result = await http(endpoint,path,value);
  if (result.status >= 300) throw Error(`${path}: HTTP ${result.status}`);
  return result.value;
}
