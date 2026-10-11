import { Hooks, Type, contract, form, type Codec } from 'agenthooksprotocol/client';
// @ts-expect-error Admission implementation helpers are not public client exports.
import { admitContracts } from 'agenthooksprotocol/client';
// @ts-expect-error Encoding implementation helpers are not public client exports.
import { encodeContract } from 'agenthooksprotocol/client';
// @ts-expect-error Snapshot implementation helpers are not public client exports.
import { freezeContractValue } from 'agenthooksprotocol/client';
// @ts-expect-error Lossless round-trip implementation is hidden; use contract.decode.
import { decodeContract } from 'agenthooksprotocol/client';
void [admitContracts, encodeContract, freezeContractValue, decodeContract];

const argumentsContract = contract(Type.Object({ count: Type.Integer(), nullable: Type.Union([Type.String(), Type.Null()]) }));
const resultContract = contract(Type.Object({ answer: Type.String() }));
const provenanceContract = contract(Type.Object({ supplier: Type.String() }));
declare const hooks: Hooks;
void hooks.toolBefore({ callId: 'call', name: 'read', path: 'native', origin: 'native', input: { count: 1, nullable: null } }, {
  contracts: { arguments: argumentsContract, result: resultContract, provenance: provenanceContract },
}).then(settled => {
  const count: number = settled.input.count;
  const eventCount: number = settled.event.tool.input.count;
  const nullable: string | null = settled.input.nullable;
  if (settled.state.candidate !== null) {
    const answer: string = settled.state.candidate.value.answer;
    const supplier: string | undefined = settled.state.candidate.provenance?.supplier;
    // @ts-expect-error Return values use Result, not Arguments.
    settled.state.candidate.value.count;
    // @ts-expect-error Candidate properties remain readonly.
    settled.state.candidate.value = { answer: 'changed' };
    void [answer, supplier];
  }
  void [count, eventCount, nullable];
});

const answer = form(Type.Object({ approved: Type.Boolean(), reason: Type.Optional(Type.String()) }));
const typed = answer.decode({ action: 'accept', content: { approved: true } });
if (typed.action === 'accept' && typed.content !== undefined) {
  const approved: boolean = typed.content.approved;
  const reason: string | undefined = typed.content.reason;
  // @ts-expect-error The form declaration is the answer type source.
  const wrong: string = typed.content.approved;
  void [approved, reason, wrong];
}

const date: Codec<Date> = { decode(value) { if (typeof value !== 'string') throw Error('date'); return new Date(value); }, encode(value) { return value.toISOString(); } };
void hooks.toolBefore({ callId: 'call', name: 'date', path: 'native', origin: 'native', input: new Date() }, { contracts: { arguments: date, result: resultContract } }).then(result => {
  const accepted: Date = result.input;
  void accepted;
});
