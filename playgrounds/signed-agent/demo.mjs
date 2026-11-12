import { runProof } from './proof.mjs';
const proof = await runProof();
console.log('WebDecoy signed-agent verification: controlled local fixture');
console.log(proof.fixture);
console.table(proof.results);
console.log(`Fixture directory reads: ${proof.directoryReads}. No API key supplied.`);
console.log('A verified signature establishes a trusted key, not permission to use your app.');
