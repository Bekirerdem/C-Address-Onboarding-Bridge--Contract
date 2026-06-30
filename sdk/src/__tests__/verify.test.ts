import {
  computeWasmHash,
  fetchDeployedWasmHash,
  verifyDeployedWasm,
  ContractDataReader,
} from '../verify';
import { SorobanRpc, xdr } from '@stellar/stellar-sdk';

const CONTRACT_ID = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

/** Build a fake `getContractData` result whose instance points at `executable`. */
function instanceEntry(
  executable: xdr.ContractExecutable,
): SorobanRpc.Api.LedgerEntryResult {
  const instanceScVal = xdr.ScVal.scvContractInstance(
    new xdr.ScContractInstance({ executable, storage: null }),
  );
  // Only the `val.contractData().val()` navigation is stubbed; everything from
  // the instance ScVal onward is a real XDR object so the accessors are exercised.
  return {
    val: { contractData: () => ({ val: () => instanceScVal }) },
  } as unknown as SorobanRpc.Api.LedgerEntryResult;
}

/** A reader that always returns the given ledger entry. */
function readerReturning(entry: SorobanRpc.Api.LedgerEntryResult): ContractDataReader {
  return { getContractData: async () => entry };
}

/** A WASM-backed instance whose executable carries `hashHex`. */
function wasmReader(hashHex: string): ContractDataReader {
  const executable = xdr.ContractExecutable.contractExecutableWasm(
    Buffer.from(hashHex, 'hex'),
  );
  return readerReturning(instanceEntry(executable));
}

describe('computeWasmHash', () => {
  it('matches known SHA-256 vectors', () => {
    // FIPS 180-4 test vectors.
    expect(computeWasmHash(Buffer.from(''))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(computeWasmHash(Buffer.from('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('produces a 64-char hex digest', () => {
    const hash = computeWasmHash(Buffer.from([0xde, 0xad, 0xbe, 0xef]));
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('fetchDeployedWasmHash', () => {
  it('extracts the hex wasm hash from a WASM-backed instance', async () => {
    const hashHex = '07'.repeat(32);
    const result = await fetchDeployedWasmHash(wasmReader(hashHex), CONTRACT_ID);
    expect(result).toBe(hashHex);
  });

  it('throws for a non-WASM (Stellar Asset) contract', async () => {
    const reader = readerReturning(
      instanceEntry(xdr.ContractExecutable.contractExecutableStellarAsset()),
    );
    await expect(fetchDeployedWasmHash(reader, CONTRACT_ID)).rejects.toThrow(
      /not WASM-backed/,
    );
  });
});

describe('verifyDeployedWasm', () => {
  it('reports a match when local and deployed hashes are equal', async () => {
    const wasm = Buffer.from('abc');
    const reader = wasmReader(computeWasmHash(wasm));
    const result = await verifyDeployedWasm(reader, CONTRACT_ID, wasm);
    expect(result).toEqual({
      match: true,
      localHash: computeWasmHash(wasm),
      deployedHash: computeWasmHash(wasm),
    });
  });

  it('reports a mismatch (without throwing) when hashes differ', async () => {
    const wasm = Buffer.from('the local build');
    const reader = wasmReader('00'.repeat(32));
    const result = await verifyDeployedWasm(reader, CONTRACT_ID, wasm);
    expect(result.match).toBe(false);
    expect(result.localHash).toBe(computeWasmHash(wasm));
    expect(result.deployedHash).toBe('00'.repeat(32));
  });
});
