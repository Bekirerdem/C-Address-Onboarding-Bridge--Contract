/**
 * Deployment verification: prove the WASM running on-chain is byte-for-byte the
 * artifact you built locally.
 *
 * Soroban identifies uploaded contract code by the SHA-256 hash of its WASM
 * bytes, and a deployed contract *instance* stores a reference to that hash in
 * its executable. Verifying a deployment is therefore a hash comparison:
 *
 *   sha256(local .wasm)  ===  deployed instance's executable wasm hash
 *
 * A mismatch means the on-chain contract was built from different source — or a
 * different compiler/toolchain — than the artifact in hand. That is a deploy you
 * must not trust, so the deploy script fails loudly on mismatch.
 */

import { createHash } from 'crypto';
import { SorobanRpc, xdr } from '@stellar/stellar-sdk';

/**
 * The slice of `SorobanRpc.Server` needed to read a contract instance. Declared
 * structurally so the real server, the retry-wrapped provider, and test doubles
 * all satisfy it without casts.
 */
export type ContractDataReader = Pick<SorobanRpc.Server, 'getContractData'>;

/** Result of comparing a local WASM artifact against a deployed contract. */
export interface WasmVerification {
  /** True when the local artifact's hash equals the deployed code's hash. */
  match: boolean;
  /** Hex-encoded SHA-256 of the local `.wasm` file. */
  localHash: string;
  /** Hex-encoded WASM hash the deployed contract instance points at. */
  deployedHash: string;
}

/** Hex-encoded SHA-256 of the given WASM bytes — the hash Soroban indexes code by. */
export function computeWasmHash(wasm: Uint8Array): string {
  return createHash('sha256').update(wasm).digest('hex');
}

/**
 * Read the WASM hash that a deployed contract *instance* points at, by fetching
 * its `LedgerKeyContractInstance` entry and pulling the executable's wasm hash.
 *
 * @throws if the contract is not WASM-backed (e.g. a Stellar Asset Contract),
 *   since there is no WASM artifact to compare against.
 */
export async function fetchDeployedWasmHash(
  reader: ContractDataReader,
  contractId: string,
): Promise<string> {
  const entry = await reader.getContractData(
    contractId,
    xdr.ScVal.scvLedgerKeyContractInstance(),
    SorobanRpc.Durability.Persistent,
  );

  const executable = entry.val.contractData().val().instance().executable();
  if (executable.switch().name !== 'contractExecutableWasm') {
    throw new Error(
      `Contract ${contractId} is not WASM-backed (executable: ${executable.switch().name}); nothing to verify`,
    );
  }

  return executable.wasmHash().toString('hex');
}

/**
 * Compare a local WASM artifact against the code a deployed contract is running.
 *
 * Returns both hashes plus whether they match. A plain hash mismatch is *not*
 * thrown — it is reported in the result so the caller decides how to surface it
 * (the deploy script prints a diff and exits non-zero). Errors are reserved for
 * conditions that make the comparison impossible (RPC failure, non-WASM contract).
 */
export async function verifyDeployedWasm(
  reader: ContractDataReader,
  contractId: string,
  wasm: Uint8Array,
): Promise<WasmVerification> {
  const localHash = computeWasmHash(wasm);
  const deployedHash = await fetchDeployedWasmHash(reader, contractId);
  return { match: localHash === deployedHash, localHash, deployedHash };
}
