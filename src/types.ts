// Local copies of the EsploraTx data shapes.
//
// We deliberately do NOT import these from ../lib/esplora: that
// module pulls in endpoints.ts → idb.ts (browser IndexedDB), which
// drags the whole browser-only type surface into the Node typecheck.
// These are pure data interfaces, so a local copy is the clean cut —
// the indexer's rpc.ts produces them, scan.ts consumes them, and the
// registry apply functions accept the same field names. Keep these in
// sync with esplora.ts's definitions (they rarely change).

export interface EsploraTxVout {
  scriptpubkey: string;        // hex
  scriptpubkey_type?: string;  // "op_return" | "v0_p2wpkh" | "v1_p2tr" | ...
  value: number;               // sats
}

export interface EsploraTxVin {
  txid: string;
  vout: number;
  prevout?: EsploraTxVout;
  witness?: string[];          // hex stack
  scriptsig?: string;
  sequence?: number;
}

export interface EsploraTx {
  txid: string;
  vin: EsploraTxVin[];
  vout: EsploraTxVout[];
  status: {
    confirmed: boolean;
    block_height?: number;
    block_hash?: string;
    block_time?: number;
  };
}
