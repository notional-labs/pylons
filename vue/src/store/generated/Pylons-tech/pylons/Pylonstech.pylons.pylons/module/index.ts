// THIS FILE IS GENERATED AUTOMATICALLY. DO NOT MODIFY.

import { StdFee } from "@cosmjs/launchpad";
import { SigningStargateClient } from "@cosmjs/stargate";
import { Registry, OfflineSigner, EncodeObject, DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { Api } from "./rest";
import { MsgGoogleIAPGetPylons } from "./types/pylons/tx";
import { MsgSendItems } from "./types/pylons/tx";
import { MsgTransferCookbook } from "./types/pylons/tx";
import { MsgCreateCookbook } from "./types/pylons/tx";
import { MsgExecuteRecipe } from "./types/pylons/tx";
import { MsgCreateRecipe } from "./types/pylons/tx";
import { MsgUpdateCookbook } from "./types/pylons/tx";
import { MsgSetItemString } from "./types/pylons/tx";
import { MsgCreateAccount } from "./types/pylons/tx";
import { MsgUpdateRecipe } from "./types/pylons/tx";


const types = [
  ["/Pylonstech.pylons.pylons.MsgGoogleIAPGetPylons", MsgGoogleIAPGetPylons],
  ["/Pylonstech.pylons.pylons.MsgSendItems", MsgSendItems],
  ["/Pylonstech.pylons.pylons.MsgTransferCookbook", MsgTransferCookbook],
  ["/Pylonstech.pylons.pylons.MsgCreateCookbook", MsgCreateCookbook],
  ["/Pylonstech.pylons.pylons.MsgExecuteRecipe", MsgExecuteRecipe],
  ["/Pylonstech.pylons.pylons.MsgCreateRecipe", MsgCreateRecipe],
  ["/Pylonstech.pylons.pylons.MsgUpdateCookbook", MsgUpdateCookbook],
  ["/Pylonstech.pylons.pylons.MsgSetItemString", MsgSetItemString],
  ["/Pylonstech.pylons.pylons.MsgCreateAccount", MsgCreateAccount],
  ["/Pylonstech.pylons.pylons.MsgUpdateRecipe", MsgUpdateRecipe],
  
];
export const MissingWalletError = new Error("wallet is required");

const registry = new Registry(<any>types);

const defaultFee = {
  amount: [],
  gas: "200000",
};

interface TxClientOptions {
  addr: string
}

interface SignAndBroadcastOptions {
  fee: StdFee,
  memo?: string
}

const txClient = async (wallet: OfflineSigner, { addr: addr }: TxClientOptions = { addr: "http://localhost:26657" }) => {
  if (!wallet) throw MissingWalletError;

  const client = await SigningStargateClient.connectWithSigner(addr, wallet, { registry });
  const { address } = (await wallet.getAccounts())[0];

  return {
    signAndBroadcast: (msgs: EncodeObject[], { fee, memo }: SignAndBroadcastOptions = {fee: defaultFee, memo: ""}) => client.signAndBroadcast(address, msgs, fee,memo),
    msgGoogleIAPGetPylons: (data: MsgGoogleIAPGetPylons): EncodeObject => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgGoogleIAPGetPylons", value: data }),
    msgSendItems: (data: MsgSendItems): EncodeObject => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgSendItems", value: data }),
    msgTransferCookbook: (data: MsgTransferCookbook): EncodeObject => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgTransferCookbook", value: data }),
    msgCreateCookbook: (data: MsgCreateCookbook): EncodeObject => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgCreateCookbook", value: data }),
    msgExecuteRecipe: (data: MsgExecuteRecipe): EncodeObject => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgExecuteRecipe", value: data }),
    msgCreateRecipe: (data: MsgCreateRecipe): EncodeObject => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgCreateRecipe", value: data }),
    msgUpdateCookbook: (data: MsgUpdateCookbook): EncodeObject => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgUpdateCookbook", value: data }),
    msgSetItemString: (data: MsgSetItemString): EncodeObject => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgSetItemString", value: data }),
    msgCreateAccount: (data: MsgCreateAccount): EncodeObject => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgCreateAccount", value: data }),
    msgUpdateRecipe: (data: MsgUpdateRecipe): EncodeObject => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgUpdateRecipe", value: data }),
    
  };
};

interface QueryClientOptions {
  addr: string
}

const queryClient = async ({ addr: addr }: QueryClientOptions = { addr: "http://localhost:1317" }) => {
  return new Api({ baseUrl: addr });
};

export {
  txClient,
  queryClient,
};