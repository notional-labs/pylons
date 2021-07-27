// THIS FILE IS GENERATED AUTOMATICALLY. DO NOT MODIFY.
import { SigningStargateClient } from "@cosmjs/stargate";
import { Registry } from "@cosmjs/proto-signing";
import { Api } from "./rest";
import { MsgUpdateRecipe } from "./types/pylons/tx";
import { MsgCreateCookbook } from "./types/pylons/tx";
import { MsgUpdateCookbook } from "./types/pylons/tx";
import { MsgCreateRecipe } from "./types/pylons/tx";
const types = [
    ["/Pylonstech.pylons.pylons.MsgUpdateRecipe", MsgUpdateRecipe],
    ["/Pylonstech.pylons.pylons.MsgCreateCookbook", MsgCreateCookbook],
    ["/Pylonstech.pylons.pylons.MsgUpdateCookbook", MsgUpdateCookbook],
    ["/Pylonstech.pylons.pylons.MsgCreateRecipe", MsgCreateRecipe],
];
export const MissingWalletError = new Error("wallet is required");
const registry = new Registry(types);
const defaultFee = {
    amount: [],
    gas: "200000",
};
const txClient = async (wallet, { addr: addr } = { addr: "http://localhost:26657" }) => {
    if (!wallet)
        throw MissingWalletError;
    const client = await SigningStargateClient.connectWithSigner(addr, wallet, { registry });
    const { address } = (await wallet.getAccounts())[0];
    return {
        signAndBroadcast: (msgs, { fee, memo } = { fee: defaultFee, memo: "" }) => client.signAndBroadcast(address, msgs, fee, memo),
        msgUpdateRecipe: (data) => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgUpdateRecipe", value: data }),
        msgCreateCookbook: (data) => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgCreateCookbook", value: data }),
        msgUpdateCookbook: (data) => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgUpdateCookbook", value: data }),
        msgCreateRecipe: (data) => ({ typeUrl: "/Pylonstech.pylons.pylons.MsgCreateRecipe", value: data }),
    };
};
const queryClient = async ({ addr: addr } = { addr: "http://localhost:1317" }) => {
    return new Api({ baseUrl: addr });
};
export { txClient, queryClient, };