package v4

import (
	"fmt"

	pylonskeeper "github.com/Pylons-tech/pylons/x/pylons/keeper"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

type MsgRestrictUbedrockDecorator struct {
	pk pylonskeeper.Keeper
}

func NewMsgRestrictUbedrockDecorator(pk pylonskeeper.Keeper) MsgRestrictUbedrockDecorator {
	return MsgRestrictUbedrockDecorator{
		pk:              pk,
	}
}

// AnteDecorator for restrict ubedrock denom used by unallowed address
func (ad MsgRestrictUbedrockDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	sigTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid transaction type")
	}

	messages := sigTx.GetMsgs()
	if len(messages) <= 0 {
		return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "invalid messages")
	}

	if msgSend, ok := messages[0].(*banktypes.MsgSend); ok {
		fmt.Printf("[LOG] msgSend: %v\n", msgSend)
		if ok, _ = msgSend.Amount.Find("ubedrock"); ok {
			fmt.Printf("[LOG] msgSend.ToAddress: %s\n", msgSend.ToAddress)
			if _, kycAcc_found := ad.pk.GetPylonsKYC(ctx, msgSend.ToAddress); !kycAcc_found {
				fmt.Printf("[LOG] 'ubedrock' should only be transfer among allowed address\n")
				return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "'ubedrock' should only be transfer among allowed address")
			}
		}
	}
	return next(ctx, tx, simulate)
}
