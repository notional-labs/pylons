package app

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

type AnteSpamMigitationDecorator struct {
	pk PylonsKeeper
}

type AnteRestrictUbedrockDecorator struct {
	pk PylonsKeeper
}

func NewSpamMigitationAnteDecorator(pylonsmodulekeeper PylonsKeeper) AnteSpamMigitationDecorator {
	return AnteSpamMigitationDecorator{
		pk: pylonsmodulekeeper,
	}
}

func NewRestrictUbedrockAnteDecorator(pylonsmodulekeeper PylonsKeeper) AnteRestrictUbedrockDecorator {
	return AnteRestrictUbedrockDecorator{
		pk: pylonsmodulekeeper,
	}
}

// AnteDecorator
func (ad AnteSpamMigitationDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	if (ctx.IsCheckTx() || ctx.IsReCheckTx()) && !simulate {
		sigTx, ok := tx.(authsigning.SigVerifiableTx)
		if !ok {
			return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid transaction type")
		}

		// get max txs in a block, default is 20
		params := ad.pk.GetParams(ctx)
		maxTxs := params.MaxTxsInBlock

		// increment sequence of all signers
		for _, addr := range sigTx.GetSigners() {
			AccountTrack[addr.String()]++
			if AccountTrack[addr.String()] > maxTxs {
				panic(fmt.Sprintf("maximum txs in block is %d ", maxTxs))
			}
		}
	}

	return next(ctx, tx, simulate)
}

// AnteDecorator for restrict ubedrock denom used by unallowed address
func (ad AnteRestrictUbedrockDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	if (ctx.IsCheckTx() || ctx.IsReCheckTx()) && !simulate {
		sigTx, ok := tx.(authsigning.SigVerifiableTx)
		if !ok {
			return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid transaction type")
		}

		messages := sigTx.GetMsgs()
		if len(messages) <= 0 {
			return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "invalid messages")
		}

		if msgSend, ok := messages[0].(*banktypes.MsgSend); ok {
			if ok, _ = msgSend.Amount.Find("ubedrock"); ok {
				if _, kycAcc_found := ad.pk.GetPylonsKYC(ctx, msgSend.ToAddress); kycAcc_found == false {
					panic("'ubedrock' should only be transfer among allowed address")
				}
			}
		}
	}
	return next(ctx, tx, simulate)
}
