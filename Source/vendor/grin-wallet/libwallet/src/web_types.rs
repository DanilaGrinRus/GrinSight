//! Browser-only subset of grin-wallet API types.
//!
//! The full wallet backend (LMDB, scanner, owner API) is not compiled with the
//! `web` feature. GrinSight only needs the slate/address types and the payment
//! proof shape; these definitions match the fields used by the native wallet.

use crate::grin_core::libtx::secp_ser;
use crate::grin_util::secp::pedersen;
use crate::slate_versions::ser as dalek_ser;
use crate::slate_versions::SlateVersion;
use crate::SlatepackAddress;

use ed25519_dalek::Signature as DalekSignature;

/// V2 Init / Send TX API Args (same wire shape as libwallet).
#[derive(Clone, Debug, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct InitTxArgs {
	/// The human readable account name from which to draw outputs.
	pub src_acct_name: Option<String>,
	/// Amount in nanogrins.
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount: u64,
	/// Does the amount include the fee?
	pub amount_includes_fee: Option<bool>,
	/// Minimum confirmations for an output.
	#[serde(with = "secp_ser::string_or_u64")]
	pub minimum_confirmations: u64,
	/// Soft limit on selected outputs.
	pub max_outputs: u32,
	/// Target number of change outputs.
	pub num_change_outputs: u32,
	/// Use as many outputs as possible.
	pub selection_strategy_is_use_all: bool,
	/// Refresh outputs from the node.
	#[serde(default = "default_refresh_outputs_from_node")]
	pub refresh_outputs_from_node: bool,
	/// Target slate version.
	pub target_slate_version: Option<u16>,
	/// Blocks after which the transaction should be ignored.
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(default)]
	pub ttl_blocks: Option<u64>,
	/// Require a payment proof for this recipient.
	#[serde(default)]
	pub payment_proof_recipient_address: Option<SlatepackAddress>,
	/// Estimate only.
	pub estimate_only: Option<bool>,
	/// Late-locked transaction.
	#[serde(default)]
	pub late_lock: Option<bool>,
	/// Optional send arguments.
	pub send_args: Option<InitTxSendArgs>,
}

fn default_refresh_outputs_from_node() -> bool {
	true
}

/// Send arguments (same wire shape as libwallet).
#[derive(Clone, Debug, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct InitTxSendArgs {
	/// Destination.
	pub dest: String,
	/// Post the transaction after send/finalize.
	pub post_tx: bool,
	/// Use fluff relay.
	pub fluff: bool,
	/// Skip the Tor send attempt.
	pub skip_tor: Option<bool>,
}

/// Packaged payment proof.
#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug, Clone)]
pub struct PaymentProof {
	/// Amount.
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount: u64,
	/// Kernel excess.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub excess: pedersen::Commitment,
	/// Recipient wallet address.
	pub recipient_address: SlatepackAddress,
	/// Recipient signature.
	#[serde(with = "dalek_ser::dalek_sig_serde")]
	pub recipient_sig: DalekSignature,
	/// Sender wallet address.
	pub sender_address: SlatepackAddress,
	/// Sender signature.
	#[serde(with = "dalek_ser::dalek_sig_serde")]
	pub sender_sig: DalekSignature,
}
