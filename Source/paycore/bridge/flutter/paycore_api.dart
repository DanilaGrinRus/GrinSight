// Dart client of the payment core bridge (fly-paycore-bridge, API version 1).
//
// NOT COMPILED OR RUN YET: written against the bridge's method list
// (../README.md) without a Dart SDK at hand. Run `dart analyze` and the
// smoke test below before relying on it.
//
// Transport-independent: give it a function that sends one JSON-RPC request
// object and returns the decoded response object. With the existing
// grinsight-service that is one POST to /rpc; the service routes every
// method starting with "paycore." to Bridge::call.
//
// Amounts are nanogrin as BigInt (1 GRIN = 10^9): results arrive as decimal
// strings, so they are exact on the web too.
//
// Nothing here ever carries a seed, a key or a password. Unlocking the
// wallet stays where it is today.

import 'dart:async';

/// Sends one JSON-RPC 2.0 request object, returns the response object.
typedef PaycoreTransport = Future<Map<String, dynamic>> Function(Map<String, dynamic> request);

/// A refusal or failure reported by the core.
class PaycoreException implements Exception {
  PaycoreException(this.code, this.kind, this.reason);
  final int code;

  /// Stable machine-readable kind: bad_slate, refused, not_found, conflict,
  /// unknown_outcome, insufficient_funds, storage, storage_open, corrupt,
  /// rng, build, codec, invalid_params, method_not_found, invalid_request,
  /// parse_error.
  final String kind;

  /// English reason from the core; for logs, not for the screen. Map [kind]
  /// (and for `refused` the reason) to localized text in the UI.
  final String reason;

  /// "Signature may exist, nothing will be signed again": show it as its own
  /// state, never as an ordinary error with a retry button.
  bool get isUnknownOutcome => kind == 'unknown_outcome';

  @override
  String toString() => reason.isEmpty ? 'paycore: $kind' : 'paycore: $kind ($reason)';
}

class PaycoreBalance {
  PaycoreBalance(this.spendable, this.reserved, this.immature);
  final BigInt spendable;
  final BigInt reserved;
  final BigInt immature;
}

class PaycorePrepared {
  PaycorePrepared(this.op, this.slate);

  /// Operation id (hex). Keep it: finalize, cancel, status and broadcast need it.
  final String op;

  /// Text to hand to the recipient (S1) or to the payee (I2).
  final String slate;
}

class PaycorePaymentProof {
  PaycorePaymentProof(this.amount, this.excess, this.senderAddress, this.receiverAddress, this.signature);
  final BigInt amount;
  final String excess;
  final String senderAddress;
  final String receiverAddress;
  final String signature;
}

class PaycoreFinalized {
  PaycoreFinalized(this.txHex, this.slate, this.excess, this.paymentProof);
  final String txHex;
  final String slate;
  final String excess;
  final PaycorePaymentProof? paymentProof;
}

class PaycoreSendStatus {
  PaycoreSendStatus(this.state, this.reserve, this.conflict, this.accepted, this.rejected, this.unknown,
      {this.delivery, this.replyHeld = false});

  /// prepared | cancelled | unknown | finalized | confirmed | contested | dead
  final String state;
  final bool reserve;
  final bool conflict;
  final int accepted;
  final int rejected;
  final int unknown;

  /// Delivery of S1 through the message transport, or null when the slate
  /// travels by hand: queued | waiting_relay | relay_accepted | expired |
  /// queue_busy | queue_full. It says nothing about the payment itself:
  /// "relay_accepted" is not "received" and not "paid".
  final String? delivery;

  /// The recipient's reply has arrived and waits for the user's decision.
  final bool replyHeld;
}

class PaycoreIncomingStatus {
  PaycoreIncomingStatus(this.status, this.rule, this.spent);

  /// confirmed | preliminary | not_confirmed
  final String status;

  /// Row of the Level 5 table: S1, S2, S3, S4, S6, S7, S7a, S8.
  final String? rule;
  final bool spent;
}

class PaycoreApi {
  PaycoreApi(this._send);
  final PaycoreTransport _send;
  int _id = 0;

  Future<Map<String, dynamic>> _call(String method, [Map<String, dynamic>? params]) async {
    final Map<String, dynamic> response = await _send(<String, dynamic>{
      'jsonrpc': '2.0',
      'id': ++_id,
      'method': method,
      if (params != null) 'params': params,
    });
    final dynamic error = response['error'];
    if (error is Map) {
      final dynamic data = error['data'];
      throw PaycoreException(
        (error['code'] as num?)?.toInt() ?? 0,
        data is Map ? (data['kind'] ?? 'unknown').toString() : (error['message'] ?? 'unknown').toString(),
        data is Map ? (data['reason'] ?? '').toString() : '',
      );
    }
    final dynamic result = response['result'];
    return result is Map ? Map<String, dynamic>.from(result) : <String, dynamic>{};
  }

  static BigInt _amount(dynamic v) => BigInt.parse(v.toString());

  PaycoreFinalized _finalized(Map<String, dynamic> r) {
    final dynamic p = r['payment_proof'];
    return PaycoreFinalized(
      r['tx'] as String,
      r['slate'] as String,
      r['excess'] as String,
      p is Map
          ? PaycorePaymentProof(_amount(p['amount']), p['excess'] as String, p['sender_address'] as String,
              p['receiver_address'] as String, p['signature'] as String)
          : null,
    );
  }

  Future<Map<String, dynamic>> info() => _call('paycore.info');

  Future<PaycoreBalance> balance() async {
    final r = await _call('paycore.balance');
    return PaycoreBalance(_amount(r['spendable']), _amount(r['reserved']), _amount(r['immature']));
  }

  /// ed25519 key of the receive address (hex), for payment proofs.
  Future<String> address() async => (await _call('paycore.address'))['address'] as String;

  Future<Map<String, dynamic>> history() => _call('paycore.history');

  // ----- sending

  /// [proofTo]: recipient address key (hex) to request a payment proof.
  /// [late]: late lock, nothing is reserved until finalize.
  /// [replaces]: a contested operation this payment repeats.
  /// [notARepeat]: the user confirmed this is not a repeat of a contested payment.
  /// [deliverTo]: contact key (hex) the slate is sent to through the message
  /// transport; follow with [deliveryPump]. Not with [replaces]/[notARepeat].
  Future<PaycorePrepared> sendPrepare(
    BigInt amount, {
    int ttlCutoffHeight = 0,
    String? proofTo,
    bool late = false,
    String? replaces,
    bool notARepeat = false,
    String? deliverTo,
  }) async {
    final r = await _call('paycore.send.prepare', <String, dynamic>{
      'amount': amount.toString(),
      if (ttlCutoffHeight != 0) 'ttl_cutoff_height': ttlCutoffHeight,
      if (proofTo != null) 'proof_to': proofTo,
      if (late) 'late': true,
      if (replaces != null) 'replaces': replaces,
      if (notARepeat) 'not_a_repeat': true,
      if (deliverTo != null) 'deliver_to': deliverTo,
    });
    return PaycorePrepared(r['op'] as String, r['slate'] as String);
  }

  /// The one signature. The same reply again returns the stored result;
  /// a different reply throws `conflict`; `unknown_outcome` means the app
  /// stopped between choosing the reply and storing the result.
  Future<PaycoreFinalized> sendFinalize(String op, String replySlate) async =>
      _finalized(await _call('paycore.send.finalize', <String, dynamic>{'op': op, 'slate': replySlate}));

  Future<void> sendCancel(String op) => _call('paycore.send.cancel', <String, dynamic>{'op': op});

  Future<PaycoreSendStatus> sendStatus(String op) async {
    final r = await _call('paycore.send.status', <String, dynamic>{'op': op});
    final Map<String, dynamic> b = Map<String, dynamic>.from(r['broadcasts'] as Map);
    return PaycoreSendStatus(r['state'] as String, r['reserve'] as bool, r['conflict'] as bool,
        (b['accepted'] as num).toInt(), (b['rejected'] as num).toInt(), (b['unknown'] as num).toInt(),
        delivery: r['delivery'] as String?, replyHeld: (r['reply_held'] as bool?) ?? false);
  }

  /// Sign with the reply that arrived by itself: call after the user has
  /// confirmed the payment on screen.
  Future<PaycoreFinalized> sendFinalizeHeld(String op) async =>
      _finalized(await _call('paycore.send.finalize_held', <String, dynamic>{'op': op}));

  // ----- delivery through the message transport

  /// Publish envelopes that still wait for a relay. Call after [sendPrepare]
  /// with deliverTo and then from time to time. Returns {op, delivery} items.
  Future<List<Map<String, dynamic>>> deliveryPump() async =>
      _maps((await _call('paycore.delivery.pump'))['published']);

  /// Take incoming messages. Event kinds: reply_held (ask the user, then
  /// [sendFinalizeHeld]), reply_signed, payment_answered, reply_pending,
  /// needs_approval (show to the user, then [receiveDraft] + [deliveryReply],
  /// or [deliveryAck] to decline), dropped, deferred, unknown_outcome.
  Future<List<Map<String, dynamic>>> deliveryReceive() async =>
      _maps((await _call('paycore.delivery.receive'))['events']);

  /// Send the approved reply back the way the payment came. False means the
  /// relay did not confirm; call again later with the same arguments.
  Future<bool> deliveryReply(String id, String replySlate) async =>
      (await _call('paycore.delivery.reply', <String, dynamic>{'id': id, 'slate': replySlate}))['sent'] as bool;

  /// Forget an incoming message the user declined.
  Future<void> deliveryAck(String id) => _call('paycore.delivery.ack', <String, dynamic>{'id': id});

  // ----- transport identity, contacts, transport

  /// The transport identity: {public, npub, imported, previous} or
  /// {public: null} when the wallet has none yet. It is a key of its own,
  /// not derived from the seed: restoring from the seed does not bring it
  /// back, its backup is [identityExport].
  Future<Map<String, dynamic>> identityGet() => _call('paycore.identity.get');

  /// Make a new random identity. With [replace] an existing one is retired.
  /// Refused while a delivered payment still waits for its reply.
  Future<Map<String, dynamic>> identityCreate({bool replace = false}) =>
      _call('paycore.identity.create', <String, dynamic>{if (replace) 'replace': true});

  /// Take an identity from its backup form (nsec1…).
  Future<Map<String, dynamic>> identityImport(String nsec, {bool replace = false}) =>
      _call('paycore.identity.import', <String, dynamic>{'nsec': nsec, if (replace) 'replace': true});

  /// The backup of the identity (nsec1…). SECRET: whoever reads it can read
  /// and send messages as this wallet (it moves no money). Show it only on
  /// the user's explicit request; never log or store it.
  Future<String> identityExport() async => (await _call('paycore.identity.export'))['nsec'] as String;

  /// Contacts by name: {key, npub, name, address}.
  Future<List<Map<String, dynamic>>> contactsList() async =>
      _maps((await _call('paycore.contacts.list'))['contacts']);

  /// Add a contact or change its name; give [npub] or [key] (hex).
  Future<void> contactsSet({String? npub, String? key, required String name, String? address}) =>
      _call('paycore.contacts.set', <String, dynamic>{
        if (npub != null) 'npub': npub,
        if (key != null) 'key': key,
        'name': name,
        if (address != null) 'address': address,
      });

  /// Remove a contact. Refused while a payment to it waits for its reply.
  Future<void> contactsRemove(String key) => _call('paycore.contacts.remove', <String, dynamic>{'key': key});

  /// {identity, running, error}: whether the message transport is up.
  Future<Map<String, dynamic>> transportStatus() => _call('paycore.transport.status');

  /// Stop the transport and start it again; returns {running, error}.
  Future<Map<String, dynamic>> transportRestart() => _call('paycore.transport.restart');

  static List<Map<String, dynamic>> _maps(dynamic list) =>
      (list as List).map((dynamic e) => Map<String, dynamic>.from(e as Map)).toList();

  Future<PaycoreFinalized> sendResult(String op) async =>
      _finalized(await _call('paycore.send.result', <String, dynamic>{'op': op}));

  /// accepted | rejected | unknown. Safe to repeat: the same bytes are sent.
  Future<String> sendBroadcast(String op) async =>
      (await _call('paycore.send.broadcast', <String, dynamic>{'op': op}))['outcome'] as String;

  // ----- receiving

  /// The user approved this incoming payment. Returns S2 for the sender.
  Future<String> receiveDraft(String slate) async =>
      (await _call('paycore.receive.draft', <String, dynamic>{'slate': slate}))['slate'] as String;

  /// Unattended receive: nothing is stored; the status never rises above
  /// "preliminary" until the output is found by scan.
  Future<String> receiveAuto(String slate, {BigInt? minAmount}) async =>
      (await _call('paycore.receive.auto', <String, dynamic>{
        'slate': slate,
        if (minAmount != null) 'min_amount': minAmount.toString(),
      }))['slate'] as String;

  Future<void> setAutoReceive(bool on) => _call('paycore.receive.set_auto', <String, dynamic>{'on': on});

  Future<PaycoreIncomingStatus> receiveStatus(String slateId) async {
    final r = await _call('paycore.receive.status', <String, dynamic>{'slate_id': slateId});
    return PaycoreIncomingStatus(r['status'] as String, r['status_rule'] as String?, r['spent'] as bool);
  }

  Future<void> receiveAbandon(String slateId) =>
      _call('paycore.receive.abandon', <String, dynamic>{'slate_id': slateId});

  Future<int> receiveExpire() async => ((await _call('paycore.receive.expire'))['closed'] as num).toInt();

  // ----- invoices

  /// Returns (slate id, I1 text for the payer).
  Future<(String, String)> invoiceIssue(BigInt amount) async {
    final r = await _call('paycore.invoice.issue', <String, dynamic>{'amount': amount.toString()});
    return (r['slate_id'] as String, r['slate'] as String);
  }

  Future<PaycoreFinalized> invoiceFinalize(String slateId, String paidSlate) async =>
      _finalized(await _call('paycore.invoice.finalize', <String, dynamic>{'slate_id': slateId, 'slate': paidSlate}));

  /// [maxAmount] is the amount the user saw and agreed to. Paying signs at
  /// once; the same invoice again returns the same reply, never a second payment.
  Future<PaycorePrepared> invoicePay(String invoiceSlate, BigInt maxAmount) async {
    final r = await _call('paycore.invoice.pay',
        <String, dynamic>{'slate': invoiceSlate, 'max_amount': maxAmount.toString()});
    return PaycorePrepared(r['op'] as String, r['slate'] as String);
  }
}

// Wiring with the existing service client (lib/backend/grinsight_service.dart),
// which today hides the JSON-RPC envelope: add a method there that posts a
// ready request object to /rpc and returns the decoded response object
// without turning errors into GrinSightError, e.g.
//
//   Future<Map<String, dynamic>> raw(Map<String, dynamic> request) async { ... }
//
// then:  final paycore = PaycoreApi(service.raw);
//
// Smoke test once the service routes "paycore.":
//   final info = await paycore.info();          // api_version == 1
//   final bal  = await paycore.balance();       // BigInt values
