import '../core.dart';
import '../catalogue_api.dart';
import '../wallet_model.dart';
import 'grinsight_service.dart';

/// Настоящее ядро: JSON-RPC к `grinsight-service`.
class RealWalletCore implements WalletCore, CatalogueApi, WalletInitializationWarnings, CatalogueIdentityApi, BoundWalletUnlock, SlatepackHistoryApi, TorControlApi {
  RealWalletCore(this._service);

  final GrinSightService _service;
  String? _walletInitializationWarning;
  @override
  Future<bool> isActiveProfile(String login, String network) async {
    final profile = await _service.mutationIdentity();
    return profile['name'] == login && profile['network'] == network;
  }

  @override
  Future<String> credentialDigest({required String login, required String network, required String password}) async {
    final result = await _service.verifyPasswordBound(login, network, password);
    final digest = result['vault_digest'];
    if (digest is! String) throw StateError('Wallet identity unavailable');
    return digest;
  }

  @override
  String? takeWalletInitializationWarning() {
    final warning = _walletInitializationWarning;
    _walletInitializationWarning = null;
    return warning;
  }

  void _captureInitializationWarning(Map<String, dynamic> result) {
    final value = result['messenger_setup_warning'];
    _walletInitializationWarning = value is String ? value : null;
  }

  @override
  Future<Map<String, dynamic>> catalogueIdentity() async => Map<String, dynamic>.from(await _service.call('chat.catalog_identity') as Map);

  @override
  Future<Map<String, dynamic>> catalogueOwnCode() async => Map<String, dynamic>.from(await _service.call('chat.catalog_own_code') as Map);

  @override
  Future<Map<String, dynamic>> catalogueSearch(String name) async => Map<String, dynamic>.from(await _service.call('chat.catalog_search', {'name': name}) as Map);
  @override
  Future<void> catalogueAdd(Map<String, dynamic> profile, String name, {required bool identityChecked}) async { await _service.call('chat.catalog_add', {'profile':profile,'name':name,'identity_checked':identityChecked}); }
  @override
  Future<Map<String, dynamic>> cataloguePublish(String name, {required bool revoked, required bool consentPublic}) async => Map<String, dynamic>.from(await _service.call('chat.catalog_publish', {'name':name,'revoked':revoked,'consent_public':consentPublic}) as Map);


  @override
  Future<Map<String, dynamic>> chatInfo() => _service.chatInfo();
  @override
  Future<Map<String, dynamic>> chatStatus() => _service.chatStatus();
  @override
  Future<Map<String, dynamic>> chatQuarantineInvalidExport(String token) => _service.chatQuarantineInvalidExport(token);
  @override
  Future<void> chatQuarantineInvalidDiscard(String token) => _service.chatQuarantineInvalidDiscard(token);
  @override
  Future<Map<String, dynamic>> chatQuarantineList() => _service.chatQuarantineList();
  @override
  Future<Map<String, dynamic>> chatQuarantineExport(String id, String digest) => _service.chatQuarantineExport(id, digest);
  @override
  Future<void> chatQuarantineDiscard(String id, String digest, bool corrupt) => _service.chatQuarantineDiscard(id, digest, corrupt);
  @override
  Future<void> chatQuarantineCleanup() => _service.chatQuarantineCleanup();
  @override
  Future<Map<String, dynamic>> chatDeferredList() => _service.chatDeferredList();
  @override
  Future<void> chatDeferredRetry(String route) => _service.chatDeferredRetry(route);
  @override
  Future<void> chatDeferredDiscard(String id, String route) => _service.chatDeferredDiscard(id, route);
  @override
  Future<Map<String, dynamic>> chatNostrBinding() async => Map<String, dynamic>.from(await _service.call('chat.nostr_binding') as Map);
  @override
  Future<Map<String, dynamic>> chatI2pBinding() async => Map<String, dynamic>.from(await _service.call('chat.i2p_binding') as Map);
  @override
  Future<void> chatI2pAdd(Map<String, dynamic> binding, String name) async { await _service.call('chat.i2p_add', {'binding': binding, 'name': name}); }
  @override
  Future<void> chatNostrAdd(Map<String, dynamic> binding, String name) async { await _service.call('chat.nostr_add', {'binding': binding, 'name': name}); }
  @override
  Future<Map<String, dynamic>> nostrSettings() async {
    final s = await _service.settings();
    return {'mode': s['messenger_nostr_mode'] ?? 'off', 'url': s['messenger_nostr_url'] ?? '', 'proxy': s['messenger_nostr_proxy'] ?? '', 'expiry': s['messenger_nostr_expiry'] == true, 'historyDays': s['messenger_history_days'] ?? 0, 'catalogueAutoPublish': s['catalogue_auto_publish'] is bool ? s['catalogue_auto_publish'] : null};
  }
  @override
  Future<void> setNostrSettings({required String mode, required String url, required String proxy, required bool consent, required bool expiry, required int historyDays, bool? catalogueAutoPublish}) async {
    final values = <String, dynamic>{'messenger_nostr_mode': mode, 'messenger_nostr_url': url, 'messenger_nostr_proxy': proxy, 'messenger_nostr_consent': consent, 'messenger_nostr_expiry': expiry, 'messenger_history_days': historyDays};
    if (catalogueAutoPublish != null) values['catalogue_auto_publish'] = catalogueAutoPublish;
    await _service.call('wallet.set_settings', values);
  }
  @override
  Future<Map<String, dynamic>> chatMessages([int after = 0]) => _service.chatMessages(after);
  @override
  Future<Map<String, dynamic>> chatSend(String to, String text) => _service.chatSend(to, text);

  @override
  Future<void> close() => _service.stop();

  @override
  Future<List<WalletProfile>> profiles() async {
    final Map<String, dynamic> info = await _service.info();
    final List<dynamic> raw = (info['profiles'] as List<dynamic>?) ?? <dynamic>[];
    return raw
        .map((dynamic e) => e as Map<String, dynamic>)
        .map((Map<String, dynamic> p) => WalletProfile(
              name: (p['name'] ?? '') as String,
              network: (p['network'] ?? 'mainnet') as String,
              installed: p['installed'] == true,
              lastUsed: p['last_used'] is int ? p['last_used'] as int : 0,
            ))
        .toList();
  }

  @override
  Future<String> newPhrase({int words = 24}) => _service.newPhrase(words: words);

  @override
  Future<void> checkPhrase(String phrase) => _service.checkPhrase(phrase);

  @override
  Future<void> createWallet({required String login, required String phrase, required String password, required String network}) async {
    _walletInitializationWarning = null;
    _captureInitializationWarning(await _service.create(name: login, network: network, phrase: phrase, password: password));
  }

  @override
  Future<void> importWallet({required String login, required String phrase, required String password, required String network}) async {
    _walletInitializationWarning = null;
    _captureInitializationWarning(await _service.restore(name: login, network: network, phrase: phrase, password: password));
  }

  @override
  Future<void> unlock({required String login, required String password, required String network}) async {
    await _service.unlock(name: login, network: network, password: password);
  }

  @override
  Future<void> unlockBound({required String login, required String password, required String network, required String vaultDigest}) async {
    await _service.unlockBound(name: login, network: network, password: password, vaultDigest: vaultDigest);
  }

  @override
  Future<void> lock() => _service.lock();

  @override
  Future<WalletStatus> status() async {
    final Map<String, dynamic> json = await _service.status();
    final Map<String, dynamic> balance = (json['balance'] as Map?)?.cast<String, dynamic>() ?? <String, dynamic>{};
    final Map<String, dynamic> proof = (json['proof'] as Map?)?.cast<String, dynamic>() ?? <String, dynamic>{};
    final Map<String, dynamic> last = (proof['last_open'] as Map?)?.cast<String, dynamic>() ?? <String, dynamic>{};
    final Map<String, dynamic> session = (proof['session'] as Map?)?.cast<String, dynamic>() ?? <String, dynamic>{};
    final Map<String, dynamic> sync = (last['sync'] as Map?)?.cast<String, dynamic>() ?? <String, dynamic>{};
    final bool hasSession = proof['session'] != null;
    final String independence = (sync['independent_nets'] ?? '').toString();
    final RegExpMatch? nets = RegExp(r'\d+').firstMatch(independence);
    return WalletStatus(
      profile: (json['name'] ?? '') as String,
      network: (json['network'] ?? 'mainnet') as String,
      address: json['address'] as String?,
      balance: WalletBalance(
        availableNano: _i(balance['available_nanogrin']),
        reservedNano: _i(balance['reserved_nanogrin']),
        incomingNano: _i(balance['incoming_nanogrin']),
        immatureNano: _i(balance['immature_nanogrin']),
        totalNano: _i(balance['total_nanogrin']),
        tipHeight: _i(balance['tip_height']),
        unspentOutputs: _i(balance['unspent_outputs']),
      ),
      proof: WalletProof(
        tipHeight: _i(session['tip_height']) > 0
            ? _i(session['tip_height'])
            : _i(sync['height']) > 0
                ? _i(sync['height'])
                : _i(proof['proven_at_height']) > 0
                    ? _i(proof['proven_at_height'])
                    : null,
        tipAgeSeconds: session['tip_age_seconds'] == null ? null : _i(session['tip_age_seconds']),
        freshness: (session['freshness'] ?? sync['freshness'] ?? 'UNKNOWN').toString(),
        canSpend: session['can_spend'] == true,
        hasSession: hasSession,
        independentNets: nets == null ? 0 : int.tryParse(nets.group(0)!) ?? 0,
        peerIndependence: sync['peer_independence']?.toString(),
        currentTipState: last['current_tip_state']?.toString(),
        canonicalTip: sync['canonical_tip']?.toString(),
        chainSupport: sync['chain_support']?.toString(),
        syncStatus: (session['sync_status'] ?? sync['status'])?.toString(),
        balanceAuthentication: last['balance_authentication']?.toString(),
        openedAt: DateTime.tryParse((last['at'] ?? '').toString()),
        sessionPath: last['session']?.toString(),
        proofVerdict: last['proof_verdict']?.toString(),
        // Строго: без явного ok от ядра баланс не считается доказанным.
        balanceOk: (json['balance_check'] as Map?)?['ok'] == true,
        balanceProblem: (json['balance_check'] as Map?)?['reason']?.toString(),
      ),
      torRunning: ((json['tor'] as Map?)?['running']) == true,
      verifyMode: (json['verify_mode'] ?? 'checkpoint').toString(),
    );
  }

  @override
  Future<String> address() => _service.address();

  @override
  Future<List<WalletTx>> payments() async {
    final Map<String, dynamic> json = await _service.payments();
    final int needed = _i(json['confirmations_needed']);
    final List<dynamic> raw = (json['payments'] as List<dynamic>?) ?? <dynamic>[];
    final List<WalletTx> out = <WalletTx>[];
    for (final dynamic e in raw) {
      final Map<String, dynamic> p = (e as Map).cast<String, dynamic>();
      final Map<String, dynamic> conf = (p['confirmation'] as Map?)?.cast<String, dynamic>() ?? <String, dynamic>{};
      final String kind = (p['kind'] ?? '').toString();
      final TxDirection direction = (p['direction']?.toString() == 'incoming' || kind == 'receive' || kind == 'invoice')
          ? TxDirection.incoming
          : TxDirection.outgoing;
      final int depth = _i(p['depth'] ?? conf['depth']);
      final int? height = _i(p['height'] ?? conf['height']) > 0 ? _i(p['height'] ?? conf['height']) : null;
      String stage = (p['stage'] ?? '').toString();
      final TxStage mapped = txStageFromService(stage);
      final String counterparty = (p['to'] ?? p['from'] ?? p['payer'] ?? '').toString();
      out.add(WalletTx(
        txId: (p['tx_id'] ?? '').toString(),
        kind: kind,
        torStatus: p['tor_status']?.toString(),
        backupRetry: p['backup_retry'] == true,
        direction: direction,
        stage: mapped,
        amountNano: _i(p['amount']),
        feeNano: p['fee'] == null ? null : _i(p['fee']),
        counterparty: counterparty,
        height: height,
        confirmations: depth,
        confirmationsNeeded: needed,
        created: DateTime.tryParse((p['created'] ?? '').toString()),
        cancelled: stage == 'cancelled',
        // Grin payment proof = recipient signature (sender_verified / payment-proof.json), not inclusion.
        proof: p['sender_verified'] == true || p['payment_proof'] == true,
      ));
    }
    out.sort((WalletTx a, WalletTx b) {
      final DateTime x = a.created ?? DateTime.fromMillisecondsSinceEpoch(0);
      final DateTime y = b.created ?? DateTime.fromMillisecondsSinceEpoch(0);
      return y.compareTo(x);
    });
    return out;
  }

  @override
  Future<List<ContactInfo>> contacts() async {
    final Map<String, dynamic> json = await _service.contacts();
    final List<dynamic> raw = (json['contacts'] as List<dynamic>?) ?? <dynamic>[];
    return raw.map((dynamic e) {
      final Map<String, dynamic> c = (e as Map).cast<String, dynamic>();
      final id = (c['id'] ?? '').toString();
      final name = (c['name'] ?? '').toString().trim();
      return ContactInfo(
        id: id,
        name: name.isNotEmpty ? name : (id.isNotEmpty ? id : '?'),
        messenger: c['messenger']?.toString(),
        auto: c['auto'] != false,
        onion: c['onion']?.toString(),
        identityChecked: c['identity_checked'] == true,
      );
    }).toList();
  }

  @override
  Future<void> cancelPayment(String txId) => _service.release(txId);

  @override
  Future<String> showPhrase(String password) async {
    final Map<String, dynamic> r = await _service.showPhrase(password);
    return (r['phrase'] ?? '').toString();
  }

  @override
  Future<void> changePassword(String oldPassword, String newPassword) async {
    await _service.changePassword(oldPassword, newPassword);
  }

  @override
  Future<void> renameWallet(String name) async {
    await _service.renameWallet(name);
  }

  @override
  Future<void> addContact(String address, String name) async {
    final id = address.trim();
    final label = name.trim();
    if (id.isEmpty || label.isEmpty) throw ArgumentError('Name and wallet address are required');
    await _service.insertContact(id: id, name: label);
  }

  @override
  Future<void> renameContact(String id, String name) async {
    final List<ContactInfo> all = await contacts();
    final ContactInfo? cur = all.where((ContactInfo c) => c.id == id).firstOrNull;
    await _service.addContact(id: id, name: name.trim(), messenger: cur?.messenger, auto: cur?.auto ?? true);
  }

  @override
  Future<String?> autoAcceptPolicy() async {
    final value = (await _service.contacts())['auto_accept'];
    const modes = <String>{'ask_all', 'ask', 'contacts', 'all', 'off'};
    return value is String && modes.contains(value) ? value : null;
  }

  @override
  Future<void> autoAccept(String mode) async {
    await _service.autoAccept(mode);
  }

  @override
  Future<Map<String, dynamic>> torBridgeSettings() async {
    final settings = await _service.settings();
    return <String, dynamic>{
      'mode': settings['tor_bridge_mode'] ?? 'direct',
      'line': settings['tor_bridge_line'] ?? '',
      'binary': settings['tor_bridge_binary'] ?? '',
    };
  }

  @override
  Future<void> setTorBridgeSettings({required String mode, required String line, required String binary}) async {
    await _service.call('wallet.set_settings', <String, dynamic>{
      'tor_bridge_mode': mode, 'tor_bridge_line': line, 'tor_bridge_binary': binary,
    });
  }

  @override
  Future<void> torStart() => _service.torStart();

  @override
  Future<void> torStop() => _service.torStop();

  @override
  Future<TorStatusInfo> torStatus() async {
    final dynamic raw = await _service.call('tor.status');
    final Map<String, dynamic> j = raw is Map ? raw.cast<String, dynamic>() : <String, dynamic>{};
    final Map<String, dynamic> api = (j['foreign_api'] as Map?)?.cast<String, dynamic>() ?? <String, dynamic>{};
    final dynamic rawState = j['status'];
    final Map<String, dynamic> state = rawState is Map ? rawState.cast<String, dynamic>() : <String, dynamic>{};
    return TorStatusInfo(
      running: j['running'] == true,
      phase: TorStatusInfo.phaseFromService(j['running'] == true, state['tor']),
      pendingCount: _i(j['pending_count']),
      foreignAddress: api['address']?.toString(),
      foreignOnion: api['onion']?.toString(),
    );
  }

  @override
  Future<List<PendingPayment>> torPending() async {
    final dynamic raw = await _service.call('tor.pending');
    if (raw is! List) return const <PendingPayment>[];
    final List<PendingPayment> out = <PendingPayment>[];
    for (final dynamic e in raw) {
      final Map<String, dynamic> j = (e as Map).cast<String, dynamic>();
      out.add(PendingPayment(
        slateId: (j['slate_id'] ?? '').toString(),
        amountNano: _i(j['amount']),
        feeNano: j['fee'] == null ? null : _i(j['fee']),
        from: j['from']?.toString(),
        messengerPeer: j['messenger_peer']?.toString(),
        channel: (j['channel'] ?? 'tor-foreign').toString(),
        expiresInSeconds: _i(j['expires_in_s']),
        waiting: j['waiting'] == true,
      ));
    }
    return out;
  }

  @override
  Future<PendingDecision> torDecide({
    required String slateId,
    required bool accept,
    bool addContact = true,
    String name = '',
  }) async {
    final dynamic raw = await _service.call('tor.decide', <String, dynamic>{
      'slate_id': slateId,
      'accept': accept,
      'add_contact': addContact,
      'name': name,
    });
    final Map<String, dynamic> j = raw is Map ? raw.cast<String, dynamic>() : <String, dynamic>{};
    return PendingDecision(
      accepted: j['accepted'] == true,
      answeredOverTor: j['answered_over_tor'] == true,
      contactAdded: j['contact_added'] == true,
    );
  }

  @override
  Future<List<InboxItem>> torInbox() async {
    final dynamic raw = await _service.call('tor.inbox');
    if (raw is! List) return const <InboxItem>[];
    final List<InboxItem> out = <InboxItem>[];
    for (final dynamic e in raw) {
      final Map<String, dynamic> j = (e as Map).cast<String, dynamic>();
      final int at = _i(j['received_at']);
      out.add(InboxItem(
        file: (j['file'] ?? '').toString(),
        kind: (j['kind'] ?? 'payment').toString(),
        amountNano: j['amount'] == null ? null : _i(j['amount']),
        feeNano: j['fee'] == null ? null : _i(j['fee']),
        from: j['from']?.toString(),
        receivedAt: at > 0 ? DateTime.fromMillisecondsSinceEpoch(at * 1000) : null,
        transportMode: j['transport_mode']?.toString(),
      ));
    }
    return out;
  }

  @override
  Future<ReceiveResult> receiveInbox(String inboxFile) async {
    final dynamic raw = await _service.call('wallet.receive', <String, dynamic>{'inbox_file': inboxFile});
    final Map<String, dynamic> r = raw is Map ? raw.cast<String, dynamic>() : <String, dynamic>{};
    final String s2 = (r['slatepack'] ?? r['answer'] ?? '').toString();
    return ReceiveResult(
      txId: (r['tx_id'] ?? '').toString(),
      answer: (r['answer'] ?? s2).toString(),
      slatepack: s2,
      amountNano: _i(r['amount']),
      from: r['from']?.toString(),
      senderVerified: r['sender_verified'] == true,
      deliveryQueued: r['delivery'] is Map ? (r['delivery'] as Map)['queued'] == true : null,
      deliveryError: r['delivery'] is Map ? (r['delivery'] as Map)['error']?.toString() : null,
    );
  }

  @override
  Future<WalletJob> payInvoiceInboxJob(String inboxFile) async =>
      WalletJob(id: await _service.payInvoice(inboxFile: inboxFile), core: this);

  @override
  Future<void> setExtraPeers(List<String> peers) async {
    await _service.setSettings(extraPeers: peers);
  }

  @override
  Future<void> setVerifyMode(String mode) async {
    if (mode != 'checkpoint' && mode != 'header_proof') {
      throw ArgumentError('verify_mode must be checkpoint or header_proof');
    }
    await _service.setSettings(verifyMode: mode);
  }

  @override
  Future<String> getVerifyMode() async {
    final settings = await _service.settings();
    return (settings['verify_mode'] ?? 'checkpoint').toString();
  }

  @override
  Future<CheckpointInfo> checkpointInfo({String? network}) async {
    final Map<String, dynamic> j = await _service.checkpointInfo(network: network);
    final Map<String, dynamic> shipped = (j['shipped'] as Map?)?.cast<String, dynamic>() ?? <String, dynamic>{};
    final Map<String, dynamic> own = (j['own'] as Map?)?.cast<String, dynamic>() ?? <String, dynamic>{};
    return CheckpointInfo(
      source: (j['source'] ?? 'release') as String,
      shippedExists: shipped['exists'] == true,
      shippedHeight: shipped['height'] == null ? null : _i(shipped['height']),
      shippedHash: shipped['hash']?.toString(),
      ownBuilt: own['built'] == true,
      ownPaused: own['paused'] == true,
      ownHeight: own['height'] == null ? null : _i(own['height']),
      ownHash: own['hash']?.toString(),
      matches: own['matches'] is bool ? own['matches'] as bool : (j['matches'] is bool ? j['matches'] as bool : null),
      offerSeen: j['offer_seen'] == true,
    );
  }

  @override
  Future<WalletJob> ownCheckpointJob({String? network}) async =>
      WalletJob(id: await _service.ownCheckpoint(network: network), core: this);

  @override
  Future<void> setCheckpointSource(String source) async {
    await _service.setSettings(checkpointSource: source);
  }

  @override
  Future<void> markCheckpointOfferSeen() async {
    await _service.setSettings(checkpointOfferSeen: true);
  }

  @override
  Future<WalletJob> openJob() async => WalletJob(id: await _service.open(), core: this);

  @override
  Future<WalletJob> sendJob({required String to, required int amountNano, Map<String, String>? backupIntent}) async =>
      WalletJob(id: await _service.send(to: to, amount: amountNano, backupIntent: backupIntent), core: this);

  @override
  Future<void> deliverTor(String txId) => _service.torDeliver(txId);

  @override
  Future<Map<String, dynamic>> backupPaymentContacts() => _service.backupPaymentContacts();
  @override
  Future<void> deliverBackup(String txId, {required String peer, required String mode, required String route}) => _service.deliverBackup(txId, peer, mode, route);
  @override
  Future<void> validateBackupInboxInvoice(String file) => _service.validateBackupInboxInvoice(file);
  @override
  Future<void> deliverBackupInboxInvoice(String file, String txId) => _service.deliverBackupInboxInvoice(file, txId);
  @override
  Future<Map<String, dynamic>> backupPaymentRetryInfo(String txId) => _service.backupPaymentRetryInfo(txId);
  @override
  Future<void> retryBackupPayment(String txId) => _service.retryBackupPayment(txId);

  @override
  Future<WalletJob> finalizeJob({required String txId, required String answer}) async =>
      WalletJob(id: await _service.finalize(txId: txId, answer: answer), core: this);

  @override
  Future<WalletJob> broadcastJob(String txId) async => WalletJob(id: await _service.broadcast(txId), core: this);

  @override
  Future<WalletJob> confirmJob(String txId) async => WalletJob(id: await _service.confirm(txId), core: this);

  @override
  Future<WalletJob> payInvoiceJob(String slatepack) async => WalletJob(id: await _service.payInvoice(slatepack: slatepack), core: this);

  @override
  Future<JobProgress> waitJob(String id, {void Function(JobProgress)? onProgress}) async {
    final dynamic result = await _service.waitJob(id, onProgress: (JobState s) {
      onProgress?.call(JobProgress(id: s.id, state: s.state, phase: s.phase, lines: s.lines));
    });
    return JobProgress(id: id, state: 'done', phase: '', lines: const <String>[], result: result);
  }

  @override
  Future<void> cancelJob(String id) => _service.cancelJob(id);

  @override
  Future<SendResult> send({required String to, required int amountNano}) async {
    final WalletJob job = await sendJob(to: to, amountNano: amountNano);
    final Map<String, dynamic> r = await job.wait();
    return SendResult(txId: (r['tx_id'] ?? '').toString(), slatepack: (r['slatepack'] ?? '').toString(), feeNano: r['fee'] == null ? null : _i(r['fee']));
  }

  @override
  Future<ReceiveResult> receive(String slatepack) async {
    final Map<String, dynamic> r = await _service.receive(slatepack);
    return ReceiveResult(
      txId: (r['tx_id'] ?? '').toString(),
      answer: (r['answer'] ?? '').toString(),
      amountNano: _i(r['amount']),
      from: r['from']?.toString(),
      senderVerified: r['sender_verified'] == true,
    );
  }

  @override
  Future<InvoiceResult> invoice({required int amountNano, String? payer, Map<String, String>? backupIntent}) async {
    final Map<String, dynamic> r = await _service.invoice(amount: amountNano, payer: payer, backupIntent: backupIntent);
    return InvoiceResult(txId: (r['tx_id'] ?? '').toString(), slatepack: (r['slatepack'] ?? '').toString(), backupIntentError: r['backup_intent_error']?.toString());
  }

  @override
  Future<String> slatepack(String txId) => _service.slatepack(txId);

  @override
  Future<List<SlatepackFile>> slatepacks(String txId) async {
    final Object? list = (await _service.slatepacks(txId))['slatepacks'];
    if (list is! List) return const <SlatepackFile>[];
    return <SlatepackFile>[
      for (final Object? e in list)
        if (e is Map && e['file'] is String && e['slatepack'] is String)
          SlatepackFile(e['file'] as String, e['slatepack'] as String),
    ];
  }

  @override
  Future<void> hideCancelled(String txId) async {
    await _service.call('wallet.hide_cancelled', <String, dynamic>{'tx_id': txId});
  }

  @override
  String describeError(Object error) {
    if (error is GrinSightError) return error.message;
    return error.toString().replaceFirst('Exception: ', '');
  }

  static int _i(Object? v) {
    if (v is int) return v;
    if (v is num) return v.toInt();
    return int.tryParse(v?.toString() ?? '') ?? 0;
  }

}
