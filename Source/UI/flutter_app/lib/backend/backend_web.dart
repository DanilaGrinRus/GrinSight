import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import '../core.dart';
import '../wallet_model.dart';

class WebBackendError implements Exception {
  WebBackendError(this.message);
  final String message;
  @override
  String toString() => message;
}

/// Browser backend: real BIP39/ExtKeychain in Wasm, encrypted profile in
/// IndexedDB. No key or phrase ever crosses the gateway.
class WebWalletCore implements WalletCore {
  String? _login;
  String _network = 'floonet';
  String _verifyMode = 'checkpoint';
  String? _addressCache;
  String? _gatewayUrl = 'wss://192.168.1.33:8444';
  int _syncAmount = 0;
  int _syncCount = 0;
  int _syncHeight = 4102560;
  Future<Map<String, dynamic>>? _syncFuture;

  Future<Object?> _call(String method, [List<Object?> args = const <Object?>[]]) async {
    final JSObject? bridge = globalContext.getProperty<JSObject?>('grinsightWeb'.toJS);
    if (bridge == null) {
      throw WebBackendError('Web-ядро не загрузилось (backend_web_bridge.mjs).');
    }
    try {
      final List<JSAny?> jsArgs = args.map((Object? e) => e?.jsify()).toList();
      final JSAny? p = bridge.callMethodVarArgs(method.toJS, jsArgs);
      final JSAny? result = await (p as JSPromise<JSAny?>).toDart;
      return result.dartify();
    } catch (e) {
      String msg = '$e';
      throw WebBackendError(msg.replaceFirst('Error: ', ''));
    }
  }

  Map<String, dynamic> _map(Object? value) {
    if (value is Map<String, dynamic>) return value;
    if (value is Map) return value.map((k, v) => MapEntry('$k', v));
    return <String, dynamic>{};
  }

  @override
  String describeError(Object error) => '$error';

  @override
  Future<void> close() async {}

  @override
  Future<List<WalletProfile>> profiles() async {
    final Object? list = await _call('list');
    final List<WalletProfile> out = <WalletProfile>[];
    if (list is List) {
      for (final Object? item in list) {
        final Map<String, dynamic> m = _map(item);
        out.add(WalletProfile(
          name: '${m['login'] ?? ''}',
          network: '${m['network'] ?? 'floonet'}',
          installed: true,
          lastUsed: (m['lastUsed'] as num?)?.toInt() ?? 0,
        ));
      }
    }
    return out;
  }

  @override
  Future<String> newPhrase({int words = 24}) async {
    final Object? p = await _call('newPhrase', <Object?>[words]);
    if (p is! String || p.isEmpty) throw WebBackendError('Не удалось сгенерировать фразу');
    return p;
  }

  @override
  Future<void> checkPhrase(String phrase) async {
    await _call('checkPhrase', <Object?>[phrase]);
  }

  @override
  Future<void> createWallet({
    required String login,
    required String phrase,
    required String password,
    required String network,
  }) async {
    final Object? r = await _call('create', <Object?>[
      <String, Object?>{'login': login, 'phrase': phrase, 'password': password, 'network': network},
    ]);
    final Map<String, dynamic> m = _map(r);
    _login = '${m['login'] ?? login}'.trim().toLowerCase();
    _network = '${m['network'] ?? network}';
    _addressCache = m['address']?.toString();
  }

  @override
  Future<void> importWallet({
    required String login,
    required String phrase,
    required String password,
    required String network,
  }) =>
      createWallet(login: login, phrase: phrase, password: password, network: network);

  @override
  Future<void> unlock({
    required String login,
    required String password,
    required String network,
  }) async {
    final Object? r = await _call('unlock', <Object?>[
      <String, Object?>{'login': login, 'password': password, 'network': network},
    ]);
    final Map<String, dynamic> m = _map(r);
    _login = '${m['login'] ?? login}'.trim().toLowerCase();
    _network = '${m['network'] ?? network}';
    _addressCache = m['address']?.toString();
  }

  @override
  Future<void> lock() async {
    await _call('lock');
    _login = null;
    _addressCache = null;
  }

  @override
  Future<WalletStatus> status() async {
    if (_login == null) throw WebBackendError('Кошелёк не разблокирован');
    final Object? a = await _call('address');
    final String? address = a is String && a.isNotEmpty ? a : _addressCache;
    _addressCache = address;
    return WalletStatus(
      profile: _login!,
      network: _network,
      address: address,
      balance: WalletBalance(
        availableNano: _syncAmount,
        reservedNano: 0,
        incomingNano: 0,
        immatureNano: 0,
        totalNano: _syncAmount,
        tipHeight: _syncHeight,
        unspentOutputs: _syncCount,
      ),
      proof: WalletProof(
        freshness: _syncCount > 0 ? 'FRESH' : 'UNKNOWN',
        hasSession: true,
        canSpend: _syncCount > 0,
        independentNets: 0,
        tipHeight: _syncHeight,
        syncStatus: _syncCount > 0 ? 'web: PIBD bundle scanned' : 'web: not synced',
        balanceAuthentication: _syncCount > 0 ? 'output_root verified in Wasm' : null,
      ),
      torRunning: false,
      verifyMode: _verifyMode,
    );
  }

  @override
  Future<String> address() async {
    final Object? a = await _call('address');
    if (a is String && a.isNotEmpty) {
      _addressCache = a;
      return a;
    }
    throw WebBackendError('Адрес недоступен: кошелёк заблокирован');
  }

  @override
  Future<List<WalletTx>> payments() async => const <WalletTx>[];

  @override
  Future<List<ContactInfo>> contacts() async => const <ContactInfo>[];

  @override
  Future<Map<String, dynamic>> nostrSettings() async => {'mode':'off'};
  @override
  Future<void> setNostrSettings({required String mode, required String url, required String proxy, required bool consent, required bool expiry, required int historyDays, bool? catalogueAutoPublish}) async => throw UnsupportedError('Nostr unavailable on web');
  @override
  Future<Map<String, dynamic>> chatNostrBinding() async => throw UnsupportedError('Nostr unavailable on web');
  @override
  Future<Map<String, dynamic>> chatI2pBinding() async => throw UnsupportedError('I2P unavailable on web');
  @override
  Future<void> chatI2pAdd(Map<String, dynamic> binding, String name) async => throw UnsupportedError('I2P unavailable on web');
  @override
  Future<void> chatNostrAdd(Map<String, dynamic> binding, String name) async => throw UnsupportedError('Nostr unavailable on web');

  @override
  Future<Map<String, dynamic>> chatStatus() async => <String, dynamic>{'last_error': null};
  @override
  Future<Map<String, dynamic>> chatQuarantineInvalidExport(String token) async => throw UnsupportedError('Quarantine unavailable');
  @override
  Future<void> chatQuarantineInvalidDiscard(String token) async => throw UnsupportedError('Quarantine unavailable');
  @override
  Future<Map<String, dynamic>> chatQuarantineList() async => throw UnsupportedError('Quarantine unavailable');
  @override
  Future<Map<String, dynamic>> chatQuarantineExport(String id, String digest) async => throw UnsupportedError('Quarantine unavailable');
  @override
  Future<void> chatQuarantineDiscard(String id, String digest, bool corrupt) async => throw UnsupportedError('Quarantine unavailable');
  @override
  Future<void> chatQuarantineCleanup() async => throw UnsupportedError('Quarantine unavailable');
  @override
  Future<Map<String, dynamic>> chatDeferredList() async => throw UnsupportedError('Deferred messages unavailable');
  @override
  Future<void> chatDeferredRetry(String route) async => throw UnsupportedError('Deferred messages unavailable');
  @override
  Future<void> chatDeferredDiscard(String id, String route) async => throw UnsupportedError('Deferred messages unavailable');
  @override
  Future<Map<String, dynamic>> chatInfo() async => <String, dynamic>{
        'ready': false,
        'address': _addressCache,
      };

  @override
  Future<Map<String, dynamic>> chatMessages([int after = 0]) async => <String, dynamic>{
        'messages': <dynamic>[],
        'next': after,
        'epoch': 'web',
      };

  @override
  Future<Map<String, dynamic>> chatSend(String to, String text) async =>
      throw WebBackendError('Мессенджер в web пока не подключён');

  @override
  Future<String?> autoAcceptPolicy() async => null;

  @override
  Future<void> autoAccept(String mode) async {}

  @override
  Future<String> showPhrase(String password) async {
    if (_login == null) throw WebBackendError('Кошелёк не разблокирован');
    final Object? p = await _call('showPhrase', <Object?>[
      <String, Object?>{'login': _login, 'password': password},
    ]);
    if (p is! String) throw WebBackendError('Не удалось расшифровать фразу');
    return p;
  }

  @override
  Future<void> changePassword(String oldPassword, String newPassword) async {
    if (_login == null) throw WebBackendError('Кошелёк не разблокирован');
    await _call('changePassword', <Object?>[
      <String, Object?>{'login': _login, 'oldPassword': oldPassword, 'newPassword': newPassword},
    ]);
  }

  @override
  Future<void> hideCancelled(String txId) async {}

  @override
  Future<void> cancelPayment(String txId) async =>
      throw WebBackendError('В web нет незавершённых платежей');

  @override
  Future<void> renameWallet(String name) async {
    if (_login == null) throw WebBackendError('Кошелёк не разблокирован');
    await _call('rename', <Object?>[
      <String, Object?>{'login': _login, 'name': name},
    ]);
  }

  @override
  Future<void> renameContact(String id, String name) async {}

  @override
  Future<void> addContact(String address, String name) async => throw UnsupportedError("Contacts are unavailable on web");

  @override
  Future<Map<String, dynamic>> torBridgeSettings() async => <String, dynamic>{};

  @override
  Future<void> setTorBridgeSettings({required String mode, required String line, required String binary}) async =>
      throw WebBackendError('Tor недоступен в web');

  @override
  Future<void> torStart() async => throw WebBackendError('Tor недоступен в web');

  @override
  Future<TorStatusInfo> torStatus() async => const TorStatusInfo(running: false);

  @override
  Future<List<PendingPayment>> torPending() async => const <PendingPayment>[];

  @override
  Future<PendingDecision> torDecide({
    required String slateId,
    required bool accept,
    bool addContact = true,
    String name = '',
  }) =>
      throw WebBackendError('Tor недоступен в web');

  @override
  Future<List<InboxItem>> torInbox() async => const <InboxItem>[];

  @override
  Future<ReceiveResult> receiveInbox(String inboxFile) async =>
      throw WebBackendError('Приём файлов в web пока не подключён');

  @override
  Future<WalletJob> payInvoiceInboxJob(String inboxFile) async =>
      throw WebBackendError('Счета в web пока не подключены');

  @override
  Future<void> setExtraPeers(List<String> peers) async {
    final String ws = peers.firstWhere((String p) => p.startsWith('ws://') || p.startsWith('wss://'), orElse: () => '');
    if (ws.isNotEmpty) _gatewayUrl = ws;
  }

  @override
  Future<void> setVerifyMode(String mode) async {
    _verifyMode = mode == 'header_proof' ? 'header_proof' : 'checkpoint';
  }

  @override
  Future<String> getVerifyMode() async => _verifyMode;

  @override
  Future<CheckpointInfo> checkpointInfo({String? network}) async =>
      const CheckpointInfo(source: 'none', shippedExists: false);

  @override
  Future<WalletJob> ownCheckpointJob({String? network}) async =>
      WalletJob(id: 'web-checkpoint-unsupported', core: this);

  @override
  Future<void> setCheckpointSource(String source) async {}

  @override
  Future<void> markCheckpointOfferSeen() async {}

  @override
  Future<WalletJob> openJob() async {
    final String? url = _gatewayUrl;
    if (url == null || url.isEmpty) throw WebBackendError('Не задан gateway URL для синхронизации');
    final String id = 'web-sync-${DateTime.now().microsecondsSinceEpoch}';
    _syncFuture = _sync(url);
    return WalletJob(id: id, core: this);
  }

  Future<Map<String, dynamic>> _sync(String url) async {
    final Object? r = await _call('syncBundle', <Object?>[
      <String, Object?>{'url': url, 'height': _syncHeight},
    ]);
    final Map<String, dynamic> m = _map(r);
    _syncAmount = (m['amount'] as num?)?.toInt() ?? 0;
    _syncCount = (m['count'] as num?)?.toInt() ?? 0;
    _syncHeight = (m['height'] as num?)?.toInt() ?? _syncHeight;
    return m;
  }

  @override
  Future<WalletJob> sendJob({required String to, required int amountNano, Map<String, String>? backupIntent}) async =>
      throw WebBackendError('Отправка в web пока не подключена');

  @override
  Future<void> deliverTor(String txId) async =>
      throw WebBackendError('Tor недоступен в web');

  @override
  Future<Map<String, dynamic>> backupPaymentContacts() async => throw WebBackendError('Платежи через резервные каналы недоступны в web');
  @override
  Future<void> deliverBackup(String txId, {required String peer, required String mode, required String route}) async => throw WebBackendError('Платежи через резервные каналы недоступны в web');
  @override
  Future<void> validateBackupInboxInvoice(String file) async => throw WebBackendError('Платежи через резервные каналы недоступны в web');
  @override
  Future<void> deliverBackupInboxInvoice(String file, String txId) async => throw WebBackendError('Платежи через резервные каналы недоступны в web');
  @override
  Future<Map<String, dynamic>> backupPaymentRetryInfo(String txId) async => {'available': false};
  @override
  Future<void> retryBackupPayment(String txId) async => throw WebBackendError('Платежи через резервные каналы недоступны в web');

  @override
  Future<WalletJob> finalizeJob({required String txId, required String answer}) async =>
      throw WebBackendError('Платежи в web пока не подключены');

  @override
  Future<WalletJob> broadcastJob(String txId) async =>
      throw WebBackendError('Платежи в web пока не подключены');

  @override
  Future<WalletJob> confirmJob(String txId) async =>
      throw WebBackendError('Платежи в web пока не подключены');

  @override
  Future<WalletJob> payInvoiceJob(String slatepack) async =>
      throw WebBackendError('Платежи в web пока не подключены');

  @override
  Future<JobProgress> waitJob(String id, {void Function(JobProgress)? onProgress}) async {
    final Future<Map<String, dynamic>>? f = _syncFuture;
    if (f == null) throw WebBackendError('Нет активной синхронизации');
    try {
      final Map<String, dynamic> r = await f;
      final JobProgress p = JobProgress(id: id, state: 'done', phase: 'web', lines: const <String>[], result: r);
      onProgress?.call(p);
      return p;
    } catch (e) {
      final JobProgress p = JobProgress(id: id, state: 'failed', phase: 'web', lines: const <String>[], error: describeError(e));
      onProgress?.call(p);
      return p;
    } finally {
      _syncFuture = null;
    }
  }

  @override
  Future<void> cancelJob(String id) async {}

  @override
  Future<SendResult> send({required String to, required int amountNano}) async =>
      throw WebBackendError('Отправка в web пока не подключена');

  @override
  Future<ReceiveResult> receive(String slatepack) async =>
      throw WebBackendError('Платежи в web пока не подключены');

  @override
  Future<InvoiceResult> invoice({required int amountNano, String? payer, Map<String, String>? backupIntent}) async =>
      throw WebBackendError('Счета в web пока не подключены');

  @override
  Future<String> slatepack(String txId) async =>
      throw WebBackendError('Платежи в web пока не подключены');
}


Future<WalletCore> startBackend() async => WebWalletCore();

String get devAutoProfile => '';
String get devAutoPassword => '';
String get devAutoNetwork => '';
bool get checkpointAssetsUpdated => false;





