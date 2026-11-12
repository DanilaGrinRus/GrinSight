import 'dart:async';

import 'package:grinsight/core.dart';
import 'package:grinsight/wallet_model.dart';

/// Поддельное ядро только для виджет-тестов. Никаких сетевых/демо-данных в UI.
class FakeWalletCore implements WalletCore {
  FakeWalletCore({this.proofMissing = false, this.slowOpen = false, this.balanceBroken = false});

  /// Сессия свежая, но файл баланса не прошёл проверку (MAC / другая вершина).
  final bool balanceBroken;

  /// Вернуть статус без доказательства (для проверки полосы «нужно обновить»).
  final bool proofMissing;

  /// Обновление (openJob) не завершается, пока не вызван [finishOpen]: проверка прогресс-полосы.
  final bool slowOpen;
  Completer<void>? _gate;
  String? _slowId;

  void finishOpen() => _gate?.complete();

  final Map<String, Map<String, dynamic>> _jobs = <String, Map<String, dynamic>>{};
  int _next = 1;
  bool locked = false;
  String? unlockedProfile;
  int openCalls = 0;
  String verifyMode = 'checkpoint';

  @override
  Future<void> close() async {}

  @override
  Future<List<WalletProfile>> profiles() async => const <WalletProfile>[
        WalletProfile(name: 'alex', network: 'floonet', installed: true, lastUsed: 1),
      ];

  @override
  Future<String> newPhrase({int words = 24}) async {
    const String all =
        'orbit velvet canyon harbor mirror lemon tiger galaxy pencil crystal meadow rocket anchor violin saddle thunder island copper blossom falcon marble whisper garden puzzle';
    return all.split(' ').take(words).join(' ');
  }

  @override
  Future<void> checkPhrase(String phrase) async {
    if (!<int>[12, 15, 18, 21, 24].contains(phrase.trim().split(RegExp(r'\s+')).length)) throw Exception('seed: 12/18/24 words');
  }

  @override
  Future<void> createWallet({required String login, required String phrase, required String password, required String network}) async {
    unlockedProfile = login;
    locked = false;
  }

  @override
  Future<void> importWallet({required String login, required String phrase, required String password, required String network}) async {
    unlockedProfile = login;
    locked = false;
  }

  @override
  Future<void> unlock({required String login, required String password, required String network}) async {
    unlockedProfile = login;
    locked = false;
  }

  @override
  Future<void> lock() async {
    locked = true;
    unlockedProfile = null;
  }

  @override
  Future<WalletStatus> status() async => WalletStatus(
        profile: unlockedProfile ?? 'alex',
        network: 'floonet',
        address: 'tgrin1flemgae89jutuaaqqtrgj9nk3w2323lsywgh6qz330heyuavas4svprm53',
        balance: const WalletBalance(
          availableNano: 11000000000,
          reservedNano: 2550000000,
          incomingNano: 0,
          immatureNano: 0,
          totalNano: 11000000000,
          tipHeight: 4100208,
          unspentOutputs: 2,
        ),
        verifyMode: verifyMode,
        proof: proofMissing
            ? const WalletProof()
            : WalletProof(
          balanceOk: !balanceBroken,
          balanceProblem: balanceBroken ? 'wallet-outputs.jsonl: mac mismatch' : null,
          tipHeight: 4100208,
          tipAgeSeconds: 31,
          freshness: 'FRESH',
          canSpend: true,
          hasSession: true,
          independentNets: 2,
          peerIndependence: 'DISTINCT_NETS_2',
          currentTipState: 'AT_VERIFIED_TIP_ONLY',
          canonicalTip: 'MOST_WORK_OF_INDEPENDENT_PEERS',
          chainSupport: '2/2',
          syncStatus: 'PASS',
          sessionPath: '/tmp/sync',
        ),
        torRunning: false,
      );

  @override
  Future<String> address() async => 'tgrin1flemgae89jutuaaqqtrgj9nk3w2323lsywgh6qz330heyuavas4svprm53';

  @override
  Future<List<WalletTx>> payments() async => <WalletTx>[
        WalletTx(
          txId: 'tx1',
          direction: TxDirection.incoming,
          stage: TxStage.confirmed,
          amountNano: 6500000000,
          counterparty: 'tgrin1carol',
          confirmationsNeeded: 10,
          height: 4100082,
          confirmations: 10,
          created: DateTime(2026, 11, 10, 12, 50),
          proof: true,
        ),
        WalletTx(
          txId: 'tx2',
          direction: TxDirection.outgoing,
          stage: TxStage.broadcast,
          amountNano: 500000000,
          feeNano: 25000000,
          counterparty: 'tgrin1anya',
          confirmationsNeeded: 10,
          created: DateTime(2026, 11, 10, 11, 2),
        ),
      ];

  @override
  Future<List<ContactInfo>> contacts() async => const <ContactInfo>[
        ContactInfo(id: 'tgrin1carol', name: 'Carol'),
      ];

  @override
  Future<void> autoAccept(String mode) async {}

  @override
  Future<String> showPhrase(String password) async {
    if (password != 'secret12') throw Exception('wrong password');
    return 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  }

  @override
  Future<void> changePassword(String oldPassword, String newPassword) async {}

  @override
  Future<void> renameWallet(String name) async {}

  @override
  Future<void> renameContact(String id, String name) async {}

  @override
  Future<void> torStart() async {}

  @override
  Future<TorStatusInfo> torStatus() async => const TorStatusInfo(running: false, pendingCount: 0);

  @override
  Future<List<PendingPayment>> torPending() async => const <PendingPayment>[];

  @override
  Future<PendingDecision> torDecide({
    required String slateId,
    required bool accept,
    bool addContact = true,
    String name = '',
  }) async =>
      PendingDecision(accepted: accept);

  @override
  Future<List<InboxItem>> torInbox() async => const <InboxItem>[];

  @override
  Future<ReceiveResult> receiveInbox(String inboxFile) async =>
      const ReceiveResult(txId: 'rx', answer: 'S2 ANSWER TEST', slatepack: 'S2 ANSWER TEST', amountNano: 0);

  @override
  Future<WalletJob> payInvoiceInboxJob(String inboxFile) async =>
      _job(<String, dynamic>{'tx_id': 'invoice-pay', 'answer': 'I2 ANSWER TEST'});

  @override
  Future<void> setExtraPeers(List<String> peers) async {}

  @override
  Future<void> setVerifyMode(String mode) async {
    verifyMode = mode;
  }

  @override
  Future<CheckpointInfo> checkpointInfo({String? network}) async => const CheckpointInfo(
        source: 'release',
        shippedExists: true,
        shippedHeight: 3332461,
        shippedHash: 'deadbeef',
        ownBuilt: false,
        offerSeen: false,
      );

  @override
  Future<WalletJob> ownCheckpointJob({String? network}) async => _job(<String, dynamic>{'height': 3332461, 'hash': 'deadbeef', 'matches': true});

  @override
  Future<void> setCheckpointSource(String source) async {}

  @override
  Future<void> markCheckpointOfferSeen() async {}

  WalletJob _job(Map<String, dynamic> result) {
    final String id = 'job${_next++}';
    _jobs[id] = result;
    return WalletJob(id: id, core: this);
  }

  @override
  Future<WalletJob> openJob() async {
    openCalls++;
    final WalletJob job = _job(<String, dynamic>{});
    if (slowOpen) {
      _gate = Completer<void>();
      _slowId = job.id;
    }
    return job;
  }

  @override
  Future<WalletJob> sendJob({required String to, required int amountNano}) async => _job(<String, dynamic>{
        'tx_id': 'tx-send',
        'slatepack': 'S1 SLATEPACK TEST',
        'fee': 25000000,
      });

  @override
  Future<WalletJob> finalizeJob({required String txId, required String answer}) async => _job(<String, dynamic>{'tx_id': txId});

  @override
  Future<WalletJob> broadcastJob(String txId) async => _job(<String, dynamic>{'tx_id': txId});

  @override
  Future<WalletJob> confirmJob(String txId) async => _job(<String, dynamic>{'tx_id': txId, 'state': 'in_block', 'height': 4100208, 'depth': 1});

  @override
  Future<WalletJob> payInvoiceJob(String slatepack) async => _job(<String, dynamic>{'tx_id': 'invoice-pay', 'answer': 'I2 ANSWER TEST'});

  @override
  Future<JobProgress> waitJob(String id, {void Function(JobProgress)? onProgress}) async {
    if (id == _slowId) {
      onProgress?.call(JobProgress(id: id, state: 'running', phase: 'Поиск узлов', lines: const <String>[]));
      await _gate!.future;
    }
    final JobProgress p = JobProgress(id: id, state: 'done', phase: 'done', lines: const <String>[], result: _jobs[id] ?? <String, dynamic>{});
    onProgress?.call(p);
    return p;
  }

  @override
  Future<void> cancelJob(String id) async {}

  @override
  Future<SendResult> send({required String to, required int amountNano}) async =>
      const SendResult(txId: 'tx-send', slatepack: 'S1 SLATEPACK TEST', feeNano: 25000000);

  @override
  Future<ReceiveResult> receive(String slatepack) async =>
      const ReceiveResult(txId: 'rx', answer: 'S2 ANSWER TEST', amountNano: 1000000000);

  @override
  Future<InvoiceResult> invoice({required int amountNano}) async =>
      const InvoiceResult(txId: 'inv', slatepack: 'I1 SLATEPACK TEST');

  @override
  Future<String> slatepack(String txId) async => 'SLATEPACK TEST';

  @override
  String describeError(Object error) => error.toString().replaceFirst('Exception: ', '');
}

