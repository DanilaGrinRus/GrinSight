/// Модели кошелька GrinSight. Суммы — всегда nanogrin (int), 1 GRIN = 10^9.
library;

enum TxDirection { incoming, outgoing, invoice }

/// Этапы платежа Grin (slatepack): ответ другой стороны нужен до блока.
enum TxStage {
  /// S1/I1 отправлен, ждём ответа (S2/I2) или входящий ещё не в цепи.
  waitingAnswer,

  /// Транзакция готова, но успешная рассылка не подтверждена.
  finalized,

  /// Транзакция разослана пирам.
  broadcast,

  /// В блоке, подтверждений меньше порога.
  inBlock,

  /// Подтверждено (глубина >= confirmations_needed).
  confirmed,

  /// Блок подтверждения ушёл из цепочки (reorg).
  reorged,

  /// Отменён/освобождён.
  cancelled,

  /// Блок платежа ещё не перепроверен на текущей проверенной цепочке
  /// (после обновления станет «в блоке» / «подтверждён» / «блок отменён»).
  unknown,
}

String nanoToGrin(int nano) {
  final String whole = (nano ~/ 1000000000).toString();
  String frac = (nano % 1000000000).toString().padLeft(9, '0').replaceFirst(RegExp(r'0+$'), '');
  if (frac.isEmpty) frac = '0';
  return '$whole.$frac';
}

/// 2 знака после запятой для компактных сумм (округление вверх по thousandths).
/// 2 знака после запятой без округления вверх: 0.999 -> 0.99 (не больше, чем есть).
String shortGrin(int nano) {
  final int whole = nano ~/ 1000000000;
  final int cents = ((nano % 1000000000) ~/ 10000000);
  return '$whole.${cents.toString().padLeft(2, '0')}';
}

/// "1.5" -> 1500000000. Никаких double.
int grinToNano(String grin) {
  final String t = grin.trim().replaceAll(',', '.').replaceAll(' ', '');
  final RegExp ok = RegExp(r'^\d+(\.\d{1,9})?$');
  if (!ok.hasMatch(t)) throw const FormatException('amount: up to 9 decimals');
  final List<String> p = t.split('.');
  final String frac = (p.length > 1 ? p[1] : '').padRight(9, '0');
  return int.parse(p[0]) * 1000000000 + int.parse(frac);
}

/// Стадия платежа из `wallet.payments` сервиса.
TxStage txStageFromService(String stage) {
  switch (stage) {
    case 'waiting_answer':
    case 'waiting_sender':
    case 'waiting_payer':
    case 'waiting_issuer':
    case 'building':
      return TxStage.waitingAnswer;
    case 'finalized':
      return TxStage.finalized;
    case 'broadcast':
      return TxStage.broadcast;
    case 'in_block':
      return TxStage.inBlock;
    case 'confirmed':
      return TxStage.confirmed;
    case 'reorged':
      return TxStage.reorged;
    case 'cancelled':
      return TxStage.cancelled;
    case 'unknown':
      return TxStage.unknown;
    default:
      return TxStage.waitingAnswer;
  }
}

class WalletProfile {
  const WalletProfile({required this.name, required this.network, required this.installed, this.lastUsed = 0});
  final String name;
  final String network;
  final bool installed;
  final int lastUsed;
}

class WalletBalance {
  const WalletBalance({
    required this.availableNano,
    required this.reservedNano,
    required this.incomingNano,
    required this.immatureNano,
    required this.totalNano,
    required this.tipHeight,
    required this.unspentOutputs,
  });

  final int availableNano;
  final int reservedNano;
  final int incomingNano;
  final int immatureNano;
  final int totalNano;
  final int tipHeight;
  final int unspentOutputs;

  bool get hasImmature => immatureNano > 0;
}

class WalletProof {
  const WalletProof({
    this.tipHeight,
    this.tipAgeSeconds,
    this.freshness = 'UNKNOWN',
    this.canSpend = false,
    this.hasSession = false,
    this.independentNets = 0,
    this.peerIndependence,
    this.currentTipState,
    this.canonicalTip,
    this.chainSupport,
    this.syncStatus,
    this.balanceAuthentication,
    this.openedAt,
    this.sessionPath,
    this.proofVerdict,
    this.balanceOk = true,
    this.balanceProblem,
  });

  final int? tipHeight;
  final int? tipAgeSeconds;
  final String freshness;
  final bool canSpend;
  final bool hasSession;
  final int independentNets;
  final String? peerIndependence;
  final String? currentTipState;
  final String? canonicalTip;
  final String? chainSupport;
  final String? syncStatus;
  final String? balanceAuthentication;
  final DateTime? openedAt;
  final String? sessionPath;
  final String? proofVerdict;

  /// Файл баланса подписан (MAC) seed-фразой этого кошелька и описывает ту же
  /// вершину, что и сессия доказательства. Иначе баланс нельзя показывать как доказанный.
  final bool balanceOk;
  final String? balanceProblem;

  bool get fresh => freshness.toUpperCase() == 'FRESH';
  bool get verified => hasSession && canSpend && fresh && balanceOk;
}

class WalletStatus {
  const WalletStatus({
    required this.profile,
    required this.network,
    required this.address,
    required this.balance,
    required this.proof,
    required this.torRunning,
    this.verifyMode = 'checkpoint',
  });

  final String profile;
  final String network;
  final String? address;
  final WalletBalance balance;
  final WalletProof proof;
  final bool torRunning;
  final String verifyMode;
  bool get headerProof => verifyMode == 'header_proof';
}

class WalletTx {
  const WalletTx({
    required this.txId,
    required this.direction,
    required this.stage,
    required this.amountNano,
    required this.counterparty,
    required this.confirmationsNeeded,
    this.feeNano,
    this.height,
    this.confirmations = 0,
    this.created,
    this.cancelled = false,
    this.proof = false,
    this.kind = '',
    this.torStatus,
    this.backupRetry = false,
  });

  final String txId;
  final TxDirection direction;
  final TxStage stage;
  final int amountNano;
  final int? feeNano;
  final String counterparty;
  final int? height;
  final int confirmations;
  final int confirmationsNeeded;
  final DateTime? created;
  final bool cancelled;
  final bool proof;
  /// Original service kind, retained to distinguish issued invoices from receives.
  final String kind;
  final String? torStatus;
  /// Saved route and original slatepack are intact; final authority remains the daemon.
  final bool backupRetry;

  bool get incoming => direction == TxDirection.incoming;
}

class SendResult {
  const SendResult({required this.txId, required this.slatepack, this.feeNano});
  final String txId;
  final String slatepack;
  final int? feeNano;
}

class ReceiveResult {
  const ReceiveResult({
    required this.txId,
    required this.answer,
    required this.amountNano,
    this.from,
    this.senderVerified = false,
    this.slatepack = '',
    this.deliveryQueued,
    this.deliveryError,
  });

  final String txId;
  final String answer;
  final int amountNano;
  final String? from;
  final bool senderVerified;
  final bool? deliveryQueued;
  final String? deliveryError;

  /// S2-слейтпак для ручной передачи отправителю. У `wallet.receive` с
  /// `inbox_file` ядро отдаёт его отдельным полем; иначе он же лежит в [answer].
  final String slatepack;

  /// Ответ для показа: S2 из `slatepack`, а если его нет — [answer].
  String get handoverSlatepack => slatepack.isNotEmpty ? slatepack : answer;
}

/// Статус Tor из `tor.status`: нужен, чтобы опрашивать входящие и показывать
/// счётчик платежей, ожидающих ручного решения.
enum TorPhase { stopped, starting, onionStarted, failed, unknown }

class TorStatusInfo {
  const TorStatusInfo({
    required this.running,
    this.phase = TorPhase.unknown,
    this.pendingCount = 0,
    this.foreignAddress,
    this.foreignOnion,
  });

  final bool running;
  /// The daemon's reported phase; it does not prove external reachability.
  final TorPhase phase;

  static TorPhase phaseFromService(bool running, Object? status) {
    if (!running) return TorPhase.stopped;
    if (status is! String) return TorPhase.unknown;
    if (status == 'starting') return TorPhase.starting;
    if (status == 'ready') return TorPhase.onionStarted;
    if (status.startsWith('failed:')) return TorPhase.failed;
    return TorPhase.unknown;
  }

  /// Сколько платежей ждёт решения пользователя.
  final int pendingCount;

  /// Slatepack-адрес (grin1…/tgrin1…), на который grin-wallet и Grin++ шлют
  /// Tor-платежи. Тот же адрес, что показывает экран «Получить».
  final String? foreignAddress;

  /// Onion Foreign API, куда ходят grin-wallet и Grin++.
  final String? foreignOnion;
}

/// Входящий платёж, ожидающий решения пользователя (`tor.pending`).
class PendingPayment {
  const PendingPayment({
    required this.slateId,
    required this.amountNano,
    required this.channel,
    this.feeNano,
    this.from,
    this.messengerPeer,
    this.expiresInSeconds = 0,
    this.waiting = false,
  });

  final String slateId;
  final int amountNano;
  final int? feeNano;

  /// Заявленный адрес отправителя; null — отправитель неизвестен.
  final String? from;

  /// Verified messenger key; distinct from the claimed wallet address.
  final String? messengerPeer;

  /// `tor-foreign` (grin-wallet / Grin++ по Tor) или `messenger` (GlauxNet).
  final String channel;

  /// Сколько секунд отправитель ещё ждёт ответа (0 — не удерживается).
  final int expiresInSeconds;

  /// Запрос удерживается до решения: grin-wallet ждёт S2 в этом же ответе.
  final bool waiting;

  bool get overMessenger => channel == 'messenger';

  /// Пришёл по Foreign API: отправитель grin-wallet / Grin++. Адрес в этом
  /// случае только заявлен (`proof.saddr`), а не подтверждён подписью.
  bool get overForeignApi => !overMessenger;
}

/// Результат `tor.decide`.
class PendingDecision {
  const PendingDecision({
    required this.accepted,
    this.answeredOverTor = false,
    this.contactAdded = false,
  });

  final bool accepted;

  /// Ответ (S2) ушёл тому же отправителю по Tor в удержанном запросе.
  final bool answeredOverTor;

  /// Отправитель добавлен в адресную книгу.
  final bool contactAdded;
}

/// Входящие (`tor.inbox`): платёж или счёт, сохранённый для ручного приёма.
class InboxItem {
  const InboxItem({
    required this.file,
    required this.kind,
    this.amountNano,
    this.feeNano,
    this.from,
    this.receivedAt,
    this.transportMode,
  });

  /// Имя файла во входящих (передаётся в `wallet.receive`/`wallet.pay_invoice`).
  final String file;

  /// `payment` — платёж (S1), `invoice` — счёт (I1).
  final String kind;
  final int? amountNano;
  final int? feeNano;
  final String? from;
  final DateTime? receivedAt;
  final String? transportMode;
  bool get viaBackup => const {'i2p_direct', 'nostr_i2p', 'nostr_direct'}.contains(transportMode);

  bool get isPayment => kind == 'payment';
  bool get isInvoice => kind == 'invoice';
}

class InvoiceResult {
  const InvoiceResult({required this.txId, required this.slatepack, this.backupIntentError});
  final String txId;
  final String slatepack;
  final String? backupIntentError;
}

class ConfirmResult {
  const ConfirmResult({required this.state, this.height, this.depth});
  final String state;
  final int? height;
  final int? depth;
}

class CheckpointInfo {
  const CheckpointInfo({
    required this.source,
    required this.shippedExists,
    this.shippedHeight,
    this.shippedHash,
    this.ownBuilt = false,
    this.ownPaused = false,
    this.ownHeight,
    this.ownHash,
    this.matches,
    this.offerSeen = false,
  });

  final String source;
  final bool shippedExists;
  final int? shippedHeight;
  final String? shippedHash;
  final bool ownBuilt;
  final bool ownPaused;
  final int? ownHeight;
  final String? ownHash;

  /// null = not compared; false = own chain does NOT contain shipped checkpoint.
  final bool? matches;
  final bool offerSeen;
}

class JobProgress {
  const JobProgress({
    required this.id,
    required this.state,
    required this.phase,
    required this.lines,
    this.result,
    this.error,
  });

  final String id;
  final String state;
  final String phase;
  final List<String> lines;
  final Object? result;
  final String? error;

  bool get running => state == 'running';
  bool get done => state == 'done';
  bool get failed => state == 'failed';
  bool get cancelled => state == 'cancelled';
}
