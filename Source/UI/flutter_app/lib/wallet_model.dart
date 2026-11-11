/// Модели кошелька GrinSight. Суммы — всегда nanogrin (int), 1 GRIN = 10^9.
library;

enum TxDirection { incoming, outgoing, invoice }

/// Этапы платежа Grin (slatepack): ответ другой стороны нужен до блока.
enum TxStage {
  /// S1/I1 отправлен, ждём ответа (S2/I2) или входящий ещё не в цепи.
  waitingAnswer,

  /// Ответ получен, транзакция финализирована и/или разослана пирам.
  broadcast,

  /// В блоке, подтверждений меньше порога.
  inBlock,

  /// Подтверждено (глубина >= confirmations_needed).
  confirmed,

  /// Блок подтверждения ушёл из цепочки (reorg).
  reorged,

  /// Отменён/освобождён.
  cancelled,
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

  bool get fresh => freshness.toUpperCase() == 'FRESH';
  bool get verified => hasSession && canSpend && fresh;
}

class WalletStatus {
  const WalletStatus({
    required this.profile,
    required this.network,
    required this.address,
    required this.balance,
    required this.proof,
    required this.torRunning,
  });

  final String profile;
  final String network;
  final String? address;
  final WalletBalance balance;
  final WalletProof proof;
  final bool torRunning;
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
  });

  final String txId;
  final String answer;
  final int amountNano;
  final String? from;
  final bool senderVerified;
}

class InvoiceResult {
  const InvoiceResult({required this.txId, required this.slatepack});
  final String txId;
  final String slatepack;
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
