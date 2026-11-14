import 'wallet_model.dart';

/// Optional device-secured unlock, bound to the exact encrypted vault bytes.
abstract interface class BoundWalletUnlock {
  Future<bool> isActiveProfile(String login, String network);
  Future<String> credentialDigest({required String login, required String network, required String password});
  Future<void> unlockBound({required String login, required String network, required String password, required String vaultDigest});
}

/// Одно slatepack-сообщение платежа: имя файла в папке платежа и текст.
class SlatepackFile {
  const SlatepackFile(this.file, this.text);
  final String file;
  final String text;
}

/// Необязательно: все slatepack-сообщения платежа (S1, S2, I1, I2…).
/// Если ядро этого не умеет (старый сервис, web), UI берёт одно через
/// [WalletCore.slatepack].
abstract interface class SlatepackHistoryApi {
  Future<List<SlatepackFile>> slatepacks(String txId);
}

/// Необязательно: остановка Tor (запуск — [WalletCore.torStart]).
abstract interface class TorControlApi {
  Future<void> torStop();
}

/// Граница с ядром кошелька.
///
/// В приложении — [RealWalletCore] поверх `grinsight-service` (JSON-RPC).
/// В виджет-тестах используется поддельная реализация; демо-данных на экранах нет.
abstract class WalletCore {
  /// Останавливает сервис (при выходе из приложения).
  Future<void> close();

  /// Профили из `service.info` — для выбора при входе.
  Future<List<WalletProfile>> profiles();

  /// Фраза нового кошелька из системного CSPRNG ядра.
  /// words: 12 | 18 | 24 (по умолчанию 24)
  Future<String> newPhrase({int words = 24});

  /// Проверка контрольной суммы/слов до restore.
  Future<void> checkPhrase(String phrase);

  Future<void> createWallet({
    required String login,
    required String phrase,
    required String password,
    required String network,
  });

  Future<void> importWallet({
    required String login,
    required String phrase,
    required String password,
    required String network,
  });

  Future<void> unlock({
    required String login,
    required String password,
    required String network,
  });

  Future<void> lock();

  Future<WalletStatus> status();

  Future<String> address();

  Future<List<WalletTx>> payments();

  Future<List<ContactInfo>> contacts();
  /// Add an unverified wallet contact without enabling automatic acceptance.
  Future<void> addContact(String address, String name);
  Future<Map<String, dynamic>> nostrSettings();
  Future<void> setNostrSettings({required String mode, required String url, required String proxy, required bool consent, required bool expiry, required int historyDays, bool? catalogueAutoPublish});
  Future<Map<String, dynamic>> chatNostrBinding();
  Future<void> chatNostrAdd(Map<String, dynamic> binding, String name);
  Future<Map<String, dynamic>> chatI2pBinding();
  Future<void> chatI2pAdd(Map<String, dynamic> binding, String name);
  Future<Map<String, dynamic>> chatInfo();
  Future<Map<String, dynamic>> chatStatus();
  Future<Map<String, dynamic>> chatQuarantineInvalidExport(String token);
  Future<void> chatQuarantineInvalidDiscard(String token);
  Future<Map<String, dynamic>> chatQuarantineList();
  Future<Map<String, dynamic>> chatQuarantineExport(String id, String digest);
  Future<void> chatQuarantineDiscard(String id, String digest, bool corrupt);
  Future<void> chatQuarantineCleanup();
  Future<Map<String, dynamic>> chatDeferredList();
  Future<void> chatDeferredRetry(String route);
  Future<void> chatDeferredDiscard(String id, String route);
  Future<Map<String, dynamic>> chatMessages([int after = 0]);
  Future<Map<String, dynamic>> chatSend(String to, String text);
  /// Saved incoming-payment policy, or null when the service cannot determine it.
  Future<String?> autoAcceptPolicy();

  Future<void> autoAccept(String mode);

  /// Seed-фраза открытого кошелька (только при верном пароле).
  Future<String> showPhrase(String password);

  Future<void> changePassword(String oldPassword, String newPassword);

  /// Отменить незавершённый исходящий платёж: его входы снова можно тратить
  /// (`wallet.release`). Ядро откажет, если платёж мог уже уйти в сеть.
  Future<void> cancelPayment(String txId);

  /// Переименовать открытый кошелёк (имя профиля на устройстве).
  Future<void> renameWallet(String name);

  /// Своё имя контакта (адрес не меняется; повторное `contacts.add` заменяет запись).
  Future<void> renameContact(String id, String name);

  /// Запустить Tor (если ядро собрано с Tor).
  Future<void> torStart();

  Future<Map<String, dynamic>> torBridgeSettings();
  Future<void> setTorBridgeSettings({required String mode, required String line, required String binary});

  /// Статус Tor: запущен ли и сколько платежей ждёт ручного решения.
  ///
  /// Опрашивается часто (2 с), пока [TorStatusInfo.pendingCount] > 0, иначе редко.
  Future<TorStatusInfo> torStatus();

  /// Входящие платежи, ожидающие решения пользователя (`tor.pending`).
  Future<List<PendingPayment>> torPending();

  /// Решение по входящему платежу (`tor.decide`).
  ///
  /// [addContact] — добавить отправителя в адресную книгу с автоприёмом;
  /// [name] — имя контакта. Для отказа оба поля не важны.
  Future<PendingDecision> torDecide({
    required String slateId,
    required bool accept,
    bool addContact = true,
    String name = '',
  });

  /// Входящие платежи и счета, сохранённые для ручного приёма (`tor.inbox`).
  Future<List<InboxItem>> torInbox();

  /// Принять платёж из входящих файлом (`wallet.receive` + `inbox_file`).
  /// Результат содержит S2 для ручной передачи отправителю.
  Future<ReceiveResult> receiveInbox(String inboxFile);

  /// Оплатить счёт из входящих файлом (`wallet.pay_invoice` + `inbox_file`).
  Future<WalletJob> payInvoiceInboxJob(String inboxFile);

  Future<void> setExtraPeers(List<String> peers);

  /// checkpoint | header_proof; persisted in the profile settings.
  Future<void> setVerifyMode(String mode);
  Future<String> getVerifyMode();

  /// [network] — до входа (без кошелька); после входа берётся сеть кошелька.
  Future<CheckpointInfo> checkpointInfo({String? network});

  /// Создание своей контрольной точки от genesis; cancel = пауза (resume).
  Future<WalletJob> ownCheckpointJob({String? network});

  Future<void> setCheckpointSource(String source);

  Future<void> markCheckpointOfferSeen();

  /// Долгие операции ядра. Возвращают [WalletJob] — его можно отменить.
  Future<WalletJob> openJob();
  Future<WalletJob> sendJob({required String to, required int amountNano, Map<String, String>? backupIntent});

  /// Queue an already-created payment for asynchronous Tor delivery.
  /// A successful return confirms queuing, not delivery or confirmation.
  Future<void> deliverTor(String txId);

  /// Current backup channel and verified contacts. No direct-route fallback.
  Future<Map<String, dynamic>> backupPaymentContacts();
  Future<void> deliverBackup(String txId, {required String peer, required String mode, required String route});
  Future<void> validateBackupInboxInvoice(String file);
  Future<void> deliverBackupInboxInvoice(String file, String txId);
  Future<Map<String, dynamic>> backupPaymentRetryInfo(String txId);
  Future<void> retryBackupPayment(String txId);
  Future<WalletJob> finalizeJob({required String txId, required String answer});
  Future<WalletJob> broadcastJob(String txId);
  Future<WalletJob> confirmJob(String txId);
  Future<WalletJob> payInvoiceJob(String slatepack);

  Future<JobProgress> waitJob(String id, {void Function(JobProgress)? onProgress});
  Future<void> cancelJob(String id);

  Future<SendResult> send({required String to, required int amountNano});
  Future<ReceiveResult> receive(String slatepack);
  Future<InvoiceResult> invoice({required int amountNano, String? payer, Map<String, String>? backupIntent});
  Future<String> slatepack(String txId);
  Future<void> hideCancelled(String txId);

  /// Подмигивает ошибке сервиса понятным текстом; UI показывает message.
  String describeError(Object error);
}

/// Задача ядра: открытие, отправка, финализация, подтверждение, счёт.
class WalletJob {
  WalletJob({required this.id, required this.core});

  final String id;
  final WalletCore core;

  Future<Map<String, dynamic>> wait({void Function(JobProgress)? onProgress}) async {
    final JobProgress progress = await core.waitJob(id, onProgress: onProgress);
    if (!progress.done) {
      throw Exception(progress.error == null || progress.error!.isEmpty ? progress.state : progress.error!);
    }
    final Object? result = progress.result;
    if (result is Map<String, dynamic>) return result;
    if (result is Map) return result.cast<String, dynamic>();
    return <String, dynamic>{};
  }

  Future<void> cancel() => core.cancelJob(id);
}

class ContactInfo {
  const ContactInfo({
    required this.id,
    required this.name,
    this.messenger,
    this.auto = true,
    this.onion,
    this.identityChecked = false,
  });

  final String id;
  final String name;
  final String? messenger;
  final bool auto;
  final String? onion;
  /// The user compared the full pinned profile with the current contact.
  final bool identityChecked;
}

/// Optional notice after a wallet was created successfully but its messaging
/// service did not initialize. The vault remains usable.
abstract interface class WalletInitializationWarnings {
  String? takeWalletInitializationWarning();
}
