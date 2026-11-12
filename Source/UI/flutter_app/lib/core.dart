import 'wallet_model.dart';

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

  Future<void> autoAccept(String mode);

  /// Seed-фраза открытого кошелька (только при верном пароле).
  Future<String> showPhrase(String password);

  Future<void> changePassword(String oldPassword, String newPassword);

  /// Переименовать открытый кошелёк (имя профиля на устройстве).
  Future<void> renameWallet(String name);

  /// Своё имя контакта (адрес не меняется; повторное `contacts.add` заменяет запись).
  Future<void> renameContact(String id, String name);

  /// Запустить Tor (если ядро собрано с Tor).
  Future<void> torStart();

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

  /// [network] — до входа (без кошелька); после входа берётся сеть кошелька.
  Future<CheckpointInfo> checkpointInfo({String? network});

  /// Создание своей контрольной точки от genesis; cancel = пауза (resume).
  Future<WalletJob> ownCheckpointJob({String? network});

  Future<void> setCheckpointSource(String source);

  Future<void> markCheckpointOfferSeen();

  /// Долгие операции ядра. Возвращают [WalletJob] — его можно отменить.
  Future<WalletJob> openJob();
  Future<WalletJob> sendJob({required String to, required int amountNano});
  Future<WalletJob> finalizeJob({required String txId, required String answer});
  Future<WalletJob> broadcastJob(String txId);
  Future<WalletJob> confirmJob(String txId);
  Future<WalletJob> payInvoiceJob(String slatepack);

  Future<JobProgress> waitJob(String id, {void Function(JobProgress)? onProgress});
  Future<void> cancelJob(String id);

  Future<SendResult> send({required String to, required int amountNano});
  Future<ReceiveResult> receive(String slatepack);
  Future<InvoiceResult> invoice({required int amountNano});
  Future<String> slatepack(String txId);

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
  });

  final String id;
  final String name;
  final String? messenger;
  final bool auto;
  final String? onion;
}
