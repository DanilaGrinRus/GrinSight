import 'package:flutter/material.dart';

import 'wallet_model.dart';

/// Единый формат высоты блока: 4 100 208.
/// 2 знака после запятой для сумм на главной.
String shortAmount(String amount) {
  final List<String> parts = amount.split('.');
  if (parts.length != 2) return amount;
  final String whole = parts[0];
  final String fraction = parts[1].padRight(3, '0');
  final int thousandths = int.tryParse(fraction.substring(0, 3)) ?? 0;
  int cents = (thousandths + 5) ~/ 10;
  int wholeValue = int.tryParse(whole) ?? 0;
  if (cents == 100) {
    wholeValue += 1;
    cents = 0;
  }
  return '$wholeValue.${cents.toString().padLeft(2, '0')}';
}

/// Отображаемое имя сети: внутренний id floonet показываем как Testnet.
String networkLabel(String network) => network == 'floonet' ? 'Testnet' : 'Mainnet';

/// Единица монет: в тестовой сети — tGRIN.
String unitFor(String network) => network == 'floonet' ? 'tGRIN' : 'GRIN';

String formatHeight(int height) {
  final String digits = height.toString();
  final List<String> chunks = <String>[];
  for (int end = digits.length; end > 0; end -= 3) {
    final int start = end - 3 < 0 ? 0 : end - 3;
    chunks.insert(0, digits.substring(start, end));
  }
  return chunks.join(' ');
}

/// Локализация UI: RU/EN, без внешних зависимостей.
class S {
  const S(this.lang);

  final String lang;

  bool get en => lang == 'en';

  String _t(String ru, String en) => this.en ? en : ru;

  // Navigation / common
  String get login => _t('Войти', 'Sign in');
  String get options => _t('Опции', 'Options');
  String get back => _t('Назад', 'Back');
  String get done => _t('Готово', 'Done');
  String get close => _t('Закрыть', 'Close');
  String get continueLabel => _t('Продолжить', 'Continue');
  String get update => _t('Обновить', 'Update');
  String get copy => _t('Копировать', 'Copy');
  String get cancel => _t('Отмена', 'Cancel');
  String get show => _t('Показать', 'Show');
  String get change => _t('Сменить', 'Change');
  String get renameProfile => _t('Переименовать', 'Rename');
  String get configure => _t('Настроить', 'Configure');
  String get connect => _t('Подключиться', 'Connect');
  String get closeAction => _t('Закрыть', 'Close');
  String get demo => _t('демо', 'demo');

  // Launch
  String get lightWallet => _t('лёгкий кошелёк Grin', 'a light Grin wallet');
  String get checkpointStatus => _t('Чекпоинт ядра · проверяется при обновлении', 'Core checkpoint · verified on update');
  String get checkpointRevised => _t('Чекпоинт обновлён только что', 'Checkpoint updated just now');
  String get localKeysHint => _t('Ключи остаются на этом устройстве. Локальная нода не нужна.',
      'Keys stay on this device. No local node required.');
  String get prototypeDemo => _t('Исследовательский прототип · тестовая сеть', 'Research prototype · testnet');
  String get menuCheckpoint => _t('Обновить чекпоинт', 'Update checkpoint');
  String get menuCheckpointHint => _t('Проверить состояние сети вручную', 'Check network state manually');
  String get menuFuture => _t('Пощупать будущее', 'Try the future');
  String get menuFutureHint => _t('Экспериментальные функции и тестовые режимы', 'Experimental features and test modes');
  String get menuPeer => _t('Свой пир', 'Custom peer');
  String get menuPeerHint => _t('P2P-пир, порт 3414', 'P2P peer, port 3414');

  // Login
  String get loginTitle => _t('Вход', 'Sign in');
  String get loginSubtitle => _t('Откройте кошелёк, восстановите его по фразе или создайте новый.',
      'Unlock your wallet, restore it from a phrase, or create a new one.');
  String get profileAndNetwork => _t('Профиль и сеть', 'Profile & network');
  String get advanced => _t('Дополнительно', 'Advanced');
  String get networkHint => _t('Сеть выбирается при входе и не меняется в сессии.',
      'Network is chosen at sign-in and cannot change in a session.');
  String get modeOpen => _t('Открыть', 'Unlock');
  String get modeRestore => _t('Восстановить', 'Restore');
  String get modeCreate => _t('Создать', 'Create');
  String get profile => _t('Профиль', 'Profile');
  String get profileHint => _t('локальный профиль', 'local profile');
  String get loginLabel => _t('Логин', 'Login');
  String get loginHint => _t('например, alex', 'e.g. alex');
  String get password => _t('Пароль', 'Password');
  String get passwordHint => _t('••••••••', '••••••••');
  String get seedLabel => _t('Seed-фраза · 24 слова', 'Seed phrase · 24 words');
  String get seedHint => _t('24 слова через пробел', '24 words separated by spaces');
  String get seedCoreHint => _t('Фраза уходит сразу в ядро и сохраняется зашифрованной.',
      'The phrase goes straight to the core and is stored encrypted.');
  String get seedNotNeededHint => _t('Seed не нужен: ключи уже сохранены на устройстве.',
      'No seed needed: keys are already stored on this device.');
  String get openWallet => _t('Открыть кошелёк', 'Unlock wallet');
  String get restoreAction => _t('Восстановить', 'Restore');
  String get generatePhrase => _t('Сгенерировать фразу', 'Generate phrase');
  String get createWallet => _t('Создать кошелёк', 'Create wallet');
  String get phraseHiddenNote => _t('Слова скрыты. Введите № 7 и № 15, чтобы подтвердить, что фраза записана.',
      'The words are hidden. Enter #7 and #15 to confirm the phrase is saved.');
  String get savedPhrase => _t('Я записал(а) фразу', 'I wrote the phrase down');
  String get savedPhraseHint => _t('Слова не будут показаны снова', 'Words will not be shown again');
  String get word7 => _t('Слово № 7', 'Word #7');
  String get word15 => _t('Слово № 15', 'Word #15');
  String get phraseWarning => _t('Запишите 24 слова на бумаге. Без фразы кошелёк не восстановить.',
      'Write down 24 words on paper. Without them the wallet cannot be restored.');
  String get keysStayHint => _t('Ключи и seed не покидают устройство', 'Keys and seed never leave this device');
  String get enterLogin => _t('Введите логин', 'Enter login');
  String get enterPassword => _t('Введите пароль', 'Enter password');
  String get enterSeed => _t('Введите seed-фразу', 'Enter the seed phrase');
  String get seedNeeds24 => _t('Seed-фраза должна содержать 24 слова', 'The seed phrase must contain 24 words');
  String get confirmSavedPhrase => _t('Подтвердите, что фраза записана', 'Confirm that the phrase is saved');
  String get wordsMismatch => _t('Слова не совпадают — проверьте фразу', 'Words do not match — check the phrase');
  String get showSeed => _t('Показать', 'Show');
  String get hideSeed => _t('Скрыть', 'Hide');

  // Wallet header / balance
  String verifiedBlock(int block) => _t('Проверено: блок ${formatHeight(block)}', 'Verified: block ${formatHeight(block)}');
  String get verified => _t('Проверено', 'Verified');
  String get available => _t('Доступно', 'Available');
  String get spendableHint => _t('можно тратить', 'available to spend');
  String get confirmedLabel => _t('Подтверждено', 'Confirmed');
  String get reservedLabel => _t('Зарезервировано', 'Reserved');
  String get incomingLabel => _t('Входит', 'Incoming');
  String get confirmedHint => _t('подтверждено в цепи', 'confirmed on chain');
  String get paymentProof => _t('доказательство платежа', 'payment proof');
  String get immatureLabel => _t('Созревает', 'Immature');
  String get immatureHint => _t('ещё не доступно', 'not available yet');
  String get totalLabel => _t('Всего', 'Total');
  String get refreshAction => _t('Обновить', 'Refresh');
  String get notVerified => _t('Не проверено', 'Not verified');
  String get refreshNeeded => _t('Нужно обновить доказательство', 'Proof needs an update');
  String get staleProof => _t('Доказательство устарело', 'Proof is stale');
  String get reservedHint => _t('исходящие до блока · с комиссией', 'outgoing before a block · incl. fee');
  String get incomingHint => _t('не подтверждено', 'not confirmed');
  String get exactAmounts => _t('Точные суммы', 'Exact amounts');
  String get balance => _t('Баланс', 'Balance');
  String get proven => _t('Доказан', 'Proven');
  String outputsCount(int n) => _t('$n выхода · проверено локально', '$n outputs · verified locally');
  String peersSummary(int n) => _t('$n независимых пира · sync: DISTINCT_NETS_2', '$n independent peers · sync: DISTINCT_NETS_2');
  /// Человеческий возраст: 45 мин, 1 ч 5 мин, 2 д 3 ч.
  String formatAge(int seconds) {
    final int s = seconds < 0 ? 0 : seconds;
    if (s < 60) return _t('$s с', '${s}s');
    final int totalMinutes = (s / 60).round();
    if (totalMinutes < 60) return _t('$totalMinutes мин', '$totalMinutes min');
    final int totalHours = totalMinutes ~/ 60;
    final int minutes = totalMinutes % 60;
    if (totalHours < 24) {
      return minutes == 0 ? _t('$totalHours ч', '${totalHours}h') : _t('$totalHours ч $minutes мин', '${totalHours}h ${minutes}min');
    }
    final int days = totalHours ~/ 24;
    final int hours = totalHours % 24;
    return hours == 0 ? _t('$days д', '${days}d') : _t('$days д $hours ч', '${days}d ${hours}h');
  }

  String proofLine(int block, int peers, int seconds) {
    final String peerWord = peers == 1 ? _t('независимый пир', 'independent peer') : _t('независимых пира', 'independent peers');
    return _t('Доказан на проверенной вершине ${formatHeight(block)} · $peers $peerWord · ${formatAge(seconds)} назад',
        'Proven on the verified tip ${formatHeight(block)} · $peers $peerWord · ${formatAge(seconds)} ago');
  }
  String get technicalDetails => _t('Технические детали', 'Technical details');
  String get showTechnicalDetails => _t('Показать технические детали', 'Show technical details');
  String get hideTechnicalDetails => _t('Скрыть технические детали', 'Hide technical details');
  String get canonicalCaveat => _t(
      'Чекпоинт закреплён внешне по SHA-256; каноническая вершина не доказана.',
      'The checkpoint is pinned externally by SHA-256; the canonical tip is not proven.');
  String get peerIndependenceValue => _t('DISTINCT_NETS_2 · проверено sync', 'DISTINCT_NETS_2 · checked by sync');
  String get addressLabel => _t('Ваш адрес', 'Your address');
  String get keysStayOnDevice => _t('Адрес и ключи остаются на устройстве', 'Address and keys stay on this device');
  String get addressHint => _t('Slatepack-адрес для входящих · сформирован из seed',
      'Slatepack address for incoming payments · derived from seed');
  String get send => _t('Отправить', 'Send');
  String get receive => _t('Получить', 'Receive');
  String get historyTitle => _t('Операции', 'Activity');
  String get historySub => _t('статусы по проверенной цепи', 'statuses come from the verified chain');
  String get historyFootnote => '';
  String get historyEmpty => _t('Операций пока нет', 'No activity yet');
  String get messengerEntrySub => _t('Messenger · auto-accept: {mode}', 'Messenger · auto-accept: {mode}');

  // Tx
  String txTitle(TxDirection d) {
    switch (d) {
      case TxDirection.incoming:
        return _t('Получено', 'Received');
      case TxDirection.outgoing:
        return _t('Отправлено', 'Sent');
      case TxDirection.invoice:
        return _t('Счёт', 'Invoice');
    }
  }

  String txDirectionLabel(TxDirection direction) {
    switch (direction) {
      case TxDirection.incoming:
        return _t('Входящий', 'Incoming');
      case TxDirection.outgoing:
        return _t('Исходящий', 'Outgoing');
      case TxDirection.invoice:
        return _t('Счёт', 'Invoice');
    }
  }

  String feeLine(String fee) => _t('комиссия $fee', 'fee $fee');

  String txStatusLabel(TxStage stage, TxDirection direction, {int? block, int? confirmations}) {
    switch (stage) {
      case TxStage.waitingAnswer:
        return direction == TxDirection.incoming
            ? _t('ЖДЁМ ОТПРАВИТЕЛЯ', 'AWAITING SENDER')
            : _t('ЖДЁМ ПОЛУЧАТЕЛЯ', 'AWAITING RECIPIENT');
      case TxStage.broadcast:
        return _t('В СЕТИ', 'IN NETWORK');
      case TxStage.inBlock:
        return block == null ? _t('В БЛОКЕ', 'IN BLOCK') : _t('В БЛОКЕ ${formatHeight(block)}', 'IN BLOCK ${formatHeight(block)}');
      case TxStage.confirmed:
        return confirmations == null
            ? _t('ПОДТВЕРЖДЁН', 'CONFIRMED')
            : _t('ПОДТВЕРЖДЁН · $confirmations БЛОКОВ', 'CONFIRMED · $confirmations BLOCKS');
      case TxStage.reorged:
        return _t('БЛОК ОТМЕНЁН', 'BLOCK REVERTED');
      case TxStage.cancelled:
        return _t('ОТМЕНЁН', 'CANCELLED');
    }
  }

  String txNote(WalletTx tx) {
    switch (tx.stage) {
      case TxStage.waitingAnswer:
        return tx.incoming
            ? _t('ждём отправителя', 'waiting for the sender')
            : _t('получатель не ответил', 'recipient has not replied');
      case TxStage.broadcast:
        return _t('разослано, ждём блок', 'broadcast, waiting for a block');
      case TxStage.inBlock:
        return _t('в блоке, ждём подтверждений', 'in block, waiting for confirmations');
      case TxStage.confirmed:
        return _t('подтверждён', 'confirmed');
      case TxStage.reorged:
        return _t('блок отменён, ждём включения', 'block was reverted, awaiting inclusion');
      case TxStage.cancelled:
        return _t('отменён, входы освобождены', 'cancelled, inputs released');
    }
  }

  // Messenger
  String get messenger => _t('Мессенджер', 'Messenger');
  String get online => _t('на связи', 'online');
  String get torOffline => _t('не подключён', 'not connected');
  String get torStart => _t('Включить', 'Turn on');
  String get settingsWallet => _t('Настройки кошелька', 'Wallet settings');
  String get autoAccept => _t('Автоприём', 'Auto-accept');
  String get autoOff => _t('Выкл', 'Off');
  String get autoContacts => _t('Контакты', 'Contacts');
  String get autoAll => _t('Все', 'All');

  String autoAcceptValue(String mode) {
    switch (mode) {
      case 'all':
        return _t('все', 'all');
      case 'off':
        return _t('выкл', 'off');
      default:
        return _t('контакты', 'contacts');
    }
  }
  String get addressBook => _t('Адресная книга', 'Address book');
  String get recentMessages => _t('Последние сообщения', 'Recent messages');
  String get signature => _t('подпись', 'signature');
  String get signatureVerified => _t('подпись контакта проверена', 'contact signature verified');
  String get signatureMissing => _t('подпись не проверена', 'signature not verified');
  String get noFeed => _t('Сообщений и платежей пока нет.', 'No messages or payments yet.');
  String get feedNote => _t(
      'Платежи и сообщения хранятся локально. Платёжное доказательство привязано к kernel в доказанном kernel_root.',
      'Payments and messages are stored locally. The payment proof is tied to a kernel in the proven kernel_root.');

  // Service / jobs
  String get serviceUnavailable => _t('Сервис кошелька недоступен', 'Wallet service is unavailable');
  String get serviceStarting => _t('Запускаем ядро…', 'Starting the core…');
  String get loadingWallet => _t('Загружаем кошелёк…', 'Loading wallet…');
  String get passwordMin8 => _t('Пароль должен быть не короче 8 символов', 'Password must be at least 8 characters');
  String get chooseProfile => _t('Выберите профиль', 'Choose a profile');
  String get noProfiles => _t('Нет профилей. Создайте или восстановите кошелёк.', 'No profiles. Create or restore a wallet.');
  String get profilesLoading => _t('Ищем профили…', 'Looking for profiles…');
  String get jobCancel => _t('Отменить', 'Cancel');
  String get jobCancelled => _t('Операция отменена', 'Operation cancelled');
  String get jobDone => _t('Готово', 'Done');
  String get jobFailed => _t('Операция не удалась', 'Operation failed');
  String get phaseCheckpoint => _t('Контрольная точка', 'Checkpoint');
  String get phasePeers => _t('Пиры', 'Peers');
  String get phaseHeaders => _t('Заголовки', 'Headers');
  String get phaseBalance => _t('Доказанный баланс', 'Proven balance');
  String get noTransactions => _t('Операций пока нет', 'No activity yet');
  String get noContacts => _t('Контактов пока нет', 'No contacts yet');

  // Slatepack / invoice
  String get slatepack => _t('Slatepack', 'Slatepack');
  String get qrText => _t('Текст', 'Text');
  String get qrCode => _t('QR', 'QR');
  String qrPartOf(int i, int n) => _t('Часть $i из $n', 'Part $i of $n');
  String get qrPause => _t('Пауза', 'Pause');
  String get qrPlay => _t('Продолжить', 'Play');
  String get qrPrev => _t('Предыдущая часть', 'Previous part');
  String get qrNext => _t('Следующая часть', 'Next part');
  String get qrScan => _t('Сканировать', 'Scan');
  String get qrScanHint => _t('Наведите камеру на QR-код', 'Point the camera at the QR code');
  String qrCollected(int i, int n) => _t('Собрано $i из $n', 'Collected $i of $n');
  String get qrDamaged => _t('QR повреждён, отсканируйте ещё раз', 'QR is damaged; scan again');
  String get qrWrongType => _t('Это не slatepack и не адрес Grin', 'This is not a Grin slatepack or address');
  String get qrWrongNetwork => _t('Адрес другой сети', 'Address belongs to another network');
  String get qrNoCamera => _t('Камера доступна только на Android', 'Camera is available on Android only');
  String get copySlatepack => _t('Скопировать slatepack', 'Copy slatepack');
  String get copiedSlatepack => _t('Slatepack скопирован', 'Slatepack copied');
  String get answerLabel => _t('Ответ получателя (S2)', 'Recipient answer (S2)');
  String get finalizeAction => _t('Финализировать', 'Finalize');
  String get broadcastAction => _t('Разослать', 'Broadcast');
  String get confirmAction => _t('Проверить подтверждение', 'Check confirmation');
  String get receiveSlatepackLabel => _t('Входящий slatepack (S1)', 'Incoming slatepack (S1)');
  String get receiveAction => _t('Принять', 'Receive');
  String get receiveAnswerTitle => _t('Ответ для отправителя (S2)', 'Answer for the sender (S2)');
  String get invoiceAmount => _t('Сумма счёта', 'Invoice amount');
  String get createInvoice => _t('Создать счёт', 'Create invoice');
  String get payInvoice => _t('Оплатить счёт', 'Pay invoice');
  String get invoiceSlatepack => _t('Slatepack счёта', 'Invoice slatepack');

  // Send

  String get sendTitle => _t('Отправить', 'Send');
  String get reviewTitle => _t('Проверьте перевод', 'Review payment');
  String get sentTitle => _t('Отправлено', 'Sent');
  String get recipient => _t('Кому', 'To');
  String get recipientHint => _t('slatepack-адрес grin1…', 'slatepack address grin1…');
  String get amount => _t('Сумма', 'Amount');
  String get fee => _t('Комиссия', 'Fee');
  String get feeHint => _t('Сумма + комиссия; точную комиссию рассчитает ядро при отправке', 'Amount + fee; the core computes the exact fee when sending');
  String get delivery => _t('Доставка', 'Delivery');
  String get deliveryManual => _t('Вручную', 'Manual');
  String get deliveryTor => 'Tor';
  String get deliveryMail => 'Relay';
  String get deliveryManualHint => _t(
      'S1 slatepack будет скопирован — передайте его получателю любым каналом.',
      'S1 slatepack will be copied — deliver it to the recipient by any channel.');
  String deliveryAutoHint(String via) => _t(
      'Получатель ответит автоматически (S2) через $via.',
      'The recipient will reply automatically (S2) via $via.');
  String get s2Note => _t(
      'Grin — интерактивный протокол: получатель должен ответить (S2). Только после ответа транзакция финализируется и сможет попасть в блок.',
      'Grin is interactive: the recipient must reply (S2). Only after that the transaction is finalized and can be mined.');
  String get sentViaManual => _t('Slatepack S1 скопирован — передайте получателю. Ждём ответ S2.',
      'S1 slatepack copied — deliver it to the recipient. Waiting for S2.');
  String sentVia(String via) => _t('Передано через $via. Ждём ответ получателя (S2).',
      'Delivered via $via. Waiting for the recipient reply (S2).');
  String get pipelineSent => _t('Отправлено', 'Sent');
  String get pipelineSentSub => _t('S1 передан получателю', 'S1 delivered to the recipient');
  String get pipelineAwait => _t('Ждём ответ получателя', 'Waiting for recipient reply');
  String get pipelineAwaitSub => _t('получатель подписывает S2', 'recipient signs S2');
  String get pipelineFinalize => _t('Финализация', 'Finalization');
  String get pipelineFinalizeSub => _t('транзакция собрана и подписана', 'transaction assembled and signed');
  String get pipelineBlock => _t('В блоке', 'In block');
  String get pipelineBlockSub => _t('ждём включения и подтверждений', 'waiting for inclusion and confirmations');
  String get paymentProofNote => _t(
      'Подпись получателя приходит вместе с S2, поэтому платёжное доказательство есть уже после финализации. Блок нужен для подтверждения в сети.',
      'The recipient\'s signature arrives with S2, so the payment proof exists right after finalization. The block is needed for network confirmation.');

  // Receive
  String get receiveTitle => _t('Получить', 'Receive');
  String get receiveHint => _t('Отправьте этот адрес плательщику — подойдёт любой кошелёк Grin.',
      'Share this address with the payer — any Grin wallet works.');
  String get copyAddress => _t('Скопировать адрес', 'Copy address');
  String get receiveNote => _t('Платёж появится после подтверждения в сети.',
      'The payment will appear after network confirmation.');

  // Checkpoint
  String get checkpoint => _t('Чекпоинт', 'Checkpoint');
  String get checkpointNote => _t(
      'Чекпоинт ускоряет первый запуск: по нему проверяется состояние сети. Обновлять стоит редко.',
      'The checkpoint speeds up the first launch: the network state is verified against it. Update it rarely.');
  String get checkpointChecking => _t('Проверяем чекпоинт…', 'Checking checkpoint…');
  String get tenSeconds => _t('~10 секунд', '~10 seconds');
  String get checkpointUpdated => _t('Чекпоинт обновлён', 'Checkpoint updated');
  String get checkpointUpdatedMeta => _t('10 ноября · высота 4 100 379', 'Nov 10 · height 4 100 379');

  // Verification
  String get verificationTitle => _t('Доказательство баланса', 'Balance proof');
  String get verificationNote => _t(
      'Всё, что видно на главном, локально пересчитано по заголовкам. Ниже — те же строки, что печатает ядро.',
      'Everything on the main screen is recomputed locally from headers. Below are the same lines the core prints.');
  String get checkpointSection => _t('Контрольная точка', 'Checkpoint');
  String get checkpointShipped => _t('из поставки', 'from the build');
  String get checkpointOwn => _t('своя', 'own');
  String get checkpointCreate => _t('Создать свою', 'Build my own');
  String get checkpointContinue => _t('Продолжить', 'Resume');
  String get checkpointPause => _t('Пауза', 'Pause');
  String get checkpointSourceLabel => _t('Источник', 'Source');
  String get checkpointHeight => _t('высота', 'height');
  String get checkpointHash => _t('хеш', 'hash');
  String get checkpointNotBuilt => _t('своя ещё не создана', 'own is not built yet');
  String get checkpointPaused => _t('создание приостановлено, можно продолжить', 'paused; you can resume');
  String get checkpointMatches => _t('Своя точка совпадает с точкой из поставки', 'Own checkpoint matches the shipped one');
  String get checkpointMismatch => _t('Точка из поставки НЕ совпадает с проверенной вами цепочкой — не доверяйте этой поставке', 'The shipped checkpoint does NOT match the chain you verified — do not trust this build');
  String get checkpointOffer => _t('Хотите проверить всё с нуля? Создать свою контрольную точку', 'Want to verify everything from scratch? Build your own checkpoint');
  String get checkpointOfferLater => _t('Не сейчас', 'Not now');
  String get checkpointExplain => _t(
      'Кошелёк начинает с контрольной точки из поставки, подписанной разработчиками. Можно не доверять и ей: кошелёк проверит каждый заголовок с первого блока Grin. Это занимает от 30 минут; процесс можно прерывать и продолжать.',
      'The wallet starts from the checkpoint shipped by the developers. You may distrust it: the wallet can verify every header from the first Grin block. It takes 30+ minutes; the process can be paused and resumed.');

  String get verificationWarning => _t(
      'Каноническая вершина не доказана: доверие к checkpoint внешнее. Пиры подтверждают работу, но не независимость.',
      'The canonical tip is not proven: checkpoint trust is external. Peers confirm work, not independence.');

  // Settings
  String get settings => _t('Настройки', 'Settings');
  String get groupWallet => _t('Кошелёк', 'Wallet');
  String get groupMessenger => _t('Мессенджер', 'Messenger');
  String get groupNetwork => _t('Сеть', 'Network');
  String get groupSecurity => _t('Безопасность', 'Security');
  String get groupMore => _t('Ещё', 'More');
  String get profileOnDevice => _t('только на этом устройстве', 'this device only');
  String get network => _t('Сеть', 'Network');
  String networkHintWallet(String network) => _t('$network · выбирается только при входе',
      '$network · chosen at sign-in only');
  String get checkpointVerified => _t('10 ноября · проверен', 'Nov 10 · verified');
  String get deliveryHint => _t('Tor или Relay', 'Tor or Relay');
  String get relayHint => _t('Relay — если Tor недоступен', 'Relay — if Tor is unavailable');
  String get autoAcceptHint => _t('Когда принимать платежи', 'When to accept payments');
  String get peer => _t('Свой пир', 'Custom peer');
  String get peerHint => _t('Не подключён · порт 3414', 'Not connected · port 3414');
  String get passwordHintSettings => _t('Защищает вход на устройстве', 'Protects sign-in on this device');
  String get seedSettings => _t('Seed-фраза', 'Seed phrase');
  String get seedSettingsHint => _t('Сначала спросим пароль', 'Password required first');
  String get future => _t('Пощупать будущее', 'Try the future');
  String get futureHint => _t('Экспериментальные функции', 'Experimental features');
  String get logout => _t('Выход', 'Sign out');
  String get logoutHint => _t('Заблокировать кошелёк на этом устройстве', 'Lock the wallet on this device');
  String get logoutAction => _t('Выйти', 'Sign out');
  String get language => _t('Язык', 'Language');
  String get prototypeFooter => _t('GrinSight 0.1 · исследовательский прототип · не продукт',
      'GrinSight 0.1 · research prototype · not a product');
  String get changeLoginToast => _t('Переименование профиля недоступно в этой версии', 'Profile renaming is not available in this build');
  String get changePasswordToast => _t('Смена пароля недоступна в этой версии', 'Password change is not available in this build');
  String get seedHiddenToast => _t('Показ seed недоступен в этой версии', 'Seed display is not available in this build');
  String get futureOnToast => _t('Экспериментальный режим включён', 'Experimental mode enabled');
  String get futureOffToast => _t('Экспериментальный режим выключен', 'Experimental mode disabled');
  String get confirmPasswordTitle => _t('Подтвердите пароль', 'Confirm password');
  String get confirmPasswordNote => _t('Seed-фраза показывается только после ввода пароля.',
      'The seed phrase is shown only after entering the password.');

  // Future
  String get futureTitle => _t('Пощупать будущее', 'Try the future');
  String get futureNote => _t(
      'Экспериментальные функции и тестовые режимы. Не для реальных средств: правила могут меняться, балансы не гарантируются.',
      'Experimental features and test modes. Not for real funds: rules may change, balances are not guaranteed.');
  String get testnet => _t('Тестовая сеть', 'Test network');
  String get newProtocols => _t('Новые протоколы', 'New protocols');
  String get experimentalMode => _t('Экспериментальный режим', 'Experimental mode');
  String get experimentalModeHint => _t('В этом кошельке', 'In this wallet');
  String get experimentalModeNote => _t(
      'Обычные средства не затрагиваются. В прототипе переключатель только меняет состояние.',
      'Regular funds are untouched. In the prototype the switch only changes state.');

  // Peer
  String get peerTitle => _t('Свой пир', 'Custom peer');
  String get peerNote => _t(
      'Кошелёк общается с пирами по P2P (порт 3414) и проверяет данные сам. Нужен ещё как минимум один независимый пир — иначе независимость пиров не подтверждена.',
      'The wallet talks to peers over P2P (port 3414) and verifies data itself. At least one more independent peer is needed; otherwise peer independence is not confirmed.');
  String get peerAddress => _t('Адрес пира', 'Peer address');
  String get notConnected => _t('Не подключён', 'Not connected');
  String get peerFootnote => _t('Данные всё равно проверяются по заголовкам.', 'Data is still verified against headers.');
  String get peerRequired => _t('Укажите адрес пира', 'Enter the peer address');
  String get peerDemoToast => _t('Демо: подключение к пиру не выполняется', 'Demo: peer connection is not performed');
  String get peerSaved => _t('Пир добавлен в настройки профиля', 'Peer added to profile settings');

  // Contact feed
  String get feedClose => _t('Закрыть', 'Close');

  // Common toasts
  String get copiedAddress => _t('Адрес скопирован', 'Address copied');
  
  String get recipientRequired => _t('Укажите адрес получателя', 'Enter the recipient address');
  String get amountRequired => _t('Укажите сумму', 'Enter the amount');
  String get insufficientFunds => _t('Недостаточно средств с учётом комиссии', 'Insufficient funds including the fee');
  String get messengerTor => _t('Доставка через Tor (демо)', 'Delivery via Tor (demo)');
  String get messengerMail => _t('Доставка через Relay (демо)', 'Delivery via Relay (demo)');
}

/// Доступ к строкам и переключателю языка из любого места дерева, включая листы.
class AppLocale extends InheritedWidget {
  const AppLocale({
    super.key,
    required this.s,
    required this.lang,
    required this.onLangChanged,
    required super.child,
  });

  final S s;
  final String lang;
  final ValueChanged<String> onLangChanged;

  static AppLocale of(BuildContext context) {
    final AppLocale? result = context.dependOnInheritedWidgetOfExactType<AppLocale>();
    assert(result != null, 'AppLocale is missing above this widget');
    return result!;
  }

  @override
  bool updateShouldNotify(AppLocale oldWidget) => oldWidget.lang != lang;
}


