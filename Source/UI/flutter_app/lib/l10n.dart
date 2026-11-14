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

/// Сумма для диалога входящего платежа: ровно 6 знаков после запятой,
/// тысячи разделяются пробелом — как высота блока в [formatHeight].
String formatGrin6(int nano) {
  final int safe = nano < 0 ? 0 : nano;
  final String whole = formatHeight(safe ~/ 1000000000);
  final String frac = (safe % 1000000000).toString().padLeft(9, '0').substring(0, 6);
  return '$whole.$frac';
}

/// Короткий адрес для компактных подписей: grin1abc…wxyz.
String shortAddress(String value) {
  if (value.length <= 18) return value;
  return '${value.substring(0, 8)}…${value.substring(value.length - 6)}';
}

/// Адрес кошелька (grin1…/tgrin1…), а не slatepack: одно слово без пробелов.
bool looksLikeAddress(String text) {
  final String v = text.trim().toLowerCase();
  return (v.startsWith('grin1') || v.startsWith('tgrin1')) && !v.contains(RegExp(r'\s')) && v.length < 120;
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
  String get continueLabel => _t('Продолжить', 'Continue');
  String get update => _t('Обновить', 'Update');
  String get copy => _t('Копировать', 'Copy');
  String get cancel => _t('Отмена', 'Cancel');
  String get quitTitle => _t('Выйти из GrinSight?', 'Quit GrinSight?');
  String get quitBody => _t(
      'Выход остановит сервис кошелька и Tor. Ящик GlauxNet станет недоступен, пока приложение снова не откроют.',
      'Quitting stops the wallet service and Tor. The GlauxNet inbox goes offline until the app is opened again.');
  String get quitAction => _t('Выйти', 'Quit');
  String get show => _t('Показать', 'Show');
  String get change => _t('Сменить', 'Change');
  String get renameProfile => _t('Переименовать', 'Rename');
  String get configure => _t('Настроить', 'Configure');
  String get connect => _t('Подключиться', 'Connect');
  String get closeAction => _t('Закрыть', 'Close');
  String get demo => _t('демо', 'demo');

  // Launch
  String get lightWallet => _t('Медвежьи поделки', 'Bear crafts');
  String get checkpointStatus => _t('Чекпоинт ядра · проверяется при обновлении', 'Core checkpoint · verified on update');
  String get checkpointRevised => _t('Чекпоинт обновлён только что', 'Checkpoint updated just now');
  String get localKeysHint => _t('Ключи остаются на этом устройстве. Локальная нода не нужна.',
      'Keys stay on this device. No local node required.');
  String get prototypeDemo => _t('GrinSight 0.4.2 · Кошелёк для людей (2026)', 'GrinSight 0.4.2 · A wallet for people (2026)');
  String get menuCheckpoint => _t('Обновить чекпоинт', 'Update checkpoint');
  String get menuCheckpointHint => _t('Проверить состояние сети вручную', 'Check network state manually');
  String get menuFuture => _t('Пощупать будущее', 'Try the future');
  String get menuFutureHint => _t('Экспериментальные функции и тестовые режимы', 'Experimental features and test modes');
  String get menuPeer => _t('Свой пир', 'Custom peer');
  String get menuPeerHint => _t('P2P-пир, порт 3414', 'P2P peer, port 3414');
  String get futureOffHint => _t('Выкл · проверка по чекпоинту', 'Off · checkpoint verification');
  String get futureOnHint => _t('Вкл · экспериментальная настройка; баланс проверяется по чекпоинту', 'On · experimental setting; balance is checked from the checkpoint');
  String get checkpointBundledOk => _t('Чекпоинт из приложения · проверен', 'Bundled checkpoint · verified');

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
  String get loginLabel => _t('Название кошелька', 'Wallet name');
  String get loginHint => _t('например, alex', 'e.g. alex');
  String get password => _t('Пароль', 'Password');
  String get passwordHint => _t('••••••••', '••••••••');
  String get seedLabel => _t('Seed-фраза · 12, 18 или 24 слова', 'Seed phrase · 12, 18 or 24 words');
  String get seedHint => _t('Слова через пробел', 'Words separated by spaces');
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
  String get phraseLength => _t('Длина фразы', 'Phrase length');
  String get phraseLengthHint => _t('24 слова надёжнее, 12 проще записать. Фраза работает в других кошельках Grin.',
      '24 words are stronger, 12 are easier to write down. The phrase works in other Grin wallets.');
  String phraseCheckNote(int a, int b) => _t('Слова скрыты. Введите № $a и № $b, чтобы подтвердить, что фраза записана.',
      'Words are hidden. Enter #$a and #$b to confirm the phrase is written down.');
  String wordNo(int n) => _t('Слово № $n', 'Word #$n');
  String get word7 => _t('Слово № 7', 'Word #7');
  String get word15 => _t('Слово № 15', 'Word #15');
  String get phraseWarning => _t('Запишите 24 слова на бумаге. Без фразы кошелёк не восстановить.',
      'Write down 24 words on paper. Without them the wallet cannot be restored.');
  String get keysStayHint => _t('Ключи и seed не покидают устройство', 'Keys and seed never leave this device');
  String get enterLogin => _t('Введите название кошелька', 'Enter a wallet name');
  String get enterPassword => _t('Введите пароль', 'Enter password');
  String get enterSeed => _t('Введите seed-фразу', 'Enter the seed phrase');
  String get seedNeeds24 => _t('Seed-фраза: 12, 18 или 24 слова', 'The seed phrase has 12, 18 or 24 words');
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
  String peersSummary(int n) => _t('Сетей /16: $n · sync: DISTINCT_NETS_2', '/16 networks: $n · sync: DISTINCT_NETS_2');
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

  String proofLine(int block, int networks, int seconds) {
    // Неразрывные пробелы: «сетей /16: 4» и «2 ч 15 мин назад» не рвутся
    // посередине при переносе строки.
    const String nb = '\u00A0';
    final String count = (networks > 0 ? _t('сетей /16: $networks', '/16 networks: $networks') : _t('число сетей неизвестно', 'network count unknown')).replaceAll(' ', nb);
    final String age = formatAge(seconds).replaceAll(' ', nb);
    return _t('Доказан на проверенной вершине ${formatHeight(block)} · $count · $age$nbназад',
        'Proven on the verified tip ${formatHeight(block)} · $count · $age${nb}ago');
  }
  String get technicalDetails => _t('Технические детали', 'Technical details');
  String get showTechnicalDetails => _t('Показать технические детали', 'Show technical details');
  String get hideTechnicalDetails => _t('Скрыть технические детали', 'Hide technical details');
  String get canonicalCaveat => _t(
      'Заголовки после контрольной точки проверяются по PoW. Разные сети /16 не доказывают независимость пиров или каноничность вершины.',
      'Headers after the checkpoint are checked by PoW. Different /16 networks do not prove peer independence or a canonical tip.');
  String get peerIndependenceValue => _t('DISTINCT_NETS_2 · проверено sync', 'DISTINCT_NETS_2 · checked by sync');
  String get addressLabel => _t('Ваш адрес', 'Your address');
  String get keysStayOnDevice => _t('Адрес и ключи остаются на устройстве', 'Address and keys stay on this device');
  String get addressHint => _t('Slatepack-адрес для входящих · сформирован из seed',
      'Slatepack address for incoming payments · derived from seed');
  String get send => _t('Отправить', 'Send');
  String get receive => _t('Получить', 'Receive');
  String get historyTitle => _t('Операции', 'Activity');
  String get walletTab => _t('Кошелёк', 'Wallet');
  String get allLink => _t('Все', 'All');
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
      case TxStage.finalized:
        return _t('ГОТОВ К РАССЫЛКЕ', 'READY TO BROADCAST');
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
      case TxStage.unknown:
        return _t('НЕ ПЕРЕПРОВЕРЕН', 'NOT RE-CHECKED');
    }
  }

  String txNote(WalletTx tx) {
    switch (tx.stage) {
      case TxStage.waitingAnswer:
        return tx.incoming
            ? _t('ждём отправителя', 'waiting for the sender')
            : _t('получатель не ответил', 'recipient has not replied');
      case TxStage.finalized:
        return _t('транзакция создана, рассылка не подтверждена', 'transaction created; broadcast not confirmed');
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
      case TxStage.unknown:
        return _t('блок не перепроверен на текущей цепочке: обновите', 'block not re-checked on the current chain: refresh');
    }
  }

  // Messenger
  String get messenger => _t('Мессенджер', 'Messenger');
  String get torStatusUnknown => _t('Tor: статус неизвестен', 'Tor: status unknown');
  String get torStatusStopped => _t('Tor: не запущен', 'Tor: not running');
  // «Процесс запущен» и «подключён к сети» — разные состояния: процесс может
  // работать, но так и не достучаться до сети Tor (блокировка — нужны мосты).
  String get torStatusStarting => _t('Tor: процесс запущен, подключение к сети…', 'Tor: process running, connecting to the network…');
  String get torStatusOnionStarted => _t('Tor: подключён к сети', 'Tor: connected to the network');
  String get torStatusFailed => _t('Tor: не удалось подключиться к сети', 'Tor: could not connect to the network');
  String get torProcessUnconfirmed => _t('Tor: процесс запущен, связь с сетью не подтверждена', 'Tor: process running, network connection not confirmed');
  String get torBridges => _t('Настройки мостов', 'Bridge settings');
  String get torBridgesDelivery => _t('Настроить мосты Tor', 'Configure Tor bridges');
  String get messengerOff => _t('Выключить мессенджер', 'Turn messenger off');
  String get messengerOn => _t('Включить мессенджер', 'Turn messenger on');
  String get messengerIsOff => _t('Мессенджер выключен', 'Messenger is off');
  String get messengerOffHint => _t('Контакты и переписка скрыты. Tor включается отдельно — он нужен и для платежей.', 'Contacts and conversations are hidden. Tor is controlled separately — payments use it too.');
  String get messagesTitle => _t('Сообщения', 'Messages');
  String get messagesEmpty => _t('Сообщений пока нет', 'No messages yet');
  String get messageChannel => _t('Канал сообщений', 'Message channel');
  String get lastSlatepacks => _t('Slatepack последнего платежа', 'Slatepacks of the last payment');
  String get noSlatepacks => _t('У последнего платежа нет slatepack', 'The last payment has no slatepack');
  String get noPaymentsYet => _t('Платежей пока нет', 'No payments yet');
  String get serviceUnreachable => _t('Служба кошелька не отвечает. Перезапустите приложение; если повторится — пришлите журнал service.', 'The wallet service is not responding. Restart the app; if it happens again, send the service log.');
  String get torStatusDetail => _t('Состояние локального Tor. Доступность для собеседника не проверена.', 'Local Tor state. Remote reachability has not been verified.');
  String get online => _t('процесс Tor запущен', 'Tor process running');
  String get torOffline => _t('не подключён', 'not connected');
  String get torStart => _t('Включить', 'Turn on');
  String get glauxPhoneNote => _t(
      'На телефоне ящик работает, пока GrinSight открыт.',
      'On a phone the inbox works while GrinSight is open.');
  String get settingsWallet => _t('Настройки кошелька', 'Wallet settings');
  String get autoAccept => _t('Автоприём', 'Auto-accept');
  String get autoEnable => _t('Включить', 'Enable');
  String get autoDisable => _t('Выключить', 'Disable');
  String get autoAcceptUnknown => _t('Неизвестно', 'Unknown');
  String get autoAsk => _t('Спрашивать о новых', 'Ask about new');
  String get autoOff => _t('Выключен', 'Off');
  String get autoContacts => _t('Только контакты', 'Contacts only');
  String get autoAll => _t('Все', 'All');

  /// Четыре режима автоприёма в порядке UI: ask, contacts, all, off.
  List<String> get autoAcceptOptions => <String>[autoAsk, autoContacts, autoAll, autoOff];

  /// Значение режима для подписи на карточке мессенджера (строчными).
  String autoAcceptValue(String mode) {
    switch (mode) {
      case 'ask':
        return _t('спрашивать о новых', 'ask about new');
      case 'all':
        return _t('все', 'all');
      case 'off':
        return _t('выключен', 'off');
      default:
        return _t('только контакты', 'contacts only');
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

  // Tor: входящий платёж от незнакомого отправителя ждёт ручного «Да»
  String incomingPaymentTitle(String amount) => _t('Входящий платёж $amount', 'Incoming payment $amount');
  String incomingPaymentFrom(String shortAddress) => _t('от $shortAddress', 'from $shortAddress');
  String get sourceClaimed => _t(
      'Адрес указан отправителем и не подтверждён. Такие Tor-переводы требуют ручного решения.',
      'The sender-provided address is not verified. Such Tor payments require a manual decision.');
  String get sourceSigned => _t('Ключ мессенджера подтверждён подписью; указанный адрес кошелька отдельно не проверен.', 'The messenger key is verified by signature; the stated wallet address is not separately verified.');
  String get senderUnknown => _t(
      'Адрес отправителя неизвестен: добавить в адресную книгу нельзя.',
      'The sender address is unknown, so it cannot be added to the address book.');
  String get contactNameLabel => _t('Имя контакта', 'Contact name');
  String get contactNameHint => _t('необязательно', 'optional');
  String get addContactAndAuto => _t('Сохранить в адресную книгу', 'Save to address book');
  String get addContactAndAutoHint => _t(
      'Ключ мессенджера подтверждён подписью; адрес кошелька отдельно не проверен. Автоматический приём не включается.',
      'The messenger key is signed; the wallet address is not independently verified. Automatic acceptance stays off.');
  String get addUnverifiedContactHint => _t(
      'Адрес заявлен отправителем и не подтверждён. Сохраняется без автоматического приёма.',
      'The address is claimed by the sender and unverified. It is saved without automatic acceptance.');
  String get declineAction => _t('Отклонить', 'Decline');
  String secondsLeft(int seconds) => _t('Осталось $seconds с', '$seconds s left');
  String get pendingTimeoutMessage => _t(
      'Отправитель получил слейтпак для ручной передачи. Платёж сохранён во входящих.',
      'The sender received a slatepack for manual handover. The payment is saved in the inbox.');

  // Входящие (tor.inbox)
  String get inboxTitle => _t('Входящие', 'Inbox');
  /// На главном экране: чтобы не путать с входящими платежами в «Операциях».
  String get inboxCardTitle => _t('Входящие slatepack', 'Incoming slatepacks');
  String get inboxEmpty => _t(
      'Входящих пока нет. Здесь окажутся платежи и счета по Tor, которые не удалось принять сразу.',
      'No incoming items yet. Tor payments and invoices that could not be accepted immediately appear here.');
  String get inboxPayment => _t('Платёж', 'Payment');
  String get inboxInvoice => _t('Счёт', 'Invoice');
  String get inboxFromLabel => _t('от', 'from');
  String get inboxReceivedLabel => _t('получено', 'received');
  String get ago => _t('назад', 'ago');
  String get inboxS2Hint => _t(
      'Передайте этот S2 отправителю: в grin-wallet он выполнит `grin-wallet finalize`.',
      'Give this S2 to the sender: in grin-wallet they run `grin-wallet finalize`.');
  String get inboxAccepted => _t('Платёж принят', 'Payment accepted');
  String get inboxInvoicePaid => _t('Счёт оплачен', 'Invoice paid');
  String get inboxRefresh => _t('Обновить список', 'Refresh list');


  // Service / jobs
  String get serviceUnavailable => _t('Сервис кошелька недоступен', 'Wallet service is unavailable');
  String get serviceStarting => _t('Запускаем ядро…', 'Starting the core…');
  String get loadingWallet => _t('Загружаем кошелёк…', 'Loading wallet…');
  String get passwordMin8 => _t('Пароль должен быть не короче 8 символов', 'Password must be at least 8 characters');
  String get chooseProfile => _t('Выберите профиль', 'Choose a profile');
  String get noProfiles => _t('Нет профилей. Создайте или восстановите кошелёк.', 'No profiles. Create or restore a wallet.');
  String get profilesLoading => _t('Ищем профили…', 'Looking for profiles…');
  String get refreshing => _t('Проверяем…', 'Verifying…');
  String get jobCancel => _t('Отменить', 'Cancel');
  String get jobCancelled => _t('Операция отменена', 'Operation cancelled');
  String get jobDone => _t('Готово', 'Done');
  String get jobFailed => _t('Операция не удалась', 'Operation failed');
  String get phaseCheckpoint => _t('Контрольная точка', 'Checkpoint');
  String get phasePeers => _t('Пиры', 'Peers');
  String get phaseHeaders => _t('Заголовки', 'Headers');
  String get phaseBalance => _t('Доказанный баланс', 'Proven balance');
  String get noTransactions => _t('Операций пока нет. Новые платежи появятся здесь.', 'No activity yet. New payments will appear here.');
  String get noTransactionsRestoredNote => _t(
      'У восстановленного кошелька старые операции из цепи не восстанавливаются: появятся только новые платежи.',
      'A restored wallet cannot rebuild past activity from the chain: only new payments appear.');
  String get searchContacts => _t('Поиск по имени', 'Search by name');
  String get noMatches => _t('Ничего не найдено', 'Nothing found');
  String get renameContact => _t('Своё имя контакта', 'Contact name');
  String get renameContactHint => _t('Видно только вам, адрес не меняется', 'Only you see it; the address stays the same');
  String get save => _t('Сохранить', 'Save');
  String get contactRenamed => _t('Имя сохранено', 'Name saved');
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
  String get verifyRowHint => _t('Чекпоинт, режим «будущее», свой пир', 'Checkpoint, «future» mode, own peer');
  String get open => _t('Открыть', 'Open');
  String get balanceUnproven => _t('Баланс не доказан: файл баланса не прошёл проверку', 'Balance not proven: the balance file failed the check');
  String get cancelPayment => _t('Отменить', 'Cancel');
  String get cancelPaymentTitle => _t('Отменить платёж?', 'Cancel the payment?');
  String get cancelPaymentNote => _t('Монеты, отложенные под этот платёж, снова станут доступны. Если получатель уже ответил и транзакция ушла в сеть, отменить нельзя: она может попасть в блок.', 'The coins held for this payment become available again. If the recipient already answered and the transaction was broadcast, it cannot be cancelled: it may still be mined.');
  String get cancelPaymentDone => _t('Платёж отменён, монеты доступны', 'Payment cancelled, coins available');
  String get keep => _t('Оставить', 'Keep');
  String get checkFromGenesis => _t('Проверить сам', 'Check myself');
  String get ownCpTitle => _t('Проверка чекпоинта с нуля', 'Check the checkpoint from scratch');
  String get ownCpNote => _t(
      'Кошелёк скачает заголовки от genesis у пиров, проверит их и сравнит результат с поставочной точкой. Разные сети /16 не доказывают независимость пиров. На mainnet проверка может занять длительное время.',
      'The wallet downloads headers from genesis, verifies them and compares the result with the shipped checkpoint. Different /16 networks do not prove peer independence. On mainnet this can take a long time.');
  String ownCpShipped(String h) => _t('Чекпоинт в поставке: высота $h', 'Shipped checkpoint: height $h');
  String get ownCpNoShipped => _t('Чекпоинта в поставке нет: своя точка будет единственной', 'No shipped checkpoint: your own will be the only one');
  String get ownCpStart => _t('Начать проверку', 'Start the check');
  String get ownCpContinue => _t('Продолжить проверку', 'Continue the check');
  String get ownCpAgain => _t('Проверить ещё раз', 'Check again');
  String get ownCpPause => _t('Пауза', 'Pause');
  String get ownCpPausedNote => _t('Проверка на паузе, продолжится с места остановки', 'The check is paused and continues where it stopped');
  String ownCpMatch(String h) => _t('Своя точка готова (высота $h), поставочная точка есть на проверенной вами цепочке. Кошельки будут открываться от своей.', 'Own checkpoint ready (height $h); the shipped one is on the chain you checked. Wallets will open from your own.');
  String ownCpMismatch(String h) => _t('Поставочной точки НЕТ на проверенной вами цепочке (своя точка: высота $h). Не доверяйте поставке, сообщите разработчикам.', 'The shipped checkpoint is NOT on the chain you checked (own point: height $h). Do not trust the shipped one; tell the developers.');
  String get addressNotSlatepack => _t(
      'Это адрес кошелька, а не slatepack. Здесь вставляют ответ отправителя: текст от BEGINSLATEPACK до ENDSLATEPACK. Свой адрес отправьте ему — кнопка «Скопировать адрес» выше.',
      'This is a wallet address, not a slatepack. Paste the sender\'s message here: the text from BEGINSLATEPACK to ENDSLATEPACK. Give the sender your own address — the Copy address button above.');

  /// Понятный текст вместо служебной ошибки сервиса (исходная — в логах).
  String humanError(String raw) {
    final String t = raw.trim();
    if (t.contains('another wallet operation is running')) {
      return t.contains('(job open-')
          ? _t('Кошелёк сейчас обновляется. Дождитесь конца обновления (или нажмите «Отменить» у полосы обновления) и повторите.',
              'The wallet is refreshing. Wait until it finishes (or press Cancel on the refresh bar) and try again.')
          : _t('Сейчас идёт другая операция с кошельком. Дождитесь её окончания и повторите.',
              'Another wallet operation is running. Wait until it finishes and try again.');
    }
    if (t.contains('this payment is not finalized here') || t.contains('no kernel in the payment record')) {
      return _t('Пока нечего проверять: дождитесь ответа получателя и завершения платежа. Затем проверьте подтверждение снова.',
          'There is nothing to check yet: wait for the recipient and finalize the payment, then check again.');
    }
    // Сокет к локальной службе кошелька отклонён/оборван: служба остановилась.
    if (t.contains('errno = 1225') || t.contains('errno = 111') || t.contains('errno = 10061') ||
        (t.contains('127.0.0.1') && (t.contains('Socket') || t.contains('Connection refused')))) {
      return serviceUnreachable;
    }
    if (t.startsWith('not a slatepack')) {
      return _t('Это не slatepack. Вставьте сообщение целиком: от BEGINSLATEPACK до ENDSLATEPACK.',
          'This is not a slatepack. Paste the whole message: from BEGINSLATEPACK to ENDSLATEPACK.');
    }
    return raw;
  }

  String get checkpointTooOld => _t('Чекпоинт в поставке слишком старый: соберите свою точку (проверка с нуля)', 'The shipped checkpoint is too old: build your own (check from scratch)');
  String ownCpBuilt(String h) => _t('Своя точка готова: высота $h', 'Own checkpoint ready: height $h');
  String get qrFromImage => _t('QR из картинки', 'QR from image');
  String get pasteText => _t('Вставить', 'Paste');
  String get qrImageNotImage => _t('Это не картинка. Подойдут PNG, JPG, GIF, BMP, WEBP', 'Not an image. PNG, JPG, GIF, BMP or WEBP only');
  String get qrImageTooBig => _t('Файл больше 8 МБ', 'The file is larger than 8 MB');
  String get qrImageNoCode => _t('Это не QR-код: на картинке его не нашлось', 'This is not a QR code: none found in the image');
  String get availableShort => _t('Доступно', 'Available');
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
  String get resumePayment => _t('Slatepack / ответ S2', 'Slatepack / S2 reply');
  String get resumePaymentNote => _t('Вставьте ответ получателя целиком. Финализация относится к выбранному существующему платежу. После неё проверьте статус и подтверждение в сети.', 'Paste the complete recipient reply. Finalization applies to the selected existing payment. Afterwards check its status and network confirmation.');
  String get finalizeAction => _t('Финализировать', 'Finalize');
  String get broadcastAction => _t('Разослать', 'Broadcast');
  String get confirmAction => _t('Проверить подтверждение', 'Check confirmation');
  String get receiveSlatepackLabel => _t('Входящий slatepack (S1)', 'Incoming slatepack (S1)');
  String get receiveAction => _t('Принять', 'Receive');
  String get receiveAnswerTitle => _t('Ответ для отправителя (S2)', 'Answer for the sender (S2)');
  String get invoiceAmount => _t('Сумма счёта', 'Invoice amount');
  String get invoicePendingLabel => _t('Завершить выставленный счёт', 'Finalize an issued invoice');
  String get invoiceSelectHint => _t('Выберите счёт', 'Select an invoice');
  String get invoiceAnswerLabel => _t('Ответ плательщика (I2)', 'Payer response (I2)');
  String get invoiceFinalizeAction => _t('Завершить счёт', 'Finalize invoice');
  String get invoiceBroadcastPending => _t('Счёт завершён, рассылка не подтверждена', 'Invoice finalized; broadcast not confirmed');
  String get invoiceBroadcastRetry => _t('Разослать транзакцию', 'Broadcast transaction');
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
  String get deliveryMail => 'GlauxMail';
  String get relayUnavailable => _t('Платежи через GlauxMail пока недоступны. Для платежа выберите Tor или ручную доставку. Переписка через I2P и Nostr настраивается отдельно.', 'GlauxMail payments are not available yet. Choose Tor or manual delivery for payments. I2P and Nostr messaging are configured separately.');
  String get torQueued => _t('Платёж поставлен в очередь Tor. Это ещё не подтверждает доставку: нужен работающий Tor и ответ получателя.', 'Payment queued for Tor. This does not confirm delivery: Tor must be running and the recipient must reply.');
  String get torQueueUnconfirmed => _t('Состояние доставки Tor неизвестно.', 'Tor delivery status is unknown.');
  String get paymentCreated => _t('Платёж создан', 'Payment created');
  String get torManualFallback => _t('S1 создан. Скопируйте его и передайте получателю.', 'S1 created. Copy it and deliver it to the recipient.');
  String get torS1Warning => _t('Не передавайте S1 другим способом, пока доставка Tor может выполняться. При сбое проверьте операцию в истории.', 'Do not deliver S1 through another channel while Tor delivery may be running. If it fails, check the payment history.');
  String get torHistoryFailed => _t('Ошибка обработки Tor. Проверьте состояние операции; не создавайте повторный перевод.', 'Tor processing failed. Check the payment status; do not create a duplicate payment.');
  String get torQueueFailed => _t('Платёж создан; подтвердить постановку в очередь Tor не удалось. Доставка могла начаться: проверьте статус, не создавайте повторный перевод', 'Payment created; Tor queueing could not be confirmed. Delivery may have started: check its status and do not create a duplicate');
  String get deliveryManualHint => _t(
      'Скопируйте S1 slatepack и передайте его получателю любым каналом.',
      'Copy the S1 slatepack and deliver it to the recipient by any channel.');
  String deliveryAutoHint(String via) => _t(
      'Доставка через $via требует работающего соединения; получателю может потребоваться принять платёж.',
      'Delivery via $via requires a working connection; the recipient may need to accept the payment.');
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
  String get tabAccept => _t('Принять', 'Accept');
  String get tabInvoice => _t('Счёт', 'Invoice');
  String get tabPay => _t('Оплатить', 'Pay');
  String get newPassword => _t('Новый пароль', 'New password');
  String get oldPassword => _t('Текущий пароль', 'Current password');
  String get repeatPassword => _t('Повторите новый пароль', 'Repeat new password');
  String get passwordsDiffer => _t('Пароли не совпадают', 'Passwords do not match');
  String get passwordTooShort => _t('Пароль не короче 8 символов', 'At least 8 characters');
  String get passwordChanged => _t('Пароль изменён', 'Password changed');
  String get seedShownTitle => _t('Ваша seed-фраза', 'Your seed phrase');
  String get seedShownNote => _t('Запишите на бумаге и никому не показывайте. Окно закроется, фраза не сохранится на экране.', 'Write it on paper and show it to no one. It is not kept on screen once this window closes.');
  String get wrongPassword => _t('Неверный пароль', 'Wrong password');
  String get close => _t('Закрыть', 'Close');
  String get receiveTitle => _t('Получить', 'Receive');
  String get receiveHint => _t('Отправьте этот адрес плательщику — подойдёт любой кошелёк Grin.',
      'Share this address with the payer — any Grin wallet works.');
  String get receiveCompatibleHint => _t(
      'Этот же адрес работает в grin-wallet и Grin++ (по Tor, пока GrinSight открыт и GlauxNet включён).',
      'The same address works in grin-wallet and Grin++ (over Tor while GrinSight is open and GlauxNet is enabled).');
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
      'Кошелёк начинает с контрольной точки из поставки, подписанной разработчиками. Можно не доверять и ей: кошелёк проверит каждый заголовок с первого блока Grin, построит свежую точку (и если поставочная устарела) и проверит, что поставочная лежит на той же цепочке. Это занимает от 30 минут; процесс можно прерывать и продолжать.',
      'The wallet starts from the checkpoint shipped by the developers. You may distrust it: the wallet checks every header from the first Grin block, builds a fresh checkpoint (also when the shipped one is outdated) and checks that the shipped one is on the same chain. It takes 30+ minutes; the process can be paused and resumed.');

  String get verificationWarning => _t(
      'Каноническая вершина не доказана: доверие к checkpoint внешнее. Пиры подтверждают работу, но не независимость.',
      'The canonical tip is not proven: checkpoint trust is external. Peers confirm work, not independence.');

  // Settings
  String get settings => _t('Настройки', 'Settings');
  String get groupWallet => _t('Кошелёк', 'Wallet');
  String get groupMessenger => _t('Мессенджер', 'Messenger');
  String get groupNetwork => _t('Сеть', 'Network');
  String get groupVerify => _t('Проверка и сеть', 'Verification & network');
  String get groupSecurity => _t('Безопасность', 'Security');
  String get groupMore => _t('Ещё', 'More');
  String get profileOnDevice => _t('только на этом устройстве', 'this device only');
  String get network => _t('Сеть', 'Network');
  String networkHintWallet(String network) => _t('$network · выбирается только при входе',
      '$network · chosen at sign-in only');
  String get checkpointVerified => _t('10 ноября · проверен', 'Nov 10 · verified');
  String get deliveryHint => _t('Tor или GlauxMail', 'Tor or GlauxMail');
  String get relayHint => _t('GlauxMail пока недоступен', 'GlauxMail is not available yet');
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
  String get prototypeFooter => _t('GrinSight 0.4.2 · Кошелёк для людей (2026)',
      'GrinSight 0.4.2 · A wallet for people (2026)');
  String get renameWalletTitle => _t('Новое название кошелька', 'New wallet name');
  String get renameWalletHint => _t('Только на этом устройстве: 1–32 латинских букв, цифр, «-» или «_». Кошелёк ненадолго перезапустится.', 'Only on this device: 1–32 letters, digits, "-" or "_". The wallet restarts briefly.');
  String get walletRenamed => _t('Название сохранено', 'Wallet name saved');
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
  String get futureBadge => _t('Будущее', 'Future');
  String get futureNoCheckpoint => _t('Без контрольной точки', 'No checkpoint');
  String get futureNoCheckpointNote => _t(
      'Проверка идёт по header-proof от свежего якоря. Подписанный чекпоинт и PIBD в этом режиме не используются.',
      'Verification uses header proofs from a fresh anchor. The signed checkpoint and PIBD are not used in this mode.');
  String get futureNoPeers => _t(
      'Патченные header-proof ноды не найдены. Вернитесь в обычный режим.',
      'No patched header-proof peers found. Switch back to normal mode.');
  String get experimentalModeNote => _t(
      'Переключатель сохраняет настройку, но не включает проверку header-proof.',
      'The switch saves a setting; it does not enable header-proof verification.');

  // Peer
  String get peerTitle => _t('Свой пир', 'Custom peer');
  String get peerNote => _t(
      'Кошелёк проверяет данные пиров по P2P. Для выбора цепочки нужны сторонники из разных сетей /16; это не доказывает их независимость.',
      'The wallet checks peer data over P2P. Chain selection requires supporters from different /16 networks; this does not prove independence.');
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
  String get recipientInvalid => _t('Введите корректный адрес кошелька Grin', 'Enter a valid Grin wallet address');
  String get amountRequired => _t('Укажите сумму', 'Enter the amount');
  String get insufficientFunds => _t('Недостаточно средств с учётом комиссии', 'Insufficient funds including the fee');
  String get messengerTor => _t('Доставка через Tor (демо)', 'Delivery via Tor (demo)');
  String get messengerMail => _t('GlauxMail пока недоступен', 'GlauxMail is not available yet');
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


