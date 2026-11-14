import 'package:flutter/foundation.dart';

/// Журнал предупреждений и ошибок текущего сеанса (главный экран, блок под балансом).
/// Хранит только уже понятные пользователю тексты и вид проблемы — не сырые
/// ошибки службы (в них бывают адреса и токены).
enum LogLevel { warning, error }

class LogEntry {
  LogEntry({required this.kind, required this.text, required this.level, required this.time});
  final String kind;
  final String text;
  final LogLevel level;
  DateTime time;
  int count = 1;
}

class EventLog extends ChangeNotifier {
  static final EventLog instance = EventLog();

  final List<LogEntry> _items = <LogEntry>[];
  static const int _max = 50;

  /// Новые сверху.
  List<LogEntry> get items => List<LogEntry>.unmodifiable(_items.reversed);

  /// Повтор той же записи подряд не плодит строки: растёт счётчик и время.
  void add(String kind, String text, {LogLevel level = LogLevel.error}) {
    final LogEntry? last = _items.isEmpty ? null : _items.last;
    if (last != null && last.kind == kind && last.text == text) {
      last.count++;
      last.time = DateTime.now();
    } else {
      _items.add(LogEntry(kind: kind, text: text, level: level, time: DateTime.now()));
      if (_items.length > _max) _items.removeAt(0);
    }
    notifyListeners();
  }

  /// Сырая ошибка службы → вид проблемы; в журнал идёт только [humanText].
  void addError(String raw, String humanText) => add(classifyError(raw), humanText);

  void clear() {
    if (_items.isEmpty) return;
    _items.clear();
    notifyListeners();
  }
}

/// Вид проблемы по сырому тексту (сам сырой текст никуда не попадает).
String classifyError(String raw) {
  final String t = raw.toLowerCase();
  if (t == '__status_unavailable__') return 'status_unavailable';
  if (t.contains('errno = 1225') || t.contains('errno = 111') || t.contains('errno = 10061') ||
      (t.contains('127.0.0.1') && (t.contains('socket') || t.contains('connection refused')))) {
    return 'service_unreachable';
  }
  if (t == 'message_history_unavailable') return 'history_unavailable';
  if (t.contains('nostr receive page is full')) return 'nostr_page_full';
  if (t.contains('text history full') || t.contains('payment message storage full') || t.contains('queue') || t.contains('quota')) return 'storage_full';
  if (t.contains('history write') || t.contains('history read') || t.contains('history record')) return 'history_io';
  if (t.startsWith('ack:')) return 'ack_failed';
  if (t.startsWith('fetch:')) return 'fetch_failed';
  if (t.contains('another wallet operation is running')) return 'busy';
  if (t.contains('tor')) return 'tor_error';
  return 'generic';
}

/// Короткое название, что это значит и что сделать — для «?» у записи.
({String title, String meaning, String fix}) logHelp(String kind, bool en) {
  String t(String ru, String e) => en ? e : ru;
  return switch (kind) {
    'nostr_ip' => (
      title: t('Сервер Nostr видит ваш IP', 'Nostr server sees your IP'),
      meaning: t('Выбран канал «Nostr напрямую»: сервер видит ваш IP-адрес, время подключений и с кем вы обмениваетесь сообщениями.',
          'The “Direct Nostr” channel is selected: the server sees your IP address, connection times and who you exchange messages with.'),
      fix: t('Если это нежелательно — в шапке откройте «Каналы переписки» и выберите Tor, I2P напрямую или Nostr через I2P.',
          'If that is not acceptable, open “Message channels” in the header and choose Tor, Direct I2P or Nostr via I2P.'),
    ),
    'tor_failed' => (
      title: t('Tor не подключился к сети', 'Tor could not connect'),
      meaning: t('Процесс Tor запущен, но до сети Tor достучаться не удалось. Чаще всего Tor блокирует провайдер или сеть.',
          'The Tor process runs but could not reach the Tor network. Most often the provider or network blocks Tor.'),
      fix: t('Включите мост (obfs4 или Snowflake) в «Tor и мосты». Проверьте интернет и точное время на компьютере. Пока Tor не подключён, платежи можно передавать «Вручную».',
          'Enable a bridge (obfs4 or Snowflake) in “Tor and bridges”. Check the internet and the computer clock. Until Tor connects, use “Manual” delivery.'),
    ),
    'service_unreachable' || 'status_unavailable' => (
      title: t('Служба кошелька не отвечает', 'Wallet service not responding'),
      meaning: t('Приложение не может связаться со своей локальной службой: она остановилась или зависла.',
          'The app cannot reach its local service: it stopped or hung.'),
      fix: t('Перезапустите приложение. Если повторяется — пришлите журнал service из папки данных.',
          'Restart the app. If it repeats, send the service log from the data folder.'),
    ),
    'history_unavailable' || 'history_io' => (
      title: t('Не удаётся прочитать или сохранить переписку', 'Cannot read or save conversations'),
      meaning: t('Хранилище переписки на устройстве недоступно или повреждено.', 'The conversation storage on this device is unavailable or damaged.'),
      fix: t('Проверьте свободное место и права на папку данных, затем перезапустите приложение.', 'Check free space and permissions of the data folder, then restart the app.'),
    ),
    'storage_full' || 'nostr_page_full' => (
      title: t('Хранилище сообщений заполнено', 'Message storage is full'),
      meaning: t('Новые сообщения или платёжные запросы могут не приниматься.', 'New messages or payment requests may not be accepted.'),
      fix: t('Разберите «Необработанные сообщения» и «Карантин» в меню мессенджера (⋯); включите удаление старой переписки через 30 дней.',
          'Process “Unprocessed messages” and “Quarantine” in the messenger menu (⋯); enable deleting conversations after 30 days.'),
    ),
    'fetch_failed' => (
      title: t('Не удалось получить сообщения', 'Could not receive messages'),
      meaning: t('Выбранный канал переписки сейчас не отвечает.', 'The selected message channel is not responding right now.'),
      fix: t('Проверьте статус Tor / I2P и адрес сервера в «Каналах переписки». Обычно проходит само после восстановления связи.',
          'Check Tor / I2P status and the server address in “Message channels”. Usually clears once the connection is back.'),
    ),
    'ack_failed' => (
      title: t('Сообщение может прийти повторно', 'A message may arrive again'),
      meaning: t('Не удалось подтвердить обработку входящего сообщения.', 'Processing of an incoming message could not be acknowledged.'),
      fix: t('Ничего делать не нужно: повтор будет распознан. Если повторяется часто — проверьте связь.', 'Nothing to do: a repeat is recognized. If it happens often, check the connection.'),
    ),
    'busy' => (
      title: t('Идёт другая операция', 'Another operation is running'),
      meaning: t('Кошелёк выполняет обновление или платёж и не может начать новое действие.', 'The wallet is refreshing or paying and cannot start another action.'),
      fix: t('Дождитесь окончания или нажмите «Отменить» у полосы обновления, затем повторите.', 'Wait for it to finish or press “Cancel” on the refresh bar, then retry.'),
    ),
    'tor_error' => (
      title: t('Ошибка Tor', 'Tor error'),
      meaning: t('Операция через Tor не удалась.', 'An operation over Tor failed.'),
      fix: t('Проверьте статус Tor в карточке мессенджера; при блокировке включите мосты. Платёж можно передать «Вручную».',
          'Check Tor status in the messenger card; enable bridges if blocked. The payment can be delivered “Manually”.'),
    ),
    _ => (
      title: t('Операция не выполнена', 'Operation failed'),
      meaning: t('Действие завершилось ошибкой; подробность — в тексте записи.', 'The action ended with an error; see the entry text.'),
      fix: t('Повторите действие. Если ошибка повторяется — пришлите журнал service.', 'Retry. If it repeats, send the service log.'),
    ),
  };
}
