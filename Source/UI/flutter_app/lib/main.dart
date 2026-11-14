// ignore_for_file: use_build_context_synchronously

import 'dart:async';
import 'dart:ui' show AppExitResponse;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show SystemNavigator;

import 'backend/backend.dart';
import 'components.dart';
import 'chat.dart';
import 'catalogue_sheet.dart';
import 'catalogue_api.dart';
import 'core.dart';
import 'event_log.dart';
import 'gold_layer.dart';
import 'l10n.dart';
import 'messenger.dart';
import 'screens/launch.dart';
import 'screens/login.dart';
import 'screens/wallet.dart';
import 'sheets.dart';
import 'theme.dart';
import 'wallet_model.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final WalletCore core;
  try {
    core = await startBackend();
  } catch (e) {
    runApp(_BackendErrorApp(message: e.toString().replaceFirst('Exception: ', '')));
    return;
  }
  final Map<String, String> params = Uri.base.queryParameters;
  runApp(
    GrinSightApp(
      core: core,
      autoProfile: devAutoProfile,
      autoPassword: devAutoPassword,
      autoNetwork: devAutoNetwork,
      initialScreen: params['screen'],
      initialSheet: params['sheet'],
      initialStep: int.tryParse(params['step'] ?? '') ?? 0,
      menuInitiallyOpen: params['menu'] == 'options',
      still: params['still'] == '1',
      initialMode: params['mode'],
      initialCreateStage: int.tryParse(params['stage'] ?? '') ?? 0,
      initialLanguage: params['lang'],
      initialTech: params['tech'] == '1',
    ),
  );
}

class _BackendErrorApp extends StatelessWidget {
  const _BackendErrorApp({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: buildGrinSightTheme(),
      home: Scaffold(
        backgroundColor: UPalette.bg,
        body: SafeArea(
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 460),
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: UCard(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      const Icon(Icons.error_outline_rounded, color: UPalette.amber, size: 34),
                      const SizedBox(height: 12),
                      Text(const S('ru').serviceUnavailable, style: uiStyle(16, weight: FontWeight.w600)),
                      const SizedBox(height: 8),
                      SelectableText(message, style: uiStyle(11.5, color: UPalette.text2, height: 1.6)),
                      const SizedBox(height: 14),
                      Text(const S('ru').serviceStarting, style: uiStyle(11, color: UPalette.text3)),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class GrinSightApp extends StatefulWidget {
  const GrinSightApp({
    super.key,
    required this.core,
    this.autoProfile = '',
    this.autoPassword = '',
    this.autoNetwork = '',
    this.initialScreen,
    this.initialSheet,
    this.initialStep = 0,
    this.menuInitiallyOpen = false,
    this.still = false,
    this.initialMode,
    this.initialCreateStage = 0,
    this.initialLanguage,
    this.initialTech = false,
    this.initialDelivery,
  });

  final WalletCore core;
  final String autoProfile;
  final String autoPassword;
  final String autoNetwork;

  final String? initialScreen;
  final String? initialSheet;
  final int initialStep;
  final bool menuInitiallyOpen;
  final bool still;
  final String? initialMode;
  final int initialCreateStage;
  final String? initialLanguage;
  final bool initialTech;
  /// Способ доставки при запуске (для тестов и демо); по умолчанию — Tor.
  final String? initialDelivery;

  @override
  State<GrinSightApp> createState() => _GrinSightAppState();
}

class _GrinSightAppState extends State<GrinSightApp> with WidgetsBindingObserver {
  final GlobalKey<NavigatorState> _navKey = GlobalKey<NavigatorState>();

  late String _screen;
  late String _lang;
  String _network = 'mainnet';
  String _profile = '';
  // По умолчанию — доставка через Tor; «Вручную» показывает slatepack платежа.
  late String _delivery = widget.initialDelivery ?? 'tor';
  /// Мессенджер можно выключить целиком; Tor включается/выключается отдельно.
  bool _messengerOn = true;
  /// Монохромная тема: весь интерфейс в оттенках серого (переключатель в шапке).
  bool _mono = false;
  final GoldLayerController _gold = GoldLayerController();
  // Never present an assumed incoming-payment policy as the saved policy.
  String _autoAccept = 'unknown';
  int _walletRevision = 0;
  int _policyRevision = 0;
  int _policyReadSerial = 0;
  bool _policySaving = false;
  bool _future = false;
  bool _futureSaving = false;
  int _futureRevision = 0;
  bool _loading = false;
  bool _checkpointOffer = false;
  bool _showAllHistory = false;
  bool _checkpointOfferEvaluated = false;
  String? _error;

  /// Опрос `tor.status`: 2 с, пока есть платежи, ждущие решения, иначе 10 с.
  Timer? _torPoll;
  bool _pendingDialogOpen = false;

  WalletStatus? _status;
  String? _contactPhrase;
  String? _contactPublication;
  String? _contactChannel;
  Timer? _contactIdentityPoll;
  /// Окно «Получить» открыто поверх экрана и не перестраивается вместе с ним:
  /// контактная фраза и статус публикации обновляются в нём через этот счётчик.
  final ValueNotifier<int> _identityRev = ValueNotifier<int>(0);
  int _contactIdentitySerial = 0;
  TorStatusInfo? _torInfo;
  List<WalletTx> _transactions = <WalletTx>[];
  List<UContact> _contacts = <UContact>[];
  bool _contactsUnavailable = false;

  String? _pendingSheet;
  int _pendingStep = 0;
  bool _menuConsumed = true;

  S get _s => S(_lang);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    // Журнал предупреждений — на один сеанс приложения.
    EventLog.instance.clear();
    _lang = widget.initialLanguage == 'en' ? 'en' : 'ru';
    _screen = switch (widget.initialScreen) {
      'login' => 'login',
      'wallet' => 'wallet',
      _ => 'boot',
    };
    if (widget.initialSheet != null) {
      _pendingSheet = widget.initialSheet;
      _pendingStep = widget.initialStep;
    }
    _menuConsumed = !widget.menuInitiallyOpen;
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      if (!mounted) return;
      if (_screen == 'boot') unawaited(_loadPreFuture());
      if (_screen == 'wallet' && _status == null) {
        await _loadWallet();
        if (!mounted) return;
      }
      if (widget.autoProfile.isNotEmpty && widget.autoPassword.isNotEmpty) {
        await _autoLogin();
        if (!mounted) return;
      }
      final String? pending = _pendingSheet;
      _pendingSheet = null;
      if (pending != null) _openSheet(pending, step: _pendingStep);
    });
  }

  @override
  void dispose() {
    _torPoll?.cancel();
    _contactIdentityPoll?.cancel();
    _identityRev.dispose();
    WidgetsBinding.instance.removeObserver(this);
    widget.core.close();
    super.dispose();
  }

  @override
  Future<AppExitResponse> didRequestAppExit() async {
    await widget.core.close();
    return AppExitResponse.exit;
  }

  Future<void> _autoLogin() async {
    try {
      final List<WalletProfile> profiles = await widget.core.profiles();
      final WalletProfile? selected = profiles.where((WalletProfile x) => x.name == widget.autoProfile).firstOrNull;
      if (selected == null) return;
      final WalletProfile p = selected;
      final String network = widget.autoNetwork.isNotEmpty ? widget.autoNetwork : p.network;
      await widget.core.unlock(login: p.name, password: widget.autoPassword, network: network);
      if (!mounted) return;
      setState(() {
        _walletRevision++;
        _policyRevision++;
        _autoAccept = 'unknown';
        _profile = p.name;
        _network = network;
        _screen = 'wallet';
        _loading = true;
      });
      await _loadWallet();
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = widget.core.describeError(e));
    }
  }

  Future<void> _loadWallet() async {
    if (!mounted || _screen != 'wallet') return;
    final requestedProfile = _profile;
    final requestedNetwork = _network;
    final int walletRevision = _walletRevision;
    final int policyRevision = _policyRevision;
    final int policyReadSerial = ++_policyReadSerial;
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final WalletStatus status = await widget.core.status();
      TorStatusInfo? torInfo;
      try { torInfo = await widget.core.torStatus(); } catch (_) { torInfo = null; }
      final List<WalletTx> txs = await widget.core.payments();
      List<ContactInfo>? rawContacts;
      try {
        rawContacts = await widget.core.contacts();
      } catch (_) {
        // Keep the last known list; a read failure is not an empty address book.
      }
      String? savedPolicy;
      try {
        savedPolicy = await widget.core.autoAcceptPolicy();
      } catch (_) {
        // A failed read must not be presented as the safe-looking 'ask' mode.
      }
      String? address = status.address;
      if (address == null || address.isEmpty) {
        try {
          address = await widget.core.address();
        } catch (_) {}
      }
      final WalletStatus live = WalletStatus(
        profile: status.profile,
        network: status.network,
        address: address,
        balance: status.balance,
        proof: status.proof,
        torRunning: status.torRunning,
        verifyMode: status.verifyMode,
      );
      bool offerSeen = false;
      bool ownBuilt = false;
      try {
        final CheckpointInfo ci = await widget.core.checkpointInfo();
        offerSeen = ci.offerSeen;
        ownBuilt = ci.ownBuilt;
      } catch (_) {}
      final List<UContact>? contacts = rawContacts?.map((ContactInfo c) => _contact(c, txs)).toList();
      if (!mounted || _screen != 'wallet' || _profile != requestedProfile || _network != requestedNetwork) return;
      setState(() {
        _status = live;
        _torInfo = torInfo;
        _transactions = txs;
        if (contacts != null) _contacts = contacts;
        _contactsUnavailable = contacts == null;
        if (!_policySaving && _policyRevision == policyRevision && _policyReadSerial == policyReadSerial) {
          _autoAccept = savedPolicy ?? 'unknown';
        }
        _loading = false;
        _profile = live.profile;
        _network = live.network;
        _future = live.headerProof;
        if (!_checkpointOfferEvaluated) {
          _checkpointOfferEvaluated = true;
          _checkpointOffer = live.proof.hasSession && !offerSeen && !ownBuilt;
        }
      });
      unawaited(_loadContactIdentity(live.profile, live.network, walletRevision));
      _restartTorPoll();
    } catch (e) {
      if (!mounted || _screen != 'wallet' || _profile != requestedProfile || _network != requestedNetwork) return;
      setState(() {
        _loading = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  Future<void> _loadContactIdentity(String profile, String network, int revision) async {
    final core = widget.core;
    _contactIdentityPoll?.cancel();
    if (core is! CatalogueIdentityApi) return;
    final serial = ++_contactIdentitySerial;
    unawaited(_loadContactChannel(profile, network, revision, serial));
    bool current() => mounted && _screen == 'wallet' && revision == _walletRevision &&
        profile == _profile && network == _network && serial == _contactIdentitySerial;
    try {
      final identity = await (core as CatalogueIdentityApi).catalogueIdentity();
      if (!current()) return;
      setState(() {
        final phrase = identity['search_phrase'];
        _contactPhrase = phrase is String && phrase.isNotEmpty ? phrase : null;
        _contactPublication = identity['publication'] is String ? identity['publication'] as String : 'unavailable';
      });
      _identityRev.value++;
    } catch (_) {
      if (!current()) return;
      setState(() { _contactPublication = 'unavailable'; });
      _identityRev.value++;
    } finally {
      if (current()) {
        _contactIdentityPoll = Timer(const Duration(seconds: 15),
            () => unawaited(_loadContactIdentity(profile, network, revision)));
      }
    }
  }

  Future<void> _loadContactChannel(String profile, String network, int revision, int serial) async {
    try {
      final settings = await widget.core.nostrSettings();
      if (!mounted || _screen != 'wallet' || revision != _walletRevision || profile != _profile || network != _network || serial != _contactIdentitySerial) return;
      setState(() { _contactChannel = settings['mode'] is String ? settings['mode'] as String : null; });
    } catch (_) {
      if (!mounted || _screen != 'wallet' || revision != _walletRevision || profile != _profile || network != _network || serial != _contactIdentitySerial) return;
      setState(() { _contactChannel = null; });
    }
  }

  Future<void> _loadPreFuture() async {
    final revision = _futureRevision;
    try {
      final mode = await widget.core.getVerifyMode();
      if (mounted && _screen == 'boot' && revision == _futureRevision) {
        setState(() => _future = mode == 'header_proof');
      }
    } catch (_) {
      // Do not present a failed settings read as a successful mode change.
    }
  }

  Future<bool> _setFuture(bool value) async {
    if (_futureSaving) return false;
    _futureRevision++;
    _futureSaving = true;
    try {
      await widget.core.setVerifyMode(value ? 'header_proof' : 'checkpoint');
      if (!mounted) return false;
      setState(() => _future = value);
      if (_screen == 'wallet') await _loadWallet();
      if (!mounted) return false;
      showToast(_navKey.currentContext ?? context, value ? _s.futureOnToast : _s.futureOffToast);
      return true;
    } catch (e) {
      if (!mounted) return false;
      _reportError(e);
      return false;
    } finally {
      _futureSaving = false;
    }
  }

  UContact _contact(ContactInfo c, List<WalletTx> txs) {
    final String short = c.id.length > 18 ? '${c.id.substring(0, 8)}…${c.id.substring(c.id.length - 6)}' : c.id;
    final List<UFeedItem> feed = <UFeedItem>[];
    for (final WalletTx tx in txs.where((WalletTx t) => t.counterparty == c.id)) {
      feed.add(UFeedItem(
        title: tx.incoming ? 'Входящий' : 'Исходящий',
        titleEn: tx.incoming ? 'Incoming' : 'Outgoing',
        subtitle: '${_s.txNote(tx)} · ${nanoToGrin(tx.amountNano)} ${unitFor(_network)}',
        subtitleEn: '${_s.txNote(tx)} · ${nanoToGrin(tx.amountNano)} ${unitFor(_network)}',
        amount: '${tx.incoming ? '+' : '−'}${nanoToGrin(tx.amountNano)} ${unitFor(_network)}',
        outgoing: !tx.incoming,
        confirmed: tx.stage == TxStage.confirmed,
      ));
    }
    return UContact(
      name: c.name,
      fullAddress: c.id,
      shortAddress: short,
      messenger: c.messenger,
      verified: c.identityChecked,
      feed: feed,
    );
  }

  /// Poll while unlocked, including after the daemon stops unexpectedly.
  bool get _canPollTor => mounted && _screen == 'wallet' && _status != null;

  /// Перезапускает опрос `tor.status` через [delay].
  ///
  /// Пока ждёт решения диалог, опрос молчит: после ответа его запустит
  /// [_showPendingDialog]. Таймер отменяется при блокировке и dispose.
  void _restartTorPoll([Duration delay = const Duration(seconds: 10)]) {
    _torPoll?.cancel();
    _torPoll = null;
    if (!_canPollTor || _pendingDialogOpen) return;
    _torPoll = Timer(delay, _pollTor);
  }

  Future<void> _pollTor() async {
    _torPoll = null;
    if (!_canPollTor || _pendingDialogOpen) return;
    Duration next = const Duration(seconds: 10);
    final String polledProfile = _profile;
    final String polledNetwork = _network;
    try {
      final TorStatusInfo info = await widget.core.torStatus();
      if (!mounted || _screen != 'wallet' || _profile != polledProfile || _network != polledNetwork) return;
      setState(() => _torInfo = info);
      if (info.pendingCount > 0) {
        next = const Duration(seconds: 2);
        if (!_pendingDialogOpen) {
          _pendingDialogOpen = true;
          unawaited(_showPendingDialog());
          return;
        }
      }
      // Delivery happens asynchronously; refresh payment states without
      // starting a new chain scan, and ignore a result from an old profile.
      final payments = await widget.core.payments();
      if (!mounted || _screen != 'wallet' || _profile != polledProfile || _network != polledNetwork) return;
      setState(() => _transactions = payments);
    } catch (_) {
      if (mounted && _screen == 'wallet' && _profile == polledProfile && _network == polledNetwork) {
        setState(() => _torInfo = null);
      }
    }
    if (!mounted) return;
    _restartTorPoll(next);
  }

  /// Первый ждущий платёж: удерживаемый, иначе из мессенджера, иначе любой.
  static PendingPayment? _pickPending(List<PendingPayment> list) {
    if (list.isEmpty) return null;
    for (final PendingPayment p in list) {
      if (p.waiting) return p;
    }
    for (final PendingPayment p in list) {
      if (p.overMessenger) return p;
    }
    return list.first;
  }

  /// Диалог поверх любого экрана: незнакомый отправитель ждёт «Да».
  Future<void> _showPendingDialog() async {
    PendingPayment? pending;
    try {
      pending = _pickPending(await widget.core.torPending());
    } catch (_) {
      pending = null;
    }
    if (!mounted || pending == null) {
      _pendingDialogOpen = false;
      if (mounted) _restartTorPoll(const Duration(seconds: 2));
      return;
    }
    final BuildContext? ctx = _navKey.currentContext;
    if (ctx == null) {
      _pendingDialogOpen = false;
      _restartTorPoll(const Duration(seconds: 2));
      return;
    }
    final PendingPayment decision = pending;
    PendingOutcome? outcome;
    try {
      outcome = await showDialog<PendingOutcome>(
        context: ctx,
        useRootNavigator: true,
        barrierDismissible: false,
        barrierColor: const Color(0xA604070B),
        builder: (BuildContext c) => Align(
          alignment: Alignment.center,
          child: Material(
            type: MaterialType.transparency,
            child: PendingPaymentDialog(
              core: widget.core,
              pending: decision,
              network: _status?.network ?? _network,
            ),
          ),
        ),
      );
    } catch (_) {
      outcome = null;
    }
    if (!mounted) return;
    _pendingDialogOpen = false;
    if (outcome == PendingOutcome.expired) {
      showToast(_navKey.currentContext ?? context, _s.pendingTimeoutMessage);
    }
    await _loadWallet();
    if (!mounted) return;
    // Следующий платёж может уже ждать — проверим скоро.
    _restartTorPoll(const Duration(seconds: 2));
  }

  /// Обновление проверки (job «open»). Прогресс показывает полоса проверки на
  /// кошельке, а не модальный лист: его можно закрыть/промахнуться кликом, а
  /// повторное нажатие «Обновить» не запускает второй job (и сервис тоже
  /// присоединяет второй вызов к идущему).
  WalletJob? _refreshJob;
  JobProgress? _refreshProgress;
  bool _verificationStarting = false;

  Future<void> _openWallet() async {
    if (_refreshJob != null || _verificationStarting) return;
    setState(() => _verificationStarting = true);
    try {
      final WalletJob job = await widget.core.openJob();
      if (!mounted) return;
      setState(() {
        _verificationStarting = false;
        _refreshJob = job;
        _refreshProgress = null;
      });
      try {
        await job.wait(onProgress: (JobProgress p) {
          if (mounted) setState(() => _refreshProgress = p);
        });
      } finally {
        if (mounted) {
          setState(() {
            _refreshJob = null;
            _refreshProgress = null;
          });
        }
      }
      await _loadWallet();
    } catch (e) {
      if (!mounted) return;
      setState(() => _verificationStarting = false);
      final String msg = widget.core.describeError(e);
      if (msg.contains('CHECKPOINT_TOO_OLD')) {
        // Поставочная точка слишком старая: сразу предлагаем собрать свою.
        showToast(_navKey.currentContext ?? context, _s.checkpointTooOld);
        await _openSheet('own-checkpoint');
        return;
      }
      showToast(_navKey.currentContext ?? context, msg);
    }
  }

  Future<void> _cancelPayment(String txId) async {
    final BuildContext? ctx = _navKey.currentContext;
    if (ctx == null) return;
    final S s = _s;
    final bool? yes = await showDialog<bool>(
      context: ctx,
      barrierColor: const Color(0xA604070B),
      builder: (BuildContext c) => AlertDialog(
        backgroundColor: UPalette.surface2,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20), side: const BorderSide(color: UPalette.lineStrong)),
        title: Text(s.cancelPaymentTitle, style: uiStyle(16, weight: FontWeight.w600)),
        content: Text(s.cancelPaymentNote, style: uiStyle(12.5, color: UPalette.text2, height: 1.5)),
        actions: [
          TextButton(onPressed: () => Navigator.of(c).pop(false), child: Text(s.keep, style: uiStyle(13, color: UPalette.text2))),
          TextButton(onPressed: () => Navigator.of(c).pop(true), child: Text(s.cancelPayment, style: uiStyle(13, weight: FontWeight.w600, color: UPalette.amber))),
        ],
      ),
    );
    if (yes != true || !mounted) return;
    try {
      await widget.core.cancelPayment(txId);
      await _loadWallet();
      if (mounted) showToast(ctx, s.cancelPaymentDone);
    } catch (e) {
      if (mounted) showToast(ctx, widget.core.describeError(e));
    }
  }

  Future<void> _confirmPayment(String txId) async {
    if (_refreshJob != null || _verificationStarting) return;
    setState(() => _verificationStarting = true);
    try {
      final WalletJob job = await widget.core.confirmJob(txId);
      if (!mounted) return;
      setState(() {
        _verificationStarting = false;
        _refreshJob = job;
        _refreshProgress = null;
      });
      try {
        await job.wait(onProgress: (JobProgress p) {
          if (mounted) setState(() => _refreshProgress = p);
        });
      } finally {
        if (mounted) setState(() { _refreshJob = null; _refreshProgress = null; });
      }
      await _loadWallet();
    } catch (e) {
      if (mounted) {
        setState(() => _verificationStarting = false);
        _reportError(e);
      }
    }
  }

  bool _hidingHistory = false;

  Future<void> _hideCancelledBatch(List<String> ids, {bool confirmAll = false}) async {
    if (_hidingHistory || ids.isEmpty || _screen != 'wallet') return;
    final revision = _walletRevision;
    final profile = _profile;
    final network = _network;
    bool stillCurrent() => mounted && _screen == 'wallet' && revision == _walletRevision && profile == _profile && network == _network;
    if (confirmAll) {
      final context = _navKey.currentContext;
      if (context == null) return;
      final confirmed = await showDialog<bool>(context: context, builder: (c) => AlertDialog(
        title: Text(_lang == 'en' ? 'Remove cancelled operations?' : 'Удалить отменённые операции?'),
        content: Text(_lang == 'en' ? 'They will be removed from the list; payment records remain on the device.' : 'Операции исчезнут из списка; данные платежей останутся на устройстве.'),
        actions: [TextButton(onPressed: () => Navigator.pop(c, false), child: Text(_lang == 'en' ? 'Cancel' : 'Отмена')),
          TextButton(key: const Key('confirm-hide-all'), onPressed: () => Navigator.pop(c, true), child: Text(_lang == 'en' ? 'Remove' : 'Удалить'))],
      ));
      if (confirmed != true || !stillCurrent()) return;
    }
    _hidingHistory = true;
    try {
      for (final id in ids) {
        if (!stillCurrent()) return;
        await widget.core.hideCancelled(id);
      }
    } catch (e) {
      if (stillCurrent()) _reportError(e);
    } finally {
      _hidingHistory = false;
      if (stillCurrent()) await _loadWallet();
    }
  }

  Future<void> _resumePayment(String txId) async {
    final ctx = _navKey.currentContext;
    if (ctx == null) return;
    final tx = _transactions.where((item) => item.txId == txId).firstOrNull;
    await showUSheet<void>(ctx, (c, close) => ResumeSendSheet(
      core: widget.core, txId: txId, network: _network, onClose: close,
      retryOnly: tx != null && tx.kind != 'send',
    ), disableBarrierAndDrag: true);
    if (mounted) await _loadWallet();
  }

  void _cancelRefresh() {
    final WalletJob? job = _refreshJob;
    if (job != null) unawaited(job.cancel());
  }

  Future<void> _startTor() async {
    try {
      await widget.core.torStart();
      await Future<void>.delayed(const Duration(seconds: 1));
      await _loadWallet();
    } catch (e) {
      if (!mounted) return;
      _reportError(e);
    }
  }

  Future<void> _stopTor() async {
    final core = widget.core;
    if (core is! TorControlApi) return;
    try {
      await (core as TorControlApi).torStop();
      await Future<void>.delayed(const Duration(milliseconds: 500));
      await _loadWallet();
    } catch (e) {
      if (!mounted) return;
      _reportError(e);
    }
  }

  /// Ошибка: понятный текст во всплывающем сообщении и запись в журнал на главном.
  void _reportError(Object e) {
    final String raw = widget.core.describeError(e);
    final String text = _s.humanError(raw);
    EventLog.instance.addError(raw, text);
    showToast(_navKey.currentContext ?? context, text);
  }

  void _setMessengerOn(bool on) {
    setState(() {
      _messengerOn = on;
      // GlauxMail ходит через мессенджер: без него остаётся ручная доставка.
      if (!on && _delivery == 'grinmail') _delivery = 'manual';
    });
  }

  Future<void> _setAutoAccept(String v) async {
    if (_policySaving) return;
    final int revision = ++_policyRevision;
    _policyReadSerial++;
    final String profile = _profile;
    final String network = _network;
    setState(() { _policySaving = true; _autoAccept = 'unknown'; });
    try {
      await widget.core.autoAccept(v);
      if (!mounted || revision != _policyRevision || _profile != profile || _network != network) return;
      setState(() => _autoAccept = v);
    } catch (e) {
      if (!mounted || revision != _policyRevision || _profile != profile || _network != network) return;
      _reportError(e);
    } finally {
      if (mounted && revision == _policyRevision) {
        _policyReadSerial++;
        setState(() => _policySaving = false);
      }
    }
  }

  Future<void> _logout() async {
    _contactIdentityPoll?.cancel();
    _contactIdentitySerial++;
    _walletRevision++;
    _contactPhrase = null;
    _contactPublication = null;
        _contactChannel = null;
    _policyRevision++;
    _autoAccept = 'unknown';
    _policySaving = false;
    _torPoll?.cancel();
    _torPoll = null;
    _pendingDialogOpen = false;
    await widget.core.lock();
    if (!mounted) return;
    setState(() {
      _screen = 'boot';
      _status = null;
      _torInfo = null;
      _transactions = <WalletTx>[];
      _showAllHistory = false;
      _contacts = <UContact>[];
      _contactsUnavailable = false;
      _profile = '';
    });
  }

  Future<void> _openContactCatalogue() async {
    final ctx = _navKey.currentContext;
    if (ctx == null) return;
    final revision = _walletRevision;
    final profile = _profile;
    final network = _network;
    final address = await showContactCatalogue(ctx, widget.core);
    bool currentWallet() => mounted && _screen == 'wallet' && revision == _walletRevision && profile == _profile && network == _network;
    if (!currentWallet()) return;
    await _loadWallet();
    if (!currentWallet() || address == null) return;
    final matches = _contacts.where((contact) => contact.fullAddress == address);
    if (!_contactsUnavailable && matches.length == 1 && matches.first.messenger?.isNotEmpty == true) {
      await _openSheet('chat', contact: matches.first);
    } else if (ctx.mounted) {
      showToast(ctx, _lang == 'en' ? 'Contact saved; messaging channel is unavailable.' : 'Контакт сохранён; канал переписки недоступен.');
    }
  }

  Future<void> _addWalletContact() async {
    final ctx = _navKey.currentContext;
    if (ctx == null) return;
    final en = AppLocale.of(ctx).lang == 'en';
    final name = TextEditingController();
    final address = TextEditingController();
    var busy = false;
    String? error;
    try {
      final saved = await showDialog<bool>(context: ctx, builder: (dialogContext) => StatefulBuilder(builder: (context, setDialog) => AlertDialog(
        title: Text(en ? 'Add contact' : 'Добавить контакт'),
        content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(key: const Key('contact-name'), controller: name, decoration: InputDecoration(labelText: en ? 'Name' : 'Имя')),
          TextField(key: const Key('contact-wallet-address'), controller: address, decoration: InputDecoration(labelText: en ? 'Wallet address' : 'Адрес кошелька')),
          Text(en ? 'The address is not verified. Check it with the contact.' : 'Адрес не проверен. Сверьте его с собеседником.', style: uiStyle(11)),
          if (error != null) Text(error!, style: uiStyle(11, color: UPalette.amber)),
        ])),
        actions: [TextButton(onPressed: busy ? null : () => Navigator.pop(dialogContext, false), child: Text(en ? 'Cancel' : 'Отмена')),
          TextButton(key: const Key('contact-save'), onPressed: busy ? null : () async {
            if (name.text.trim().isEmpty || address.text.trim().isEmpty) { setDialog(() => error = en ? 'Enter a name and wallet address.' : 'Укажите имя и адрес кошелька.'); return; }
            setDialog(() { busy = true; error = null; });
            try {
              await widget.core.addContact(address.text, name.text);
              if (dialogContext.mounted) Navigator.pop(dialogContext, true);
            } catch (e) { if (dialogContext.mounted) setDialog(() { busy = false; error = widget.core.describeError(e); }); }
          }, child: Text(en ? 'Add' : 'Добавить'))],
      )));
      if (saved == true && mounted) await _loadWallet();
    } finally { await WidgetsBinding.instance.endOfFrame; name.dispose(); address.dispose(); }
  }

  Future<void> _openContactPayment(UContact contact) async {
    final peer = contact.messenger?.trim();
    if (peer == null || peer.isEmpty) {
      await _openSheet('send', to: contact.fullAddress, contact: contact);
      return;
    }
    final revision = _walletRevision;
    final profile = _profile;
    final network = _network;
    bool currentWallet() => mounted && _screen == 'wallet' && revision == _walletRevision && profile == _profile && network == _network;
    try {
      final info = await widget.core.backupPaymentContacts();
      if (!currentWallet()) return;
      final mode = info['mode'];
      final route = info['route'];
      final rows = info['contacts'];
      if (!{'i2p_direct', 'nostr_i2p', 'nostr_direct'}.contains(mode) || route is! String || route.isEmpty || rows is! List || !rows.whereType<Map>().any((c) => c['address'] == peer)) {
        throw StateError('contact is unavailable on the active channel');
      }
      await _openSheet('send', to: contact.fullAddress, contact: contact, deliveryOverride: 'grinmail');
    } catch (_) {
      if (!currentWallet()) return;
      final en = _lang == 'en';
      final ctx = _navKey.currentContext;
      if (ctx == null) return;
      await showDialog<void>(context: ctx, builder: (dialogContext) => AlertDialog(
        title: Text(en ? 'Delivery unavailable' : 'Доставка недоступна'),
        content: Text(en
            ? 'This contact is not available on the active GlauxMail channel. Check the channel and contact binding, then try again.'
            : 'Контакт недоступен в выбранном канале GlauxMail. Проверьте канал и привязку контакта, затем повторите.'),
        actions: [TextButton(onPressed: () => Navigator.pop(dialogContext), child: Text(en ? 'Close' : 'Закрыть'))],
      ));
    }
  }

  Future<void> _openSheet(String name, {int step = 0, String? to, UContact? contact, String? deliveryOverride}) async {
    final BuildContext? ctx = _navKey.currentContext;
    if (ctx == null) return;
    final S s = _s;
    switch (name) {
      case 'send':
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => SendFlowSheet(
            onClose: close,
            core: widget.core,
            status: _status,
            delivery: deliveryOverride ?? _delivery,
            initialStep: step,
            initialTo: to,
            initialBackupPeer: contact?.messenger,
          ),
          disableBarrierAndDrag: true,
        );
        await _loadWallet();
        break;
      case 'receive':
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => ReceiveSheet(
            onClose: close,
            core: widget.core,
            address: _status?.address ?? '',
            network: _status?.network ?? _network,
            delivery: _delivery,
            // Адрес и фраза для Nostr — на главном экране (карточка «Мои реквизиты»).
          ),
        );
        await _loadWallet();
        break;
      case 'inbox':
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => InboxSheet(
            core: widget.core,
            onClose: close,
            network: _status?.network ?? _network,
          ),
        );
        await _loadWallet();
        break;
      case 'verification':
        if (_status == null) return;
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => VerificationSheet(
            onClose: close,
            status: _status!,
            core: widget.core,
            showTechInitially: widget.initialTech,
            future: _future,
            onFutureChanged: _setFuture,
            onPeerSaved: _loadWallet,
            onRefresh: () {
              close();
              _openWallet();
            },
          ),
        );
        break;
      case 'contact':
        final UContact feedContact = contact ?? (_contacts.isNotEmpty ? _contacts.first : UContact(name: s.noContacts, fullAddress: ''));
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => ContactFeedSheet(
            onClose: close,
            contact: feedContact,
            onChat: feedContact.messenger == null || feedContact.messenger!.isEmpty ? null : () { close(); _openSheet('chat', contact: feedContact); },
            onSend: feedContact.fullAddress.isEmpty ? null : () { close(); _openContactPayment(feedContact); },
            onRename: feedContact.fullAddress.isEmpty
                ? null
                : (String name) async {
                    close();
                    try {
                      await widget.core.renameContact(feedContact.fullAddress, name);
                      await _loadWallet();
                      if (mounted) showToast(ctx, _s.contactRenamed);
                    } catch (e) {
                      if (mounted) showToast(ctx, e.toString());
                    }
                  },
          ),
        );
        break;
      case 'checkpoint':
        await _openWallet();
        break;
      case 'own-checkpoint':
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => OwnCheckpointSheet(core: widget.core, network: _network, onClose: close),
        );
        break;
      case 'settings':
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => SettingsSheet(
            onClose: close,
            core: widget.core,
            profile: _profile,
            networkLabel: networkLabel(_network),
            futureEnabled: _future,
            onRename: (String name) async {
              close();
              try {
                await widget.core.renameWallet(name);
                await _loadWallet();
                if (mounted) showToast(ctx, _s.walletRenamed);
              } catch (e) {
                if (mounted) showToast(ctx, e.toString());
              }
            },
            onVerification: () {
              close();
              _openSheet('verification');
            },
          ),
        );
        break;
      case 'peer':
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => PeerSheet(
            onClose: close,
            core: widget.core,
            onSaved: _loadWallet,
          ),
        );
        break;
      case 'chat':
        await showUSheet<void>(ctx, (BuildContext c, VoidCallback close) => ChatSheet(core: widget.core, onClose: close, initialPeer: contact?.messenger, contacts: _contactsUnavailable ? const [] : _contacts, onFindContact: () { close(); _openContactCatalogue(); }));
        break;
      case 'messenger':
        await showUSheet<void>(
          ctx,
          // StatefulBuilder: лист не перестраивается вместе с экраном, а выбор
          // доставки / выключение мессенджера должны отражаться в нём сразу.
          (BuildContext c, VoidCallback close) => StatefulBuilder(builder: (BuildContext sheetContext, StateSetter setSheet) => USheetCard(
            title: s.messenger,
            onClose: close,
            child: MessengerContent(
              core: widget.core,
              delivery: _delivery,
              autoAccept: _autoAccept,
              contacts: _contacts,
              contactsUnavailable: _contactsUnavailable,
              torRunning: _torInfo?.running ?? _status?.torRunning ?? false,
              torPhase: _torInfo?.phase,
              onTorStart: _startTor,
              onTorStop: widget.core is TorControlApi ? _stopTor : null,
              onTorBridges: () { close(); showTorBridgeSettings(_navKey.currentContext ?? context, widget.core); },
              lastTx: latestPayment(_transactions),
              messengerOn: _messengerOn,
              onMessengerToggle: (bool v) { _setMessengerOn(v); setSheet(() {}); },
              onOpenChat: () { close(); _openSheet('chat'); },
              onSettings: () { close(); showMessagingChannelSettings(_navKey.currentContext ?? context, widget.core, preferDirect: true); },
              onDelivery: (String v) { setState(() => _delivery = v); setSheet(() {}); },
              onAutoAccept: _setAutoAccept,
              onAddContact: () { close(); _addWalletContact(); },
              onOpenCatalogue: () { close(); _openContactCatalogue(); },
              onContact: (UContact c) {
                close();
                _openSheet('contact', contact: c);
              },
              showHeader: false,
            ),
          )),
        );
        break;
    }
  }

  /// Системная кнопка «Назад» на экране кошелька завершает приложение, а выход
  /// останавливает сервис кошелька и Tor, поэтому спрашиваем подтверждение.
  Future<void> _confirmQuit() async {
    final BuildContext? ctx = _navKey.currentContext;
    if (ctx == null) return;
    final S s = _s;
    final bool? quit = await showDialog<bool>(
      context: ctx,
      barrierColor: const Color(0xA604070B),
      builder: (BuildContext c) => AlertDialog(
        backgroundColor: UPalette.surface2,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(20),
          side: const BorderSide(color: UPalette.lineStrong),
        ),
        title: Text(s.quitTitle, style: uiStyle(16, weight: FontWeight.w600)),
        content: Text(s.quitBody, style: uiStyle(11.5, color: UPalette.text2, height: 1.5)),
        actions: <Widget>[
          TextButton(onPressed: () => Navigator.of(c).pop(false), child: Text(s.cancel)),
          TextButton(onPressed: () => Navigator.of(c).pop(true), child: Text(s.quitAction)),
        ],
      ),
    );
    if (quit != true || !mounted) return;
    await widget.core.close();
    await SystemNavigator.pop();
  }

  @override
  Widget build(BuildContext context) {
    final double width = MediaQuery.sizeOf(context).width;
    final bool wide = width >= 900;
    final S s = S(_lang);

    Widget screen;
    switch (_screen) {
      case 'login':
        screen = LoginScreen(
          core: widget.core,
          initialNetwork: _network,
          initialMode: widget.initialMode,
          initialCreateStage: widget.initialCreateStage,
          onBack: () => setState(() => _screen = 'boot'),
          onLoggedIn: (String profile, String network) {
            setState(() {
              _walletRevision++;
              _policyRevision++;
              _autoAccept = 'unknown';
              _policySaving = false;
              _profile = profile;
              _network = network;
              _screen = 'wallet';
              _loading = true;
            });
            _loadWallet();
          },
        );
        break;
      case 'wallet':
        if (_status == null) {
          screen = _LoadingScreen(error: _error, loading: _loading, onRetry: _loadWallet);
        } else {
          screen = WalletScreen(
            core: widget.core,
            wide: wide,
            status: _status!,
            contactPhrase: _contactPhrase,
            contactPublication: _contactPublication,
            contactChannel: _contactChannel,
            transactions: _transactions,
            contacts: _contacts,
            contactsUnavailable: _contactsUnavailable,
            delivery: _delivery,
            autoAccept: _autoAccept,
            loading: _loading,
            torRunning: _torInfo?.running ?? _status?.torRunning ?? false,
            torInfo: _torInfo,
            onTorStart: _startTor,
            showCheckpointOffer: _checkpointOffer,
            onCheckpointOffer: () {
              setState(() => _checkpointOffer = false);
              widget.core.markCheckpointOfferSeen();
              _openSheet('verification');
            },
            onDismissCheckpointOffer: () {
              setState(() => _checkpointOffer = false);
              widget.core.markCheckpointOfferSeen();
            },
            onSettings: () => _openSheet('settings'),
            showHistory: _showAllHistory,
            onHistory: () => setState(() => _showAllHistory = !_showAllHistory),
            onOpenOwnCheckpoint: () => _openSheet('own-checkpoint'),
            onLogout: _logout,
            onSend: () => _openSheet('send'),
            onReceive: () => _openSheet('receive'),
            onOpenMessenger: () => _openSheet('messenger'),
            onContact: (UContact contact) => _openSheet('contact', contact: contact),
            onAddContact: _addWalletContact,
            onOpenCatalogue: _openContactCatalogue,
            onDeliveryChanged: (String v) => setState(() => _delivery = v),
            onAutoAcceptChanged: _setAutoAccept,
            onVerification: () => _openSheet('verification'),
            onRefresh: _openWallet,
            messengerOn: _messengerOn,
            onMessengerToggle: _setMessengerOn,
            onTorStop: widget.core is TorControlApi ? _stopTor : null,
            future: _future,
            onFutureToggle: (bool v) { _setFuture(v); },
            mono: _mono,
            onMonoToggle: () => setState(() => _mono = !_mono),
          );
        }
        break;
      default:
        screen = LaunchScreen(
          checkpointUpdated: checkpointAssetsUpdated,
          onLogin: () => setState(() => _screen = 'login'),
          onOption: (String v) => _openSheet(v),
          future: _future,
          onFutureChanged: _setFuture,
          menuInitiallyOpen: !_menuConsumed,
          mono: _mono,
          onMonoToggle: () => setState(() => _mono = !_mono),
        );
    }

    screen = PaymentActions(onCancel: _cancelPayment, onConfirm: _refreshJob == null && !_verificationStarting ? _confirmPayment : null, onResume: _resumePayment,
      onHideCancelled: (id) => unawaited(_hideCancelledBatch([id])),
      onHideAllCancelled: () => unawaited(_hideCancelledBatch(_transactions.where((tx) => tx.stage == TxStage.cancelled).map((tx) => tx.txId).toList(), confirmAll: true)), child: screen);

    screen = RefreshScope(
      active: _refreshJob != null,
      phase: _refreshProgress?.phase ?? '',
      onCancel: _cancelRefresh,
      child: screen,
    );

    return AppLocale(
      s: s,
      lang: _lang,
      onLangChanged: (String v) => setState(() => _lang = v),
      child: MaterialApp(
        navigatorKey: _navKey,
        debugShowCheckedModeBanner: false,
        title: 'GrinSight',
        theme: buildGrinSightTheme(),
        // Монохром в духе grin.mw — фильтром поверх всего приложения (включая окна
        // и диалоги): чёрно-белый с повышенным контрастом (тёмное → почти чёрное,
        // светлое и акценты → белое) и лёгкая растровая «печать» поверх.
        // Структура дерева одинакова в обеих темах (фильтр просто «прозрачный» в цветной),
        // чтобы переключение не сбрасывало открытые окна и состояние экранов.
        // Логотип и кнопка под курсором — цветной копией в слое над фильтром.
        builder: (BuildContext context, Widget? child) => GoldLayerScope(
          controller: _gold,
          mono: _mono,
          onMonoChanged: (bool v) => setState(() => _mono = v),
          child: Stack(fit: StackFit.expand, children: [
            ColorFiltered(
              colorFilter: _mono
                  ? const ColorFilter.matrix(<double>[
                      0.2870, 0.9655, 0.0975, 0, -10,
                      0.2870, 0.9655, 0.0975, 0, -10,
                      0.2870, 0.9655, 0.0975, 0, -10,
                      0, 0, 0, 1, 0,
                    ])
                  : const ColorFilter.matrix(<double>[
                      1, 0, 0, 0, 0,
                      0, 1, 0, 0, 0,
                      0, 0, 1, 0, 0,
                      0, 0, 0, 1, 0,
                    ]),
              child: child ?? const SizedBox.shrink(),
            ),
            if (_mono) const IgnorePointer(child: RepaintBoundary(child: CustomPaint(painter: HalftonePainter()))),
            if (_mono) GoldLayerView(controller: _gold),
          ]),
        ),
        home: PopScope(
          canPop: _screen != 'wallet',
          onPopInvokedWithResult: (bool didPop, Object? result) {
            if (didPop) return;
            unawaited(_confirmQuit());
          },
          child: Scaffold(
            backgroundColor: UPalette.bg,
            resizeToAvoidBottomInset: true,
            body: SafeArea(child: screen),
          ),
        ),
      ),
    );
  }
}

class _LoadingScreen extends StatelessWidget {
  const _LoadingScreen({required this.error, required this.loading, required this.onRetry});

  final String? error;
  final bool loading;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 420),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: UCard(
            padding: const EdgeInsets.all(20),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (error == null)
                  const Center(child: Padding(padding: EdgeInsets.all(8), child: CircularProgressIndicator(color: UPalette.mint)))
                else
                  const Icon(Icons.error_outline_rounded, color: UPalette.amber, size: 30),
                const SizedBox(height: 12),
                Text(error ?? s.loadingWallet, textAlign: TextAlign.center, style: uiStyle(12.5, color: UPalette.text2, height: 1.6)),
                if (error != null) ...[
                  const SizedBox(height: 12),
                  UButton(label: s.refreshAction, primary: true, onTap: onRetry),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}


