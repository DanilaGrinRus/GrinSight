// ignore_for_file: use_build_context_synchronously

import 'dart:ui' show AppExitResponse;

import 'package:flutter/material.dart';

import 'backend/backend.dart';
import 'components.dart';
import 'core.dart';
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
    UnityApp(
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
      theme: buildUnityTheme(),
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

class UnityApp extends StatefulWidget {
  const UnityApp({
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

  @override
  State<UnityApp> createState() => _UnityAppState();
}

class _UnityAppState extends State<UnityApp> with WidgetsBindingObserver {
  final GlobalKey<NavigatorState> _navKey = GlobalKey<NavigatorState>();

  late String _screen;
  late String _lang;
  String _network = 'mainnet';
  String _profile = '';
  String _delivery = 'tor';
  String _autoAccept = 'contacts';
  bool _future = false;
  bool _loading = false;
  bool _checkpointOffer = false;
  bool _checkpointOfferEvaluated = false;
  String? _error;

  WalletStatus? _status;
  List<WalletTx> _transactions = <WalletTx>[];
  List<UContact> _contacts = <UContact>[];

  String? _pendingSheet;
  int _pendingStep = 0;
  bool _menuConsumed = true;

  S get _s => S(_lang);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
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
    if (!mounted) return;
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final WalletStatus status = await widget.core.status();
      final List<WalletTx> txs = await widget.core.payments();
      List<ContactInfo> rawContacts = <ContactInfo>[];
      try {
        rawContacts = await widget.core.contacts();
      } catch (_) {
        rawContacts = <ContactInfo>[];
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
      );
      bool offerSeen = false;
      bool ownBuilt = false;
      try {
        final CheckpointInfo ci = await widget.core.checkpointInfo();
        offerSeen = ci.offerSeen;
        ownBuilt = ci.ownBuilt;
      } catch (_) {}
      final List<UContact> contacts = rawContacts.map((ContactInfo c) => _contact(c, txs)).toList();
      if (!mounted) return;
      setState(() {
        _status = live;
        _transactions = txs;
        _contacts = contacts;
        _loading = false;
        _profile = live.profile;
        _network = live.network;
        if (!_checkpointOfferEvaluated) {
          _checkpointOfferEvaluated = true;
          _checkpointOffer = live.proof.hasSession && !offerSeen && !ownBuilt;
        }
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = widget.core.describeError(e);
      });
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
      verified: false,
      feed: feed,
    );
  }

  Future<void> _openWallet() async {
    try {
      final WalletJob job = await widget.core.openJob();
      if (!mounted) return;
      final BuildContext? ctx = _navKey.currentContext;
      if (ctx == null) return;
      await showUSheet<void>(
        ctx,
        (BuildContext c, VoidCallback close) => JobProgressSheet(
          core: widget.core,
          job: job,
          title: _s.checkpoint,
          onClose: close,
        ),
      );
      await _loadWallet();
    } catch (e) {
      if (!mounted) return;
      showToast(context, widget.core.describeError(e));
    }
  }

  Future<void> _startTor() async {
    try {
      await widget.core.torStart();
      await Future<void>.delayed(const Duration(seconds: 1));
      await _loadWallet();
    } catch (e) {
      if (!mounted) return;
      showToast(context, widget.core.describeError(e));
    }
  }

  Future<void> _setAutoAccept(String v) async {
    setState(() => _autoAccept = v);
    try {
      await widget.core.autoAccept(v);
    } catch (e) {
      if (!mounted) return;
      showToast(context, widget.core.describeError(e));
    }
  }

  Future<void> _logout() async {
    await widget.core.lock();
    if (!mounted) return;
    setState(() {
      _screen = 'boot';
      _status = null;
      _transactions = <WalletTx>[];
      _contacts = <UContact>[];
      _profile = '';
    });
  }

  Future<void> _openSheet(String name, {int step = 0, String? to, UContact? contact}) async {
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
            initialStep: step,
            initialTo: to,
          ),
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
          (BuildContext c, VoidCallback close) => ContactFeedSheet(onClose: close, contact: feedContact),
        );
        break;
      case 'checkpoint':
        await _openWallet();
        break;
      case 'settings':
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => SettingsSheet(
            onClose: close,
            profile: _profile,
            networkLabel: networkLabel(_network),
            delivery: _delivery,
            autoAccept: _autoAccept,
            futureEnabled: _future,
            onDeliveryChanged: (String v) => setState(() => _delivery = v),
            onAutoAcceptChanged: _setAutoAccept,
            onFutureChanged: (bool v) => setState(() => _future = v),
            onCheckpoint: () {
              close();
              _openWallet();
            },
            onPeer: () {
              close();
              _openSheet('peer');
            },
            onLogout: () {
              close();
              _logout();
            },
          ),
        );
        break;
      case 'future':
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => FutureSheet(
            onClose: close,
            enabled: _future,
            onChanged: (bool v) => setState(() => _future = v),
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
      case 'messenger':
        await showUSheet<void>(
          ctx,
          (BuildContext c, VoidCallback close) => USheetCard(
            title: s.messenger,
            onClose: close,
            child: MessengerContent(
              delivery: _delivery,
              autoAccept: _autoAccept,
              contacts: _contacts,
              torRunning: _status?.torRunning ?? false,
              onTorStart: _startTor,
              onDelivery: (String v) => setState(() => _delivery = v),
              onAutoAccept: _setAutoAccept,
              onSettings: () {
                close();
                _openSheet('settings');
              },
              onContact: (UContact c) {
                close();
                _openSheet('contact', contact: c);
              },
              showHeader: false,
            ),
          ),
        );
        break;
    }
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
            wide: wide,
            status: _status!,
            transactions: _transactions,
            contacts: _contacts,
            delivery: _delivery,
            autoAccept: _autoAccept,
            loading: _loading,
            torRunning: _status?.torRunning ?? false,
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
            onSend: () => _openSheet('send'),
            onReceive: () => _openSheet('receive'),
            onOpenMessenger: () => _openSheet('messenger'),
            onContact: (UContact contact) => _openSheet('contact', contact: contact),
            onDeliveryChanged: (String v) => setState(() => _delivery = v),
            onAutoAcceptChanged: _setAutoAccept,
            onVerification: () => _openSheet('verification'),
            onRefresh: _openWallet,
          );
        }
        break;
      default:
        screen = LaunchScreen(
          checkpointUpdated: false,
          onLogin: () => setState(() => _screen = 'login'),
          onOption: (String v) => _openSheet(v),
          menuInitiallyOpen: !_menuConsumed,
        );
    }

    return AppLocale(
      s: s,
      lang: _lang,
      onLangChanged: (String v) => setState(() => _lang = v),
      child: MaterialApp(
        navigatorKey: _navKey,
        debugShowCheckedModeBanner: false,
        title: 'GrinSight',
        theme: buildUnityTheme(),
        home: Scaffold(
          backgroundColor: UPalette.bg,
          resizeToAvoidBottomInset: true,
          body: SafeArea(child: screen),
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


