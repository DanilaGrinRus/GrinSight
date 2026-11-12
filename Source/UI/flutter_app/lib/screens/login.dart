import 'dart:math' show Random;

import 'package:flutter/material.dart';

import '../components.dart';
import '../core.dart';
import '../l10n.dart';
import '../theme.dart';
import '../wallet_model.dart';

enum LoginMode { open, restore, create }

/// Две позиции (с 0) слов для проверки записи фразы: выбираются случайно
/// (Random.secure) и не ближе друг к другу, чем [minGap] слов: 12 слов -> 4,
/// 18 -> 6, 24 -> 10. Всегда `a < b`.
List<int> pickCheckPositions(int n, {Random? rng}) {
  final int gap = n >= 24 ? 10 : (n >= 18 ? 6 : 4);
  final Random r = rng ?? Random.secure();
  final int a = r.nextInt(n);
  final List<int> far = <int>[for (int j = 0; j < n; j++) if ((j - a).abs() >= gap) j];
  final int b = far[r.nextInt(far.length)];
  return a < b ? <int>[a, b] : <int>[b, a];
}

/// Допустимая длина фразы при восстановлении (BIP39).
bool isPhraseLength(int n) => n == 12 || n == 15 || n == 18 || n == 21 || n == 24;

class LoginScreen extends StatefulWidget {
  const LoginScreen({
    super.key,
    required this.onBack,
    required this.onLoggedIn,
    required this.core,
    this.initialNetwork = 'mainnet',
    this.initialMode,
    this.initialCreateStage = 0,
  });

  final VoidCallback onBack;
  final void Function(String profile, String network) onLoggedIn;
  final WalletCore core;
  final String initialNetwork;
  final String? initialMode;
  final int initialCreateStage;

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  S get s => AppLocale.of(context).s;

  final TextEditingController _login = TextEditingController();
  final TextEditingController _pass = TextEditingController();
  final TextEditingController _seed = TextEditingController();
  final TextEditingController _wordA = TextEditingController();
  final TextEditingController _wordB = TextEditingController();

  LoginMode _mode = LoginMode.open;
  int _network = 0;
  int _createStage = 0;
  bool _seedHidden = true;
  bool _passHidden = true;
  int _words = 24; // длина создаваемой фразы: 12 | 18 | 24
  List<int> _checkIdx = <int>[0, 0]; // позиции слов для проверки (с 0)
  bool _savedPhrase = false;
  bool _busy = false;
  bool _profilesLoading = true;
  bool _advanced = false;
  String? _error;
  List<String> _phrase = <String>[];
  List<WalletProfile> _profiles = <WalletProfile>[];
  WalletProfile? _selectedProfile;

  @override
  void initState() {
    super.initState();
    _network = widget.initialNetwork == 'floonet' ? 1 : 0;
    _advanced = _network == 1;
    switch (widget.initialMode) {
      case 'restore':
        _mode = LoginMode.restore;
      case 'create':
        _mode = LoginMode.create;
        _createStage = widget.initialCreateStage.clamp(0, 2);
      default:
        _mode = LoginMode.open;
    }
    _loadProfiles();
  }

  @override
  void dispose() {
    _login.dispose();
    _pass.dispose();
    _seed.dispose();
    _wordA.dispose();
    _wordB.dispose();
    super.dispose();
  }

  String get _networkName {
    if (_mode == LoginMode.open && _selectedProfile != null) return _selectedProfile!.network;
    return _network == 1 ? 'floonet' : 'mainnet';
  }

  Future<void> _loadProfiles() async {
    try {
      final List<WalletProfile> profiles = await widget.core.profiles();
      if (!mounted) return;
      setState(() {
        _profiles = profiles;
        WalletProfile? pick;
        final List<WalletProfile> recent = profiles.where((WalletProfile p) => p.lastUsed > 0).toList()
          ..sort((WalletProfile a, WalletProfile b) => b.lastUsed.compareTo(a.lastUsed));
        if (recent.isNotEmpty) {
          pick = recent.first;
        } else {
          for (final WalletProfile p in profiles) {
            if (p.network == 'mainnet') {
              pick = p;
              break;
            }
          }
        }
        _selectedProfile = pick;
        _network = pick?.network == 'floonet' ? 1 : 0;
        _advanced = _network == 1;
        _profilesLoading = false;
        // Профилей нет: вкладки «Открыть» нет, начинаем с «Создать».
        if (profiles.isEmpty && _mode == LoginMode.open) _mode = LoginMode.create;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _profilesLoading = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  void _changeMode(LoginMode mode) {
    setState(() {
      _mode = mode;
      _createStage = 0;
      _savedPhrase = false;
      _wordA.clear();
      _wordB.clear();
      _seed.clear();
      _error = null;
    });
  }

  bool _checkPassword() {
    if (_pass.text.isEmpty) {
      showToast(context, s.enterPassword);
      return false;
    }
    if (_pass.text.length < 8) {
      showToast(context, s.passwordMin8);
      return false;
    }
    return true;
  }

  bool _checkLogin() {
    if (_login.text.trim().isEmpty) {
      showToast(context, s.enterLogin);
      return false;
    }
    return true;
  }

  Future<void> _open() async {
    if (_selectedProfile == null) {
      showToast(context, _profiles.isEmpty ? s.noProfiles : s.chooseProfile);
      return;
    }
    if (!_checkPassword()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.core.unlock(login: _selectedProfile!.name, password: _pass.text, network: _selectedProfile!.network);
      if (!mounted) return;
      _pass.clear();
      widget.onLoggedIn(_selectedProfile!.name, _selectedProfile!.network);
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = widget.core.describeError(e));
      showToast(context, widget.core.describeError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _restore() async {
    if (!_checkLogin() || !_checkPassword()) return;
    final List<String> words = _seed.text.trim().split(RegExp(r'\s+')).where((String w) => w.isNotEmpty).toList();
    if (words.isEmpty) {
      showToast(context, s.enterSeed);
      return;
    }
    if (!isPhraseLength(words.length)) {
      showToast(context, s.seedNeeds24);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.core.checkPhrase(_seed.text.trim());
      await widget.core.importWallet(
        login: _login.text.trim(),
        phrase: _seed.text.trim(),
        password: _pass.text,
        network: _networkName,
      );
      if (!mounted) return;
      _seed.clear();
      _pass.clear();
      widget.onLoggedIn(_login.text.trim(), _networkName);
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = widget.core.describeError(e));
      showToast(context, widget.core.describeError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _generatePhrase() async {
    if (!_checkLogin() || !_checkPassword()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final String phrase = await widget.core.newPhrase(words: _words);
      if (!mounted) return;
      setState(() {
        _phrase = phrase.trim().split(RegExp(r'\s+'));
        _checkIdx = pickCheckPositions(_phrase.length);
        _createStage = 1;
        _savedPhrase = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = widget.core.describeError(e));
      showToast(context, widget.core.describeError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _phraseContinue() {
    if (!_savedPhrase) {
      showToast(context, s.confirmSavedPhrase);
      return;
    }
    setState(() => _createStage = 2);
  }

  Future<void> _create() async {
    if (_phrase.isEmpty) {
      await _generatePhrase();
      return;
    }
    if (_wordA.text.trim().toLowerCase() != _phrase[_checkIdx[0]] || _wordB.text.trim().toLowerCase() != _phrase[_checkIdx[1]]) {
      showToast(context, s.wordsMismatch);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    final String phrase = _phrase.join(' ');
    try {
      await widget.core.createWallet(
        login: _login.text.trim(),
        phrase: phrase,
        password: _pass.text,
        network: _networkName,
      );
      if (!mounted) return;
      _phrase = <String>[];
      _pass.clear();
      widget.onLoggedIn(_login.text.trim(), _networkName);
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = widget.core.describeError(e));
      showToast(context, widget.core.describeError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Widget _profileField() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: UPalette.fieldBg,
        border: Border.all(color: UPalette.lineStrong),
        borderRadius: BorderRadius.circular(13),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(s.profile, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.text3)),
                const SizedBox(height: 2),
                Text(
                  _profilesLoading
                      ? s.profilesLoading
                      : (_selectedProfile?.name ?? (_profiles.isEmpty ? s.noProfiles : s.chooseProfile)),
                  style: uiStyle(13.5, weight: FontWeight.w600, color: _selectedProfile == null ? UPalette.text3 : UPalette.text),
                ),
                if (_selectedProfile != null)
                  Text(
                    '${networkLabel(_selectedProfile!.network)} · ${s.profileHint}',
                    style: uiStyle(10.5, color: UPalette.text3),
                  ),
              ],
            ),
          ),
          Icon(_profiles.isNotEmpty ? Icons.keyboard_arrow_down_rounded : Icons.person_outline_rounded, size: 19, color: UPalette.text3),
        ],
      ),
    );
  }

  /// Поле профиля: тап по всему полю открывает список под ним (раньше меню
  /// привязывалось к стрелке и рисовалось поверх поля пароля).
  Widget _profileRow() {
    final Widget field = _profileField();
    if (_profiles.isEmpty) return field;
    return LayoutBuilder(
      builder: (BuildContext context, BoxConstraints c) => PopupMenuButton<WalletProfile>(
        tooltip: '',
        color: UPalette.surface2,
        surfaceTintColor: Colors.transparent,
        position: PopupMenuPosition.under,
        offset: const Offset(0, 6),
        constraints: BoxConstraints(minWidth: c.maxWidth, maxWidth: c.maxWidth),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(14),
          side: const BorderSide(color: UPalette.lineStrong),
        ),
        onSelected: (WalletProfile p) {
          setState(() {
            _selectedProfile = p;
            _network = p.network == 'floonet' ? 1 : 0;
          });
        },
        itemBuilder: (BuildContext context) => _profiles
            .map((WalletProfile p) => PopupMenuItem<WalletProfile>(
                  value: p,
                  height: 44,
                  child: Text('${p.name} · ${networkLabel(p.network)}', style: uiStyle(14)),
                ))
            .toList(),
        child: field,
      ),
    );
  }

  /// Действие главной кнопки (его же вызывает Enter в полях); null, пока идёт работа.
  VoidCallback? get _primaryAction => _busy
      ? null
      : switch (_mode) {
          LoginMode.open => _open,
          LoginMode.restore => _restore,
          LoginMode.create => _createStage == 0
              ? _generatePhrase
              : _createStage == 1
                  ? _phraseContinue
                  : _create,
        };

  Widget _seedField() {
    return UTextField(
      label: s.seedLabel,
      controller: _seed,
      hint: s.seedHint,
      obscure: _seedHidden,
      keyboardType: TextInputType.visiblePassword,
      autocorrect: false,
      enableSuggestions: false,
      fieldKey: const Key('login-seed'),
      suffix: IconButton(
        icon: Icon(_seedHidden ? Icons.visibility_outlined : Icons.visibility_off_outlined, size: 18, color: UPalette.text3),
        onPressed: () => setState(() => _seedHidden = !_seedHidden),
        tooltip: _seedHidden ? s.showSeed : s.hideSeed,
      ),
    );
  }

  Widget _phraseWordsPanel() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: UPalette.fieldBg,
            border: Border.all(color: UPalette.lineStrong),
            borderRadius: BorderRadius.circular(13),
          ),
          child: Wrap(
            spacing: 10,
            runSpacing: 6,
            children: <Widget>[
              for (int i = 0; i < _phrase.length; i++)
                SizedBox(
                  width: 100,
                  child: Text(
                    '${i + 1}. ${_phrase[i]}',
                    style: monoStyle(12, weight: FontWeight.w400, color: UPalette.text2, spacing: 0),
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: 8),
        Text(s.phraseWarning, style: uiStyle(11, color: UPalette.amber, height: 1.5)),
        const SizedBox(height: 10),
        UCheckline(
          title: s.savedPhrase,
          subtitle: s.savedPhraseHint,
          value: _savedPhrase,
          onChanged: (bool v) => setState(() => _savedPhrase = v),
        ),
      ],
    );
  }

  Widget _phraseCheckPanel() {
    final int a = _checkIdx[0] + 1;
    final int b = _checkIdx[1] + 1;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(s.phraseCheckNote(a, b), style: uiStyle(12, color: UPalette.text3, height: 1.5)),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: UTextField(label: s.wordNo(a), controller: _wordA, fieldKey: const Key('login-word-a')),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: UTextField(label: s.wordNo(b), controller: _wordB, fieldKey: const Key('login-word-b')),
            ),
          ],
        ),
      ],
    );
  }

  /// Выбор длины новой фразы (до генерации).
  Widget _phraseLengthPicker() {
    const List<int> options = <int>[12, 18, 24];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(s.phraseLength, style: uiStyle(12, weight: FontWeight.w600, color: UPalette.text2)),
        const SizedBox(height: 6),
        USegmented(
          options: <String>[for (final int n in options) '$n'],
          selected: options.indexOf(_words),
          expand: true,
          height: 36,
          fontSize: 13,
          onChanged: (int i) => setState(() => _words = options[i]),
        ),
        const SizedBox(height: 6),
        Text(s.phraseLengthHint, style: uiStyle(12, color: UPalette.text3, height: 1.5)),
      ],
    );
  }

  Widget _formFields() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (_mode == LoginMode.open) ...[
          _profileRow(),
          const SizedBox(height: 12),
        ] else ...[
          UTextField(
            label: s.loginLabel,
            controller: _login,
            hint: s.loginHint,
            fieldKey: const Key('login-name'),
          ),
          const SizedBox(height: 12),
        ],
        UTextField(
          label: s.password,
          controller: _pass,
          hint: s.passwordHint,
          obscure: _passHidden,
          fieldKey: const Key('login-pass'),
          onSubmitted: _primaryAction,
          suffix: IconButton(
            icon: Icon(_passHidden ? Icons.visibility_outlined : Icons.visibility_off_outlined, size: 18, color: UPalette.text3),
            onPressed: () => setState(() => _passHidden = !_passHidden),
            tooltip: _passHidden ? s.showSeed : s.hideSeed,
          ),
        ),
        if (_mode == LoginMode.create && _createStage == 0) ...[
          const SizedBox(height: 14),
          _phraseLengthPicker(),
        ],
        if (_mode == LoginMode.restore) ...[
          const SizedBox(height: 12),
          _seedField(),
          const SizedBox(height: 6),
          Text(s.seedCoreHint, style: uiStyle(11, color: UPalette.text3, height: 1.5)),
        ],
        if (_mode == LoginMode.open && _profiles.isEmpty && !_profilesLoading) ...[
          const SizedBox(height: 8),
          Text(s.noProfiles, style: uiStyle(11, color: UPalette.amber, height: 1.5)),
        ],
        if (_mode == LoginMode.create && _createStage == 1) ...[
          const SizedBox(height: 12),
          _phraseWordsPanel(),
        ],
        if (_mode == LoginMode.create && _createStage == 2) ...[
          const SizedBox(height: 12),
          _phraseCheckPanel(),
        ],
        if (_error != null) ...[
          const SizedBox(height: 8),
          Text(_error!, style: uiStyle(11, color: UPalette.amber, height: 1.5)),
        ],
        const SizedBox(height: 14),
        UButton(
          key: const Key('login-submit'),
          label: switch (_mode) {
            LoginMode.open => s.openWallet,
            LoginMode.restore => s.restoreAction,
            LoginMode.create => _createStage == 0
                ? s.generatePhrase
                : _createStage == 1
                    ? s.continueLabel
                    : s.createWallet,
          },
          primary: true,
          onTap: _primaryAction,
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Align(
                      alignment: Alignment.centerLeft,
                      child: Material(
                        color: Colors.transparent,
                        child: InkWell(
                          borderRadius: BorderRadius.circular(8),
                          onTap: widget.onBack,
                          child: Padding(
                            padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 2),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const Icon(Icons.arrow_back_rounded, size: 15, color: UPalette.text3),
                                const SizedBox(width: 6),
                                Text(s.back, style: uiStyle(12, weight: FontWeight.w600, color: UPalette.text3)),
                              ],
                            ),
                          ),
                        ),
                      ),
                    ),
                  ),
                  ULanguageToggle(),
                ],
              ),
              const SizedBox(height: 16),
              Text(s.loginTitle, style: uiStyle(25, weight: FontWeight.w700).copyWith(letterSpacing: -0.3)),
              const SizedBox(height: 14),
              UCard(
                padding: const EdgeInsets.all(18),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(s.profileAndNetwork, style: uiStyle(11.5, weight: FontWeight.w600, color: UPalette.text2)),
                        ),
                        const SizedBox(width: 8),
                        if (_mode != LoginMode.open)
                          TextButton(
                            onPressed: () => setState(() => _advanced = !_advanced),
                            child: Text(s.advanced, style: uiStyle(10.5, weight: FontWeight.w600, color: UPalette.text3)),
                          )
                        else if (_selectedProfile?.network == 'floonet')
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
                            decoration: BoxDecoration(color: UPalette.amberBg, border: Border.all(color: UPalette.amberLine), borderRadius: BorderRadius.circular(999)),
                            child: Text('TESTNET', style: uiStyle(10.5, weight: FontWeight.w600, color: UPalette.amber).copyWith(letterSpacing: 0.4)),
                          ),
                      ],
                    ),
                    if (_mode != LoginMode.open && _advanced) ...[
                      const SizedBox(height: 6),
                      USegmented(
                        options: const ['Mainnet', 'Testnet'],
                        selected: _network,
                        height: 26,
                        fontSize: 12,
                        onChanged: (int i) => setState(() => _network = i),
                      ),
                      const SizedBox(height: 6),
                      Text(s.networkHint, style: uiStyle(12, color: UPalette.text3, height: 1.5)),
                    ],
                    const SizedBox(height: 12),
                    Builder(builder: (BuildContext context) {
                      // Пока профилей нет, вкладки «Открыть» нет.
                      final List<LoginMode> modes = (_profiles.isEmpty && !_profilesLoading)
                          ? const <LoginMode>[LoginMode.restore, LoginMode.create]
                          : LoginMode.values;
                      String label(LoginMode m) => switch (m) {
                            LoginMode.open => s.modeOpen,
                            LoginMode.restore => s.modeRestore,
                            LoginMode.create => s.modeCreate,
                          };
                      return USegmented(
                        options: <String>[for (final LoginMode m in modes) label(m)],
                        selected: modes.contains(_mode) ? modes.indexOf(_mode) : 0,
                        expand: true,
                        height: 36,
                        fontSize: 13,
                        onChanged: (int i) => _changeMode(modes[i]),
                      );
                    }),
                    const SizedBox(height: 14),
                    _formFields(),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(Icons.verified_user_outlined, size: 13, color: UPalette.mint),
                  const SizedBox(width: 6),
                  Flexible(
                    child: Text(s.keysStayHint, textAlign: TextAlign.center, style: uiStyle(10.5, color: UPalette.text3)),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
