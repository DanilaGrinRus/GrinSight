import 'package:flutter/material.dart';

import '../components.dart';
import '../l10n.dart';
import '../theme.dart';

/// Экран запуска. «Опции» раскрываются прямо на экране (не всплывающим меню):
/// у каждой строки видно текущее состояние, режим «Пощупать будущее» — явный
/// переключатель. Выбор здесь делается ДО входа: сервис запоминает его и
/// применяет к кошельку, который откроется следующим.
class LaunchScreen extends StatefulWidget {
  const LaunchScreen({
    super.key,
    required this.checkpointUpdated,
    required this.onLogin,
    required this.onOption,
    required this.future,
    required this.onFutureChanged,
    this.menuInitiallyOpen = false,
  });

  final bool checkpointUpdated;
  final VoidCallback onLogin;

  /// 'checkpoint' | 'peer' (режим «будущее» меняется переключателем).
  final ValueChanged<String> onOption;
  final bool future;
  final ValueChanged<bool> onFutureChanged;
  final bool menuInitiallyOpen;

  @override
  State<LaunchScreen> createState() => _LaunchScreenState();
}

class _LaunchScreenState extends State<LaunchScreen> {
  late bool _open = widget.menuInitiallyOpen;

  Widget _optionsButton(S s) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(15),
        onTap: () => setState(() => _open = !_open),
        child: Container(
          height: 50,
          width: double.infinity,
          decoration: BoxDecoration(
            color: UPalette.surface,
            border: Border.all(color: UPalette.lineStrong),
            borderRadius: BorderRadius.circular(15),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text(s.options, style: uiStyle(14, weight: FontWeight.w600, color: UPalette.text2)),
              const SizedBox(width: 6),
              Icon(_open ? Icons.keyboard_arrow_up_rounded : Icons.keyboard_arrow_down_rounded, size: 18, color: UPalette.text3),
              if (widget.future && !_open) ...[
                const SizedBox(width: 8),
                Container(
                  width: 8,
                  height: 8,
                  decoration: const BoxDecoration(color: UPalette.violet, shape: BoxShape.circle),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _row({
    required IconData icon,
    required Color iconColor,
    required Color iconBg,
    required Color iconBorder,
    required String title,
    required String hint,
    required Widget trailing,
    VoidCallback? onTap,
    bool first = false,
  }) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        child: Container(
          constraints: const BoxConstraints(minHeight: 64),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            border: first ? null : const Border(top: BorderSide(color: UPalette.line)),
          ),
          child: Row(
            children: [
              UIconBadge(icon: icon, color: iconColor, background: iconBg, border: iconBorder),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(title, style: uiStyle(14, weight: FontWeight.w600)),
                    const SizedBox(height: 2),
                    Text(hint, style: uiStyle(12, color: UPalette.text3, height: 1.3)),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              trailing,
            ],
          ),
        ),
      ),
    );
  }

  Widget _optionsPanel(S s) {
    const Widget chevron = Icon(Icons.chevron_right_rounded, size: 20, color: UPalette.text3);
    return Container(
      decoration: BoxDecoration(
        color: UPalette.surface2,
        border: Border.all(color: UPalette.lineStrong),
        borderRadius: BorderRadius.circular(16),
      ),
      clipBehavior: Clip.antiAlias,
      child: Column(
        children: [
          _row(
            first: true,
            icon: Icons.refresh_rounded,
            iconColor: UPalette.text2,
            iconBg: UPalette.surface3,
            iconBorder: UPalette.line,
            title: s.menuCheckpoint,
            hint: widget.checkpointUpdated ? s.checkpointRevised : s.checkpointBundledOk,
            // Проверить чекпоинт самому (от genesis) можно и до входа.
            onTap: () => widget.onOption('own-checkpoint'),
            trailing: UButton(
              key: const Key('launch-own-checkpoint'),
              label: s.checkFromGenesis,
              height: 34,
              dense: true,
              expand: false,
              onTap: () => widget.onOption('own-checkpoint'),
            ),
          ),
          _row(
            icon: Icons.auto_awesome_outlined,
            iconColor: UPalette.violet,
            iconBg: UPalette.violetBg,
            iconBorder: const Color(0x57A78BFA),
            title: s.menuFuture,
            hint: widget.future ? s.futureOnHint : s.futureOffHint,
            onTap: () => widget.onFutureChanged(!widget.future),
            trailing: USwitch(key: const Key('launch-future-switch'), value: widget.future, onChanged: widget.onFutureChanged),
          ),
          _row(
            icon: Icons.public_rounded,
            iconColor: UPalette.blue,
            iconBg: UPalette.blueBg,
            iconBorder: UPalette.blueLine,
            title: s.menuPeer,
            hint: s.menuPeerHint,
            onTap: () => widget.onOption('peer'),
            trailing: chevron,
          ),
        ],
      ),
    );
  }

  /// «✦ Revelio for your coins»: заклинание акцентом, остальное тише.
  Widget _slogan() {
    return Text.rich(
      TextSpan(
        children: [
          TextSpan(
            text: '✦ ',
            style: uiStyle(16, color: UPalette.violet),
          ),
          TextSpan(
            text: 'Revelio',
            style: uiStyle(19, weight: FontWeight.w700, color: UPalette.mint).copyWith(fontStyle: FontStyle.italic, letterSpacing: 0.2),
          ),
          TextSpan(
            text: ' for your coins',
            style: uiStyle(15, color: UPalette.text2).copyWith(fontStyle: FontStyle.italic),
          ),
        ],
      ),
      textAlign: TextAlign.center,
    );
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 400),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Align(alignment: Alignment.centerRight, child: ULanguageToggle()),
              const SizedBox(height: 6),
              TweenAnimationBuilder<double>(
                tween: Tween<double>(begin: 0, end: 1),
                duration: const Duration(milliseconds: 420),
                curve: Curves.easeOutCubic,
                builder: (BuildContext context, double t, Widget? child) => Opacity(
                  opacity: t,
                  child: Transform.translate(offset: Offset(0, (1 - t) * 8), child: child),
                ),
                child: Center(
                  child: Column(
                    children: [
                      const ULogo(size: 64),
                      const SizedBox(height: 16),
                      Text('GrinSight', style: uiStyle(28, weight: FontWeight.w700).copyWith(letterSpacing: -0.4)),
                      const SizedBox(height: 8),
                      _slogan(),
                      const SizedBox(height: 6),
                      Text(s.lightWallet, style: uiStyle(12, color: UPalette.text3)),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 30),
              UButton(
                key: const Key('launch-login'),
                label: s.login,
                primary: true,
                height: 52,
                onTap: widget.onLogin,
              ),
              const SizedBox(height: 10),
              _optionsButton(s),
              if (_open) ...[
                const SizedBox(height: 10),
                _optionsPanel(s),
              ],
              if (!kReleaseBuild) ...[
                const SizedBox(height: 28),
                Text(
                  s.prototypeDemo,
                  textAlign: TextAlign.center,
                  style: uiStyle(12, color: UPalette.text3),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
