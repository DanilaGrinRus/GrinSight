import 'package:flutter/material.dart';

import '../components.dart';
import '../l10n.dart';
import '../theme.dart';

class LaunchScreen extends StatefulWidget {
  const LaunchScreen({
    super.key,
    required this.checkpointUpdated,
    required this.onLogin,
    required this.onOption,
    this.menuInitiallyOpen = false,
  });

  final bool checkpointUpdated;
  final VoidCallback onLogin;
  final ValueChanged<String> onOption;
  final bool menuInitiallyOpen;

  @override
  State<LaunchScreen> createState() => _LaunchScreenState();
}

class _LaunchScreenState extends State<LaunchScreen> {
  final GlobalKey<PopupMenuButtonState<String>> _menuKey = GlobalKey<PopupMenuButtonState<String>>();

  @override
  void initState() {
    super.initState();
    if (widget.menuInitiallyOpen) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) return;
        _menuKey.currentState?.showButtonMenu();
      });
    }
  }

  Widget _optionsButton(S s) {
    return Container(
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
          Text(s.options, style: uiStyle(13.5, weight: FontWeight.w600, color: UPalette.text2)),
          const SizedBox(width: 6),
          const Icon(Icons.keyboard_arrow_down_rounded, size: 17, color: UPalette.text3),
        ],
      ),
    );
  }

  PopupMenuItem<String> _menuItem({
    required String value,
    required String title,
    required String hint,
    required IconData icon,
    required Color iconColor,
    required Color iconBg,
    required Color iconBorder,
  }) {
    return PopupMenuItem<String>(
      value: value,
      height: 62,
      padding: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            UIconBadge(icon: icon, color: iconColor, background: iconBg, border: iconBorder),
            const SizedBox(width: 11),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(title, style: uiStyle(12.5, weight: FontWeight.w600)),
                  const SizedBox(height: 1),
                  Text(hint, style: uiStyle(10.5, color: UPalette.text3, height: 1.35)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final double menuWidth = MediaQuery.sizeOf(context).width - 48 < 400 ? MediaQuery.sizeOf(context).width - 48 : 400;
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
              Center(
                child: Column(
                  children: [
                    const ULogo(size: 64),
                    const SizedBox(height: 16),
                    Text('GrinSight', style: uiStyle(27, weight: FontWeight.w700).copyWith(letterSpacing: -0.4)),
                    const SizedBox(height: 3),
                    Text(s.lightWallet, style: uiStyle(13, color: UPalette.text2)),
                    const SizedBox(height: 9),
                    Text(
                      '«Revelio for your coins»',
                      style: uiStyle(11.5, color: UPalette.text3).copyWith(letterSpacing: 0.3),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 34),
              UButton(
                key: const Key('launch-login'),
                label: s.login,
                primary: true,
                height: 50,
                onTap: widget.onLogin,
              ),
              const SizedBox(height: 10),
              PopupMenuButton<String>(
                key: _menuKey,
                tooltip: '',
                color: UPalette.surface2,
                surfaceTintColor: Colors.transparent,
                elevation: 18,
                offset: const Offset(0, 58),
                constraints: BoxConstraints(minWidth: menuWidth, maxWidth: menuWidth),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(16),
                  side: const BorderSide(color: UPalette.lineStrong),
                ),
                onSelected: widget.onOption,
                itemBuilder: (BuildContext context) => <PopupMenuEntry<String>>[
                  _menuItem(
                    value: 'checkpoint',
                    title: s.menuCheckpoint,
                    hint: s.menuCheckpointHint,
                    icon: Icons.refresh_rounded,
                    iconColor: UPalette.text2,
                    iconBg: UPalette.surface3,
                    iconBorder: UPalette.line,
                  ),
                  _menuItem(
                    value: 'future',
                    title: s.menuFuture,
                    hint: s.menuFutureHint,
                    icon: Icons.auto_awesome_outlined,
                    iconColor: UPalette.violet,
                    iconBg: UPalette.violetBg,
                    iconBorder: const Color(0x57A78BFA),
                  ),
                  _menuItem(
                    value: 'peer',
                    title: s.menuPeer,
                    hint: s.menuPeerHint,
                    icon: Icons.public_rounded,
                    iconColor: UPalette.blue,
                    iconBg: UPalette.blueBg,
                    iconBorder: UPalette.blueLine,
                  ),
                ],
                child: _optionsButton(s),
              ),
              const SizedBox(height: 13),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Container(
                    width: 7,
                    height: 7,
                    decoration: BoxDecoration(
                      color: UPalette.mint,
                      borderRadius: BorderRadius.circular(999),
                      boxShadow: [
                        BoxShadow(color: UPalette.mint.withValues(alpha: 0.14), blurRadius: 6, spreadRadius: 2),
                      ],
                    ),
                  ),
                  const SizedBox(width: 7),
                  Flexible(
                    child: Text(
                      widget.checkpointUpdated ? s.checkpointRevised : s.checkpointStatus,
                      textAlign: TextAlign.center,
                      style: uiStyle(11, color: UPalette.text3),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 30),
              Text(
                s.localKeysHint,
                textAlign: TextAlign.center,
                style: uiStyle(10.5, color: UPalette.text3, height: 1.6),
              ),
              const SizedBox(height: 34),
              Text(
                s.prototypeDemo,
                textAlign: TextAlign.center,
                style: uiStyle(10.5, color: UPalette.text3).copyWith(fontSize: 10.5),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

