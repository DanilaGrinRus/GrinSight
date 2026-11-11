import 'package:flutter/material.dart';

import 'components.dart';
import 'l10n.dart';
import 'theme.dart';

/// Сообщение или платёж в ленте контакта.
class UFeedItem {
  const UFeedItem({
    required this.title,
    required this.titleEn,
    required this.subtitle,
    required this.subtitleEn,
    this.amount,
    this.outgoing = false,
    this.confirmed = false,
  });

  final String title;
  final String titleEn;
  final String subtitle;
  final String subtitleEn;
  final String? amount;
  final bool outgoing;
  final bool confirmed;

  String titleFor(String lang) => lang == 'en' ? titleEn : title;
  String subtitleFor(String lang) => lang == 'en' ? subtitleEn : subtitle;
}

class UContact {
  UContact({
    required this.name,
    required this.fullAddress,
    String? nameEn,
    String? shortAddress,
    this.time = '',
    this.timeEn = '',
    String? initial,
    this.color = UPalette.text2,
    this.background = UPalette.surface3,
    this.border = UPalette.line,
    this.verified = false,
    this.feed = const <UFeedItem>[],
  })  : nameEn = nameEn ?? name,
        shortAddress = shortAddress ?? fullAddress,
        initial = initial ?? name.substring(0, 1);

  final String name;
  final String nameEn;
  final String shortAddress;
  final String fullAddress;
  final String time;
  final String timeEn;
  final String initial;
  final Color color;
  final Color background;
  final Color border;
  final bool verified;
  final List<UFeedItem> feed;

  String nameFor(String lang) => lang == 'en' ? nameEn : name;
  String timeFor(String lang) => lang == 'en' ? timeEn : time;
  String initialFor(String lang) => lang == 'en' ? nameEn.substring(0, 1) : initial;
}

/// Содержимое мессенджера: доставка, автоприём, адресная книга.
class MessengerContent extends StatelessWidget {
  const MessengerContent({
    super.key,
    required this.delivery,
    required this.autoAccept,
    required this.onDelivery,
    required this.onAutoAccept,
    required this.onSettings,
    required this.onContact,
    required this.contacts,
    this.torRunning = false,
    this.onTorStart,
    this.showHeader = true,
  });

  final String delivery;
  final String autoAccept;
  final ValueChanged<String> onDelivery;
  final ValueChanged<String> onAutoAccept;
  final VoidCallback onSettings;
  final ValueChanged<UContact> onContact;
  final List<UContact> contacts;
  final bool torRunning;
  final VoidCallback? onTorStart;
  final bool showHeader;

  int get _autoIndex {
    switch (autoAccept) {
      case 'all':
        return 2;
      case 'off':
        return 0;
      default:
        return 1;
    }
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (showHeader) ...[
          Row(
            children: [
              Expanded(
                child: Text(s.messenger, style: uiStyle(14, weight: FontWeight.w600)),
              ),
              Row(
                children: [
                  Container(
                    width: 7,
                    height: 7,
                    decoration: BoxDecoration(
                      color: torRunning ? UPalette.mint : UPalette.amber,
                      borderRadius: BorderRadius.circular(999),
                      boxShadow: [
                        BoxShadow(color: (torRunning ? UPalette.mint : UPalette.amber).withValues(alpha: 0.14), blurRadius: 6, spreadRadius: 2),
                      ],
                    ),
                  ),
                  const SizedBox(width: 6),
                  Text(torRunning ? s.online : s.torOffline, style: uiStyle(10.5, color: torRunning ? UPalette.text3 : UPalette.amber)),
                  const SizedBox(width: 8),
                  UIconButton(
                    icon: Icons.settings_outlined,
                    onTap: onSettings,
                    size: 30,
                    iconSize: 15,
                    tooltip: s.settingsWallet,
                  ),
                ],
              ),
            ],
          ),
          const SizedBox(height: 14),
        ],
        if (!showHeader) ...[
          Row(
            children: [
              Container(
                width: 7,
                height: 7,
                decoration: BoxDecoration(
                  color: torRunning ? UPalette.mint : UPalette.amber,
                  borderRadius: BorderRadius.circular(999),
                ),
              ),
              const SizedBox(width: 6),
              Text(torRunning ? s.online : s.torOffline, style: uiStyle(10.5, color: torRunning ? UPalette.text3 : UPalette.amber)),
            ],
          ),
          const SizedBox(height: 8),
        ],
        if (!torRunning && onTorStart != null) ...[
          UButton(label: s.torStart, height: 32, dense: true, onTap: onTorStart),
          const SizedBox(height: 10),
        ],
        USegmented(
          options: const ['Tor', 'Relay'],
          selected: delivery == 'grinmail' ? 1 : 0,
          onChanged: (int i) => onDelivery(i == 1 ? 'grinmail' : 'tor'),
          expand: true,
        ),
        const SizedBox(height: 16),
        Text(s.autoAccept, style: uiStyle(12.5, weight: FontWeight.w600)),
        const SizedBox(height: 7),
        USegmented(
          options: <String>[s.autoOff, s.autoContacts, s.autoAll],
          selected: _autoIndex,
          onChanged: (int i) => onAutoAccept(i == 2 ? 'all' : i == 1 ? 'contacts' : 'off'),
          expand: true,
          height: 26,
          fontSize: 11,
        ),
        const SizedBox(height: 18),
        Row(
          children: [
            SectionLabel(s.addressBook),
            const Spacer(),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
              decoration: BoxDecoration(
                color: UPalette.line,
                borderRadius: BorderRadius.circular(999),
              ),
              child: Text(
                '${contacts.length}',
                style: monoStyle(10, weight: FontWeight.w500, color: UPalette.text2, spacing: 0),
              ),
            ),
          ],
        ),
        const SizedBox(height: 4),
        if (contacts.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 12),
            child: Text(s.noContacts, textAlign: TextAlign.center, style: uiStyle(11, color: UPalette.text3)),
          )
        else
          for (final UContact c in contacts)
            _ContactRow(contact: c, onTap: () => onContact(c)),
        if (_recentMessages(contacts).isNotEmpty) ...[
          const SizedBox(height: 18),
          SectionLabel(s.recentMessages),
          const SizedBox(height: 4),
          for (final (UContact, UFeedItem) recent in _recentMessages(contacts))
            _RecentRow(contact: recent.$1, item: recent.$2),
        ],
      ],
    );
  }
}


List<(UContact, UFeedItem)> _recentMessages(List<UContact> contacts) {
  final List<(UContact, UFeedItem)> result = <(UContact, UFeedItem)>[];
  for (final UContact contact in contacts) {
    for (final UFeedItem item in contact.feed) {
      if (item.titleEn == 'Message') {
        result.add((contact, item));
        break;
      }
    }
    if (result.length == 3) break;
  }
  return result;
}

class _RecentRow extends StatelessWidget {
  const _RecentRow({required this.contact, required this.item});

  final UContact contact;
  final UFeedItem item;

  @override
  Widget build(BuildContext context) {
    final AppLocale locale = AppLocale.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5, horizontal: 4),
      child: Row(
        children: [
          Container(
            width: 22,
            height: 22,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: contact.background,
              border: Border.all(color: contact.border),
              borderRadius: BorderRadius.circular(7),
            ),
            child: Text(contact.initialFor(locale.lang), style: uiStyle(10, weight: FontWeight.w700, color: contact.color)),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(contact.nameFor(locale.lang), style: uiStyle(11, weight: FontWeight.w600)),
                Text(
                  item.subtitleFor(locale.lang),
                  style: uiStyle(10.5, color: UPalette.text3),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 6),
          Text(contact.timeFor(locale.lang), style: uiStyle(10, color: UPalette.text3)),
        ],
      ),
    );
  }
}

class _ContactRow extends StatelessWidget {
  const _ContactRow({required this.contact, required this.onTap});

  final UContact contact;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final AppLocale locale = AppLocale.of(context);
    final S s = locale.s;
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(10),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 6),
          child: Row(
            children: [
              Container(
                width: 34,
                height: 34,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: contact.background,
                  border: Border.all(color: contact.border),
                  borderRadius: BorderRadius.circular(11),
                ),
                child: Text(
                  contact.initialFor(locale.lang),
                  style: uiStyle(13, weight: FontWeight.w700, color: contact.color),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Flexible(
                          child: Text(
                            contact.nameFor(locale.lang),
                            style: uiStyle(12.5, weight: FontWeight.w600),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (contact.verified) ...[
                          const SizedBox(width: 4),
                          const Icon(Icons.verified, size: 12, color: UPalette.mint),
                        ],
                      ],
                    ),
                    const SizedBox(height: 1),
                    Text(
                      contact.shortAddress,
                      style: monoStyle(10.5, weight: FontWeight.w400, color: UPalette.text3, spacing: 0),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Text(contact.timeFor(locale.lang), style: uiStyle(10, color: UPalette.text3)),
                  if (contact.verified)
                    Text(s.signature, style: uiStyle(9.5, color: UPalette.mint)),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
