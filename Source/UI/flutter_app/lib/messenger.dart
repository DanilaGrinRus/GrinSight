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
  final ValueChanged<UContact> onContact;
  final List<UContact> contacts;
  final bool torRunning;
  final VoidCallback? onTorStart;
  final bool showHeader;

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
        // Управление доставкой и автоприёмом живёт только здесь, в блоке мессенджера.
        _ControlRow(
          label: s.delivery,
          child: USegmented(
            options: const ['Tor', 'Relay'],
            selected: delivery == 'grinmail' ? 1 : 0,
            height: 30,
            fontSize: 12,
            onChanged: (int i) => onDelivery(i == 1 ? 'grinmail' : 'tor'),
          ),
        ),
        const SizedBox(height: 8),
        _ControlRow(
          label: s.autoAccept,
          child: UAutoAcceptPicker(mode: autoAccept, onChanged: onAutoAccept),
        ),
        const SizedBox(height: 18),
        _AddressBook(contacts: contacts, onContact: onContact),
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

class _AddressBook extends StatefulWidget {
  const _AddressBook({required this.contacts, required this.onContact});

  final List<UContact> contacts;
  final ValueChanged<UContact> onContact;

  @override
  State<_AddressBook> createState() => _AddressBookState();
}

class _AddressBookState extends State<_AddressBook> {
  final TextEditingController _q = TextEditingController();

  @override
  void dispose() {
    _q.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final AppLocale locale = AppLocale.of(context);
    final S s = locale.s;
    final String q = _q.text.trim().toLowerCase();
    final List<UContact> shown = q.isEmpty
        ? widget.contacts
        : widget.contacts
            .where((UContact c) => c.nameFor(locale.lang).toLowerCase().contains(q) || c.fullAddress.toLowerCase().contains(q))
            .toList();
    return UExpandSection(
      title: SectionLabel(s.addressBook),
      count: widget.contacts.length,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (widget.contacts.isNotEmpty) ...[
            const SizedBox(height: 4),
            TextField(
              controller: _q,
              onChanged: (_) => setState(() {}),
              cursorColor: UPalette.mint,
              style: uiStyle(13, color: UPalette.text),
              decoration: InputDecoration(
                hintText: s.searchContacts,
                hintStyle: uiStyle(12.5, color: UPalette.text3),
                prefixIcon: const Icon(Icons.search_rounded, size: 18, color: UPalette.text3),
                suffixIcon: q.isEmpty
                    ? null
                    : IconButton(
                        icon: const Icon(Icons.close_rounded, size: 16, color: UPalette.text3),
                        onPressed: () => setState(_q.clear),
                      ),
                filled: true,
                fillColor: UPalette.fieldBg,
                isDense: true,
                contentPadding: const EdgeInsets.symmetric(vertical: 10),
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: UPalette.lineStrong)),
                enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: UPalette.lineStrong)),
                focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: UPalette.mintLine)),
              ),
            ),
            const SizedBox(height: 4),
          ],
          if (widget.contacts.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 12),
              child: Text(s.noContacts, textAlign: TextAlign.center, style: uiStyle(12, color: UPalette.text3)),
            )
          else if (shown.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 12),
              child: Text(s.noMatches, textAlign: TextAlign.center, style: uiStyle(12, color: UPalette.text3)),
            )
          else
            for (final UContact c in shown) _ContactRow(contact: c, onTap: () => widget.onContact(c)),
        ],
      ),
    );
  }
}

class _ControlRow extends StatelessWidget {
  const _ControlRow({required this.label, required this.child});

  final String label;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(child: Text(label, style: uiStyle(12.5, color: UPalette.text2), maxLines: 1, overflow: TextOverflow.ellipsis)),
        const SizedBox(width: 8),
        child,
      ],
    );
  }
}

/// Автоприём: компактный выпадающий выбор (ask / contacts / all / off).
class UAutoAcceptPicker extends StatelessWidget {
  const UAutoAcceptPicker({super.key, required this.mode, required this.onChanged});

  final String mode;
  final ValueChanged<String> onChanged;

  static const List<String> _modes = <String>['ask', 'contacts', 'all', 'off'];

  @override
  Widget build(BuildContext context) {
    final List<String> options = AppLocale.of(context).s.autoAcceptOptions;
    final int index = _modes.contains(mode) ? _modes.indexOf(mode) : 0;
    return PopupMenuButton<int>(
      tooltip: '',
      color: UPalette.surface2,
      surfaceTintColor: Colors.transparent,
      initialValue: index,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: const BorderSide(color: UPalette.lineStrong),
      ),
      onSelected: (int i) => onChanged(_modes[i]),
      itemBuilder: (BuildContext context) => <PopupMenuEntry<int>>[
        for (int i = 0; i < options.length; i++)
          PopupMenuItem<int>(value: i, height: 44, child: Text(options[i], style: uiStyle(14))),
      ],
      child: Container(
        height: 30,
        padding: const EdgeInsets.symmetric(horizontal: 10),
        decoration: BoxDecoration(
          color: UPalette.surface,
          border: Border.all(color: UPalette.lineStrong),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(options[index], style: uiStyle(12.5, weight: FontWeight.w600, color: UPalette.text2)),
            const SizedBox(width: 2),
            const Icon(Icons.keyboard_arrow_down_rounded, size: 18, color: UPalette.text3),
          ],
        ),
      ),
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
