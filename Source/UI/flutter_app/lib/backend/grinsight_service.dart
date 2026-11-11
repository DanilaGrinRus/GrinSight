// ignore_for_file: use_null_aware_elements

// GrinSight: Dart client of grinsight-service (the Rust wallet core).
//
// The app starts the service process, reads its port and session token from
// stdout, and calls JSON-RPC 2.0 on http://127.0.0.1:<port>/rpc. Keys never
// leave the service: the phrase is sent once (create / restore) and kept
// encrypted in the service's vault; every later call needs only the password
// at unlock. Closing the service's stdin (app exit) stops it.
//
// Amounts are nanogrin (int; 1 GRIN = 1e9). Long calls (open, send,
// payInvoice, finalize, broadcast, confirm) return a job id; use waitJob()
// to follow progress.
//
// Copy this file into the Flutter app (e.g. lib/backend/) and replace
// DemoWalletCore with calls to GrinSightService. See README_RU.md.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

class GrinSightError implements Exception {
  GrinSightError(this.message);
  final String message;
  @override
  String toString() => message;
}

/// Job state from the service: running | done | failed | cancelled.
class JobState {
  JobState(this.json);
  final Map<String, dynamic> json;
  String get id => json['id'] as String;
  String get state => json['state'] as String;
  String get phase => (json['phase'] ?? '') as String;
  List<String> get lines => List<String>.from((json['lines'] ?? <dynamic>[]) as List<dynamic>);
  dynamic get result => json['result'];
  String get error => (json['error'] ?? '') as String;
  bool get running => state == 'running';
}

class GrinSightService {
  GrinSightService._(this._process, this.port, this._token);

  final Process _process;
  final int port;
  final String _token;
  final HttpClient _http = HttpClient()..idleTimeout = const Duration(seconds: 5);
  int _id = 0;

  /// Starts `grinsight-service serve`. [exePath]: the service next to the core
  /// binaries (reverse-wtema-header-sync, unity-tor) and `checkpoints\`.
  static Future<GrinSightService> start({required String exePath, String? dataDir}) async {
    final List<String> args = <String>['serve', if (dataDir != null) ...<String>['--data-dir', dataDir]];
    final Process p = await Process.start(exePath, args, runInShell: false);
    final Completer<GrinSightService> ready = Completer<GrinSightService>();
    int? port;
    String? token;
    p.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((String l) {
      if (l.startsWith('GRINSIGHT_SERVICE_PORT=')) port = int.tryParse(l.substring(23));
      if (l.startsWith('GRINSIGHT_SERVICE_TOKEN=')) token = l.substring(24);
      if (port != null && token != null && !ready.isCompleted) ready.complete(GrinSightService._(p, port!, token!));
    });
    p.stderr.drain<void>();
    unawaited(p.exitCode.then((int c) {
      if (!ready.isCompleted) ready.completeError(GrinSightError('grinsight-service exited ($c) before it was ready'));
    }));
    return ready.future.timeout(const Duration(seconds: 20));
  }

  /// One JSON-RPC call; errors of the service become [GrinSightError].
  Future<dynamic> call(String method, [Map<String, dynamic> params = const <String, dynamic>{}]) async {
    final HttpClientRequest rq = await _http.post('127.0.0.1', port, '/rpc');
    rq.headers.set(HttpHeaders.authorizationHeader, 'Bearer $_token');
    rq.headers.contentType = ContentType.json;
    final List<int> payload = utf8.encode(jsonEncode(<String, dynamic>{'jsonrpc': '2.0', 'id': ++_id, 'method': method, 'params': params}));
    rq.contentLength = payload.length;
    rq.add(payload);
    final HttpClientResponse rs = await rq.close();
    final String body = await rs.transform(utf8.decoder).join();
    if (rs.statusCode != 200) throw GrinSightError('service HTTP ${rs.statusCode}: $body');
    final Map<String, dynamic> v = jsonDecode(body) as Map<String, dynamic>;
    if (v['error'] != null) throw GrinSightError((v['error'] as Map<String, dynamic>)['message'] as String);
    return v['result'];
  }

  Future<Map<String, dynamic>> _map(String m, [Map<String, dynamic> p = const <String, dynamic>{}]) async =>
      (await call(m, p)) as Map<String, dynamic>;

  Future<String> _job(String m, [Map<String, dynamic> p = const <String, dynamic>{}]) async =>
      (await _map(m, p))['job'] as String;

  /// Polls a job until it ends; [onProgress] gets every state while running.
  Future<dynamic> waitJob(String id, {void Function(JobState)? onProgress, Duration every = const Duration(milliseconds: 700)}) async {
    while (true) {
      final JobState s = JobState(await _map('job.status', <String, dynamic>{'id': id}));
      if (onProgress != null) onProgress(s);
      if (!s.running) {
        if (s.state == 'done') return s.result;
        throw GrinSightError(s.error.isEmpty ? s.state : s.error);
      }
      await Future<void>.delayed(every);
    }
  }

  Future<void> cancelJob(String id) => call('job.cancel', <String, dynamic>{'id': id});

  // ---- profiles and keys --------------------------------------------------

  Future<Map<String, dynamic>> info() => _map('service.info');
  Future<String> newPhrase() async => (await _map('wallet.new_phrase'))['phrase'] as String;
  Future<void> checkPhrase(String phrase) => call('wallet.check_phrase', <String, dynamic>{'phrase': phrase});

  /// New wallet from a phrase made by [newPhrase] in this service run.
  Future<Map<String, dynamic>> create({required String name, required String network, required String phrase, required String password}) =>
      _map('wallet.create', <String, dynamic>{'name': name, 'network': network, 'phrase': phrase, 'password': password});

  /// Existing phrase: the first open scans the chain for its coins.
  Future<Map<String, dynamic>> restore({required String name, required String network, required String phrase, required String password}) =>
      _map('wallet.restore', <String, dynamic>{'name': name, 'network': network, 'phrase': phrase, 'password': password});

  Future<Map<String, dynamic>> unlock({required String name, required String network, required String password}) =>
      _map('wallet.unlock', <String, dynamic>{'name': name, 'network': network, 'password': password});

  Future<void> lock() => call('wallet.lock');

  // ---- state ----------------------------------------------------------------

  /// Balance (available / reserved / incoming / immature, nanogrin), proof of
  /// the last open (height, freshness now, can_spend), address, Tor.
  Future<Map<String, dynamic>> status() => _map('wallet.status');
  Future<String> address() async => (await _map('wallet.address'))['address'] as String;
  Future<Map<String, dynamic>> payments() => _map('wallet.payments');
  Future<String> slatepack(String txId) async => (await _map('wallet.slatepack', <String, dynamic>{'tx_id': txId}))['slatepack'] as String;
  Future<Map<String, dynamic>> settings() => _map('wallet.settings');
  Future<Map<String, dynamic>> setSettings({bool? autoBroadcast, List<String>? extraPeers, String? checkpointSource, bool? checkpointOfferSeen}) => _map('wallet.set_settings', <String, dynamic>{
        if (autoBroadcast != null) 'auto_broadcast': autoBroadcast,
        if (extraPeers != null) 'extra_peers': extraPeers,
        if (checkpointSource != null) 'checkpoint_source': checkpointSource,
        if (checkpointOfferSeen != null) 'checkpoint_offer_seen': checkpointOfferSeen,
      });

  /// Source (release|own), shipped/own heights+hashes, match of own with supply.
  Future<Map<String, dynamic>> checkpointInfo() => _map('wallet.checkpoint_info');

  /// Builds an own checkpoint from genesis (resumable job; cancel = pause).
  Future<String> ownCheckpoint() => _job('wallet.own_checkpoint');

  // ---- jobs: return the job id (waitJob) ----------------------------------

  /// Verified headers + proven balance (first time: install, long).
  Future<String> open() => _job('wallet.open');

  /// Pay [to] (grin1.../tgrin1...): result {tx_id, slatepack (S1), fee}.
  Future<String> send({required String to, required int amount}) => _job('wallet.send', <String, dynamic>{'to': to, 'amount': amount});

  /// Their answer (S2 to our send, I2 to our invoice): sign; broadcast if
  /// [broadcast] (default: the auto_broadcast setting).
  Future<String> finalize({required String txId, required String answer, bool? broadcast}) =>
      _job('wallet.finalize', <String, dynamic>{'tx_id': txId, 'answer': answer, if (broadcast != null) 'broadcast': broadcast});

  Future<String> broadcast(String txId) => _job('wallet.broadcast', <String, dynamic>{'tx_id': txId});

  /// Kernel in a block of the verified chain: {state: in_block|confirmed|reorged|not_in_block, height, depth}.
  Future<String> confirm(String txId) => _job('wallet.confirm', <String, dynamic>{'tx_id': txId});

  /// Pay an invoice (text, or a file from the Tor inbox): result {tx_id, answer (I2)}.
  Future<String> payInvoice({String? slatepack, String? inboxFile}) => _job('wallet.pay_invoice', <String, dynamic>{
        if (slatepack != null) 'slatepack': slatepack,
        if (inboxFile != null) 'inbox_file': inboxFile,
      });

  // ---- offline -------------------------------------------------------------

  /// Their S1 -> our answer S2: {tx_id, answer, amount, from, sender_verified}.
  Future<Map<String, dynamic>> receive(String slatepack) => _map('wallet.receive', <String, dynamic>{'slatepack': slatepack});

  /// Ask for [amount]: {tx_id, slatepack (I1)}.
  Future<Map<String, dynamic>> invoice({required int amount, String? payer}) =>
      _map('wallet.invoice', <String, dynamic>{'amount': amount, if (payer != null) 'payer': payer});

  /// Give up a payment that never completed (its coins can be spent again).
  Future<void> release(String txId, {bool force = false}) => call('wallet.release', <String, dynamic>{'tx_id': txId, 'force': force});

  // ---- Tor and contacts -----------------------------------------------------

  Future<void> torStart({String? relay}) => call('tor.start', <String, dynamic>{if (relay != null) 'relay': relay});
  Future<void> torStop() => call('tor.stop');
  Future<Map<String, dynamic>> torStatus() => _map('tor.status');
  Future<void> torDeliver(String txId, {String? messenger, bool messengerOnly = false}) =>
      call('tor.deliver', <String, dynamic>{'tx_id': txId, if (messenger != null) 'messenger': messenger, 'messenger_only': messengerOnly});
  Future<Map<String, dynamic>> contacts() => _map('contacts.list');
  Future<Map<String, dynamic>> addContact({required String id, String? name, String? messenger, bool auto = true}) =>
      _map('contacts.add', <String, dynamic>{'id': id, if (name != null) 'name': name, if (messenger != null) 'messenger': messenger, 'auto': auto});
  Future<Map<String, dynamic>> removeContact(String id) => _map('contacts.remove', <String, dynamic>{'id': id});
  Future<Map<String, dynamic>> autoAccept(String mode) => _map('contacts.auto_accept', <String, dynamic>{'mode': mode});

  /// Stops the service (also happens when the app exits).
  Future<void> stop() async {
    try {
      await call('service.shutdown');
    } catch (_) {}
    await _process.stdin.close();
    _http.close(force: true);
  }
}

/// "1.5" -> 1500000000 (no floating point).
int grinToNano(String grin) {
  final String t = grin.trim().replaceAll(',', '.');
  final RegExp ok = RegExp(r'^\d+(\.\d{1,9})?$');
  if (!ok.hasMatch(t)) throw GrinSightError('amount: up to 9 decimals, e.g. 1.5');
  final List<String> p = t.split('.');
  final String frac = (p.length > 1 ? p[1] : '').padRight(9, '0');
  return int.parse(p[0]) * 1000000000 + int.parse(frac);
}

/// 1500000000 -> "1.5" (trailing zeros removed, at least one decimal shown).
String nanoToGrin(int nano) {
  final String whole = (nano ~/ 1000000000).toString();
  String frac = (nano % 1000000000).toString().padLeft(9, '0').replaceFirst(RegExp(r'0+$'), '');
  if (frac.isEmpty) frac = '0';
  return '$whole.$frac';
}
