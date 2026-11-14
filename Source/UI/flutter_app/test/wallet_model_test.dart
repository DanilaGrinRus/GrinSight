import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/wallet_model.dart';

void main() {
  test('shortGrin truncates, never rounds up', () {
    expect(shortGrin(999000000), '0.99');
    expect(shortGrin(999999999), '0.99');
    expect(shortGrin(1394710999000), '1394.71');
    expect(shortGrin(11000000000), '11.00');
  });

  test('service stages map to TxStage without falling back to broadcast', () {
    expect(txStageFromService('building'), TxStage.waitingAnswer);
    expect(txStageFromService('waiting_answer'), TxStage.waitingAnswer);
    expect(txStageFromService('waiting_sender'), TxStage.waitingAnswer);
    expect(txStageFromService('finalized'), TxStage.finalized);
    expect(txStageFromService('broadcast'), TxStage.broadcast);
    expect(txStageFromService('in_block'), TxStage.inBlock);
    expect(txStageFromService('confirmed'), TxStage.confirmed);
    expect(txStageFromService('reorged'), TxStage.reorged);
    expect(txStageFromService('cancelled'), TxStage.cancelled);
    expect(txStageFromService('unknown_future_stage'), TxStage.waitingAnswer);
  });

  test('tip age is human readable', () {
    final S s = S('ru');
    expect(s.formatAge(45), '45 с');
    expect(s.formatAge(2693), '45 мин');
    expect(s.formatAge(3900), '1 ч 5 мин');
    expect(s.formatAge(90000), '1 д 1 ч');
  });
}
