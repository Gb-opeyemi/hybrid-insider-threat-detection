import gzip
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.wazuh_session_detection import (
    COMBINED_COLUMN, assert_dev_parity, detect_wazuh_sessions,
)


def test_original_rule_behaviour(tmp_path):
    start = pd.Timestamp('2026-11-01T12:00:00Z')
    rows, cutoffs, sessions, archive = [], [], [], []
    counter = 0

    def create_session(sid, offset, cutoff):
        sessions.append({'SessionID':sid, 'Partition':'validation'})
        cutoffs.append({'SessionID':sid,'PredictionCutoffUTC':(start+pd.Timedelta(minutes=offset,seconds=cutoff)).isoformat()})

    def add_event(sid, offset, seconds, event_id, *, user, severity='AUDIT_SUCCESS',
                  path=None, access='', provider='Security', image='', command=''):
        nonlocal counter
        counter += 1
        when = start + pd.Timedelta(minutes=offset,seconds=seconds)
        row = dict(SessionID=sid, EventID=event_id, SeverityValue=severity,
                   ResolvedUsername=user, TargetUsername=user,
                   AvailableTimeUTC=(when+pd.Timedelta(milliseconds=50)).isoformat(),
                   EventTimeUTC=when.isoformat(),
                   Computer='LAB-SERVER.example.invalid', EventChannel='Security',
                   EventRecordID=counter, ObjectName=path, AccessMask=access,
                   Provider=provider, Image=image, CommandLine=command)
        rows.append(row)
        return row

    create_session('M01',0,40)
    for t in (1,2,3):add_event('M01',0,t,5145,user='john.student',severity='AUDIT_FAILURE')

    create_session('M02',10,40)
    for t in (1,2,3):
        r=add_event('M02',10,t,4625,user='alice.student',severity='AUDIT_FAILURE')
        archive.append({'data':{'win':{'system':{'eventID':'4625','computer':r['Computer'],
                'channel':r['EventChannel'],'eventRecordID':str(r['EventRecordID'])},
                'eventdata':{'subStatus':'0xc000006a'}}}})

    create_session('M03',20,45)
    for i in range(31):
        add_event('M03',20,i+1,4663,user='reader.example',
                  path=f'C:\\UniversityData\\Research\\f{i}.txt')

    create_session('M04',30,25)
    for i in range(5):
        add_event('M04',30,i+1,4663,user='deleter.example',
                  path=f'C:\\UniversityData\\Research\\del{i}.txt',access='0x10000')

    create_session('M05',40,5)
    add_event('M05',40,2,1,user='ethan.researcher',provider='Microsoft-Windows-Sysmon',
              image=r'C:\Windows\System32\OpenSSH\sftp.exe',
              command='sftp m05receiver@198.51.100.20')

    create_session('benign',50,40)
    add_event('benign',50,1,5145,user='john.student')

    archive_root = tmp_path/'archive'
    archive_root.mkdir()
    with gzip.open(archive_root/'ossec-archive-test.json.gz','wt') as h:
        for r in archive:h.write(json.dumps(r)+'\n')

    result = detect_wazuh_sessions(pd.DataFrame(sessions),pd.DataFrame(rows),
        pd.DataFrame(cutoffs),archive_root=archive_root)
    result = result.set_index('SessionID')
    for sid, rule in [('M01','M01_Detected'),('M02','M02_Detected'),
                      ('M03','M03_Detected'),('M04','M04_Detected'),('M05','M05_Detected_0s')]:
        assert result.loc[sid, rule] == 1, (sid,rule)
        assert result.loc[sid,COMBINED_COLUMN] == 1
    assert result.loc['benign',COMBINED_COLUMN] == 0
    assert result.loc['M05','M05_Detected_3s'] == 0  # 2.05s+3 > cutoff 5s
    assert result.loc['M05','M05_Detected_5s'] == 0
    assert result.loc['M05','M05_Detected_10s'] == 0

    assert_dev_parity(result.reset_index(),result.reset_index())
    changed = result.reset_index().copy()
    changed.loc[0, 'M01_Detected'] = 1 - changed.loc[0, 'M01_Detected']
    try:
        assert_dev_parity(result.reset_index(),changed)
    except AssertionError:
        pass
    else:
        raise AssertionError('Changed historical output was not caught')

if __name__ == '__main__':
    import tempfile
    with tempfile.TemporaryDirectory() as tempdir:
        test_original_rule_behaviour(Path(tempdir))
    print('Synthetic M01-M05 tests passed')
