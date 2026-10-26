"""Observed serial/server storage campaign; requires an idle isolated test profile."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time

import serial
from run_fault_network_cases import BASE, SIGNATURE, Capture, Control, healthy

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--port', default='COM13')
p.add_argument('--baseline-version', default='5.0.2')
p.add_argument('--evidence-dir', type=Path, required=True)
p.add_argument('--redact-file', type=Path, required=True)
p.add_argument('--only', nargs='+', default=[])
a = p.parse_args()
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
private = json.loads(a.redact_file.read_text())
def redact(text):
    for secret in private.values():
        if secret: text = text.replace(secret, '[REDACTED]')
    return text

run = a.evidence_dir / datetime.now(timezone.utc).strftime('run-%Y%m%dT%H%M%SZ')
run.mkdir(parents=True, exist_ok=False)
port = serial.Serial(port=None, baudrate=115200, timeout=.1)
port.dtr = port.rts = False
port.port = a.port
cap, control = Capture(port, redact), Control()
ota = 'ota ' + BASE + 'manifest.json ' + SIGNATURE
results = []

def has(lines, text): return text in '\n'.join(lines)
def wait(marker, seconds=90):
    body = cap.pump(seconds, lambda lines: bool(re.search(marker, '\n'.join(lines))))
    if not re.search(marker, '\n'.join(body)):
        raise RuntimeError('Required marker not observed: ' + marker)
    return body
def command(text, marker, seconds=5):
    cap.send(text)
    return wait(marker, seconds)
def idle():
    state, lines = cap.baseline()
    if not healthy(state, a.baseline_version):
        raise RuntimeError('Healthy idle baseline not observed: ' + json.dumps(state))
    return state
def clear(): command('clearresume', 'clearresume_result=ESP_OK')
def done(): return wait(r'phase=(?:FAILED|CANCELLED)', 100)
def seed(reset_before=False):
    clear()
    control.call({'reset': True, 'chunk_delay_ms': 2})
    name = 'lab-reset-before-checkpoint 196608' if reset_before else 'ota-reset-at 147456'
    command(name, 'next_session_only', 3)
    cap.send(ota)
    marker = re.escape('software_reset_before_checkpoint written=196608 old_durable_q=131072 nvs_commit_for_new_q=false') if reset_before else r'software_reset written=(\d+) q=131072'
    reset_lines = wait(marker, 50)
    if not reset_before:
        match = re.search(marker, '\n'.join(reset_lines))
        if not 147456 <= int(match[1]) < 196608:
            raise RuntimeError('Reset tail not within the expected checkpoint interval')
    wait(r'phase=IDLE reason=local OTA controller ready', 18)
    cap.pump(3)
    idle()
    command('clock ' + str(int(time.time())), 'CLOCK_PROVISION.*result=0')
    cap.send('lab-checkpoint-status')
    states = wait(r'lab_checkpoint key=cp1', 4)
    if not any('valid_crc_format=1 q=131072' in line for line in states):
        raise RuntimeError('Expected durable Q131072 not observed')

def execute(name, test, body):
    if a.only and name not in a.only and test not in a.only: return
    begin = len(cap.lines)
    with (run / (name + '.log')).open('w', encoding='utf-8') as log:
        cap.log = log
        before = idle()
        try:
            checks = body()
            after = idle()
            checks['same_valid_running_image'] = all(before[k] == after[k] for k in ('version','slot','boot','state'))
            checks['no_boot_selection'] = not has(cap.lines[begin:], 'BOOT_SELECTED')
            checks['no_service_mode'] = after['service_mode'] == 0
            result = 'PASS' if all(checks.values()) else 'FAIL'
            results.append({'name':name, 'test_id':test, 'result':result, 'checks':checks,
                            'before':before, 'after':after, 'log':str((run/(name+'.log')).relative_to(a.evidence_dir))})
            if result != 'PASS': raise RuntimeError('Observed checks failed: ' + name)
        finally:
            cap.log = None
            encoded = json.dumps({'results':results},indent=2)+'\n'
            (a.evidence_dir/'summary.json').write_text(encoded)
            (run/'summary.json').write_text(encoded)

def r02():
    seed(True)
    cap.send(ota)
    lines = done()
    return {'resume_from_previous_snapshot':has(lines,'offset=131072 mode=resume'),
            'native_verify_reached':has(lines,'phase=VERIFY_FILE'),
            'dummy_descriptor_rejected':has(lines,'phase=FAILED reason=ESP_ERR_INVALID_VERSION')}

def bad_range(mode):
    # Each case owns a fresh, observed committed checkpoint.
    seed()
    control.call({'reset':True,'range_mode':mode})
    cap.send(ota)
    lines=done()
    events=control.call()['history']
    sent=any(e.get('range')=='bytes=131072-' for e in events)
    if mode=='ignore':
        return {'actual_range_request':sent,'discard_200_body':has(lines,'range_ignored; discard body and restart from zero'),
                'fresh_restart':has(lines,'offset=0 mode=fresh'),'never_append_200_to_prefix':not has(lines,'mode=resume'),
                'dummy_descriptor_rejected':has(lines,'phase=FAILED reason=ESP_ERR_INVALID_VERSION')}
    header_gate = has(lines,'status=416 error=ESP_ERR_INVALID_RESPONSE retryable=0') if mode=='416' else has(lines,'stream_header_reject')
    return {'actual_range_request':sent,'bad_header_rejected':header_gate,
            'rejected_before_writer':not has(lines,'writer_started'),
            'contract_failure':has(lines,'phase=FAILED reason=ESP_ERR_INVALID_RESPONSE')}

def r06():
    seed()
    control.call({'reset':True,'image_mode':'tamper_tail'})
    cap.send(ota)
    lines=done()
    return {'resume_same_identity':has(lines,'offset=131072 mode=resume'),
            'native_validation_passed':has(lines,'phase=VERIFY_FILE'),
            'full_signed_file_digest_rejected':has(lines,'phase=FAILED reason=ESP_ERR_INVALID_CRC')}

def r05():
    clear()
    command('lab-seed-stale-running','stale_checkpoint_target_running.*result=ESP_OK')
    control.call({'reset':True,'chunk_delay_ms':20})
    cap.send(ota)
    lines=wait('writer_started',50)
    cap.send('cancel'); lines += done()
    return {'stale_rejected_before_erase':has(lines,'checkpoint_rejected target_is_running=true before_erase=true'),
            'fresh_inactive_writer':has(lines,'offset=0 mode=fresh'),
            'cancelled_cleanly':has(lines,'phase=CANCELLED') and has(lines,'writer_abort=1 http_closed=true result=ESP_OK')}

def r07():
    seed()
    command('lab-corrupt-checkpoints','records_changed=2 result=ESP_OK')
    command('lab-corrupt-checkpoints','records_changed=2 result=ESP_OK')
    cap.send('lab-checkpoint-status'); states=wait('lab_checkpoint key=cp1')
    control.call({'reset':True,'chunk_delay_ms':20})
    cap.send(ota); lines=wait('writer_started',50)
    cap.send('cancel'); lines+=done()
    return {'both_snapshots_invalid':len([x for x in states if 'valid_crc_format=0' in x])==2,
            'no_guessed_resume_offset':has(lines,'offset=0 mode=fresh') and not has(lines,'mode=resume'),
            'clean_cancel':has(lines,'writer_abort=1 http_closed=true result=ESP_OK')}

def r08():
    clear(); control.call({'reset':True,'chunk_delay_ms':30})
    cap.send(ota); lines=wait('writer_started',50)
    cap.send(ota); lines+=wait('one worker already owns updater',4)
    cap.send('clock ' + str(int(time.time()))); lines+=wait('CLOCK_REJECT',4)
    lines+=wait('checkpoint_committed q=65536',10)
    cap.send('cancel'); lines+=done()
    cap.send('lab-checkpoint-status'); states=wait('lab_checkpoint key=cp1')
    return {'single_writer':sum('writer_started' in x for x in lines)==1,
            'duplicate_rejected':has(lines,'one worker already owns updater'),
            'clock_cannot_change_during_update':has(lines,'CLOCK_REJECT'),
            'writer_and_http_cleaned':has(lines,'writer_abort=1 http_closed=true result=ESP_OK'),
            'cancelled':has(lines,'phase=CANCELLED'),
            'checkpoints_removed':len([x for x in states if 'found=0' in x])==2}

try:
    port.open()
    execute('R02-before-checkpoint-commit','R02',r02)
    for mode in ['416','wrong_start','wrong_total','wrong_end','ignore']:
        execute('N08-range-'+mode,'N08',lambda mode=mode:bad_range(mode))
    execute('R06-same-url-changed-tail','R06',r06)
    execute('R05-stale-running-target','R05',r05)
    execute('R07-two-corrupt-snapshots','R07',r07)
    execute('R08-duplicate-cancel','R08',r08)
finally:
    if port.is_open:
        cap.send('cancel'); cap.pump(.5)
        port.close()
    control.call({'reset':True})
print(json.dumps({'results':[(x['name'],x['result']) for x in results]}))
