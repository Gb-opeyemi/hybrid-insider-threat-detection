"""New local job store. Never opens or migrates the operational RF database."""
import json
import sqlite3
from uuid import uuid4
from .model_selection import validate_model
from scripts.integration.receive_ml_prediction import canonical
import hashlib
from datetime import datetime, timezone


class Job:
    def __init__(self, folder):
        self.folder = folder
        self.db = sqlite3.connect(folder / 'execution.sqlite3')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')

    @classmethod
    def create(cls, folder, selection, record):
        folder.mkdir(parents=True, exist_ok=False, mode=0o700)
        job = cls(folder)
        job.db.execute('CREATE TABLE execution(id TEXT PRIMARY KEY, selected_model TEXT, record TEXT, digest TEXT, state TEXT)')
        record = {**record, 'job_id': str(uuid4()), 'selected_model': validate_model(selection.model),
                  'selection_source': selection.source, 'created_at_utc': datetime.now(timezone.utc).isoformat()}
        digest = hashlib.sha256(canonical(record).encode()).hexdigest()
        with job.db:
            job.db.execute('INSERT INTO execution VALUES(?,?,?,?,?)',
                (record['job_id'], selection.model, canonical(record), digest, canonical({'status': 'created'})))
        return job

    def read(self):
        rows = self.db.execute('SELECT * FROM execution').fetchall()
        if len(rows) != 1: raise ValueError('Exactly one pinned local execution required')
        row = rows[0]; record = json.loads(row['record'])
        if (hashlib.sha256(canonical(record).encode()).hexdigest() != row['digest']
                or record['selected_model'] != row['selected_model'] or record['job_id'] != row['id']):
            raise ValueError('Pinned job model/identity changed')
        validate_model(record['selected_model'])
        return record, json.loads(row['state'])

    def update(self, **values):
        record, state = self.read(); state.update(values)
        state['updated_at_utc'] = datetime.now(timezone.utc).isoformat()
        with self.db: self.db.execute('UPDATE execution SET state=? WHERE id=?', (canonical(state), record['job_id']))

    def close(self): self.db.close()
